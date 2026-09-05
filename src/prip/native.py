#  Copyright 2026 Hoo-dles
#  https://github.com/hoo-dles/prip

import re
import struct
import zipfile
from pathlib import Path
from typing import cast

import lief

from .models import LibraryFridaInfo, TextSectionInfo

_PAIRIP_SO = "libpairipcore.so"


def _unzip(file: Path):
    with zipfile.ZipFile(file, "r") as zip:
        path = file.parent / file.stem
        zip.extractall(path)
        return path


def _is_valid_lib_path(file: Path):
    return file.is_file and file.suffix == ".so" and file.name != _PAIRIP_SO


def _get_encrypted(elf: lief.ELF.Binary):
    text_section = elf.get_section(".text")
    if not text_section:
        raise RuntimeError("Missing .text section")

    dump_len = min(text_section.size, 51120)
    encrypted = bytes(text_section.content[:dump_len])
    return TextSectionInfo(
        v_addr=text_section.virtual_address, size=dump_len
    ), encrypted


def _missing_got_addrs(elf: lief.ELF.Binary):
    got_section = elf.get_section(".got.plt") or elf.get_section(".got")
    plt_section = elf.get_section(".plt")
    if not got_section or not plt_section:
        raise RuntimeError("Missing .got or .plt section")

    got_start = got_section.virtual_address
    got_bytes = bytes(got_section.content)

    # GOT slot index -> virtual address
    got_slots: dict[int, int] = {}
    ptr_size = 8
    unpack_fmt = "<Q"

    # scan GOT
    for cursor in range(0, len(got_bytes), ptr_size):
        i = int(cursor / ptr_size)
        chunk = got_bytes[cursor : cursor + ptr_size]
        if len(chunk) < ptr_size:
            break

        slot_vaddr = got_start + cursor
        val_at_rest: int = struct.unpack(unpack_fmt, chunk)[0]

        # late-initialized GOT values have placeholders pointing at .plt start
        if val_at_rest == plt_section.virtual_address:
            got_slots[i] = slot_vaddr

    # exclude GOT entries that have a corresponding relocation
    known_reloc_addrs = {r.address for r in list(elf.pltgot_relocations)}
    return [va for va in got_slots.values() if va not in known_reloc_addrs]


def analyze_natives(arm_apk: Path):
    unzip_path = _unzip(arm_apk)
    libs_path = unzip_path / "lib" / "arm64-v8a"

    frida_infos: dict[str, LibraryFridaInfo] = {}
    encrypts: dict[str, bytes] = {}
    for lib in libs_path.iterdir():
        if not _is_valid_lib_path(lib):
            continue

        elf = cast(lief.ELF.Binary, lief.parse(lib))
        if _PAIRIP_SO not in elf.libraries:
            continue

        try:
            text_info, encrypted = _get_encrypted(elf)
            got_addrs = _missing_got_addrs(elf)
        except RuntimeError as e:
            e.add_note(f"Library: {lib.name}")
            raise

        frida_infos[lib.name] = LibraryFridaInfo(
            text_info=text_info, got_vaddrs=got_addrs
        )
        encrypts[lib.name] = encrypted

    return frida_infos, encrypts


def keystream(enc: bytes, dec: bytes):
    """Calcuate XOR cipher. Returns empty `bytes` object if equal."""
    return bytes([e ^ d for e, d in zip(enc, dec)]) if enc != dec else b""


def _find_func_symbol(elf: lief.ELF.Binary, offset: int):
    for sym in elf.symbols:
        if sym.type == lief.ELF.Symbol.TYPE.FUNC and sym.value == offset:
            return sym.name
    return None


def find_symbols(lib: Path, offsets: list[int]):
    elf = cast(lief.ELF.Binary, lief.parse(lib))

    symbols: dict[int, str] = {}
    for offset in offsets:
        symbol = _find_func_symbol(elf, offset)
        if not symbol or not isinstance(symbol, str):
            raise RuntimeError(f"Could not find symbol ({lib.name}+{hex(offset)})")
        symbols[offset] = symbol
    return symbols


_PREFIX_REGEX = r"^(portable_simd_|__kernel_|__libc_|__)"
_ARCH_REGEX = r"_(aarch64|arm|neon|mte|v8|sve2?|pac|opt|shared|static).*$"


def clean_symbol_name(symbol: str):
    res = symbol
    for pattern in [_PREFIX_REGEX, _ARCH_REGEX]:
        res = re.sub(pattern, "", res)
    return res

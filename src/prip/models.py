from dataclasses import dataclass, field

# --- Java Reflection ---


@dataclass
class Field:
    name: str
    value: str | None = None


@dataclass
class JavaReflection:
    methods: dict[str, list[Field]] = field(default_factory=dict)
    strings: dict[str, list[Field]] = field(default_factory=dict)


# --- Native Libraries ---


@dataclass
class TextSectionInfo:
    v_addr: int
    size: int


@dataclass
class LibraryFridaInfo:
    text_info: TextSectionInfo
    got_vaddrs: list[int]


@dataclass
class Relocation:
    address: int
    symbol: str


@dataclass
class LibraryFridaResult:
    decrypted: bytes
    relocations: list[Relocation]


@dataclass
class LibraryData:
    keystream: str
    relocations: list[Relocation]


# --- Results ---


@dataclass
class ExportResults:
    java: JavaReflection
    libs: dict[str, LibraryData]

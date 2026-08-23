import subprocess
from pathlib import Path
from time import sleep

import frida

from .adb import adb_shell, get_pid
from .models import JavaReflection, LibraryFridaInfo, LibraryFridaResult

SCRIPT_PATH = Path(__file__).resolve().parents[2] / "js/build/frida.compiled.js"


def start_frida_server():
    try:
        adb_shell("su -c '/data/local/tmp/frida-server' > /dev/null 2>&1 &")
        # wait some time for frida-server to start
        sleep(0.5)
        return get_pid("frida-server")
    except subprocess.CalledProcessError:
        return None


def attach_and_run_script(
    pid: int, java: JavaReflection, native: dict[str, LibraryFridaInfo]
):
    device = frida.get_usb_device(timeout=5)

    session = device.attach(pid)

    compiled_js = Path(SCRIPT_PATH).read_text(encoding="utf-8")
    script = session.create_script(compiled_js)
    script.load()

    reflection_results: dict = script.exports.extract_java(java.model_dump())
    native_results: dict = script.exports.extract_native(
        {lib: info.model_dump() for lib, info in native.items()}
    )

    session.detach()

    deserialized_native: dict[str, LibraryFridaResult] = {
        lib: LibraryFridaResult(**lib_result)
        for lib, lib_result in native_results.items()
    }
    return JavaReflection(**reflection_results), deserialized_native

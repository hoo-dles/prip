import json
import subprocess
from pathlib import Path
from time import sleep

import frida

from .adb import adb_shell, get_pid
from .data import Reflected

SCRIPT_PATH = Path(__file__).resolve().parents[2] / "js/build/frida.compiled.js"


def start_frida_server():
    try:
        adb_shell("su -c '/data/local/tmp/frida-server' > /dev/null 2>&1 &")
        # wait some time for frida-server to start
        sleep(0.5)
        return get_pid("frida-server")
    except subprocess.CalledProcessError:
        return None


def attach_and_run_script(pid: int, data: Reflected):
    device = frida.get_usb_device(timeout=5)

    session = device.attach(pid)

    compiled_js = Path(SCRIPT_PATH).read_text(encoding="utf-8", newline="")
    script = session.create_script(compiled_js)
    script.load()
    results: dict = script.exports.extract_values(data.serialize())

    session.detach()

    return Reflected(**results)

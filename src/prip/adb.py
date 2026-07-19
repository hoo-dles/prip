import subprocess
from pathlib import Path


def adb_shell(command: str):
    result = subprocess.run(
        f'adb shell "{command}"',
        shell=True,
        check=True,
        text=True,
        capture_output=True,
    )
    return result.stdout.strip()


def launch_app(package: str):
    adb_shell(f"monkey -p {package} 1")
    return get_pid(package)


def force_stop(package: str):
    adb_shell(f"am force-stop {package}")


def get_pid(package: str):
    return int(adb_shell(f"pidof {package}"))


def try_get_pid(package: str):
    try:
        return get_pid(package)
    except subprocess.CalledProcessError:
        return None


def get_package_version(package: str):
    res = adb_shell(f"dumpsys package {package} | grep versionName")
    return res.strip().removeprefix("versionName=")


def _get_base_apk_path(package: str):
    res = adb_shell(f"pm path {package} | grep base\\.apk")
    return res.removeprefix("package:")


def pull_base_apk(package: str, output: Path):
    path = _get_base_apk_path(package)
    subprocess.run(
        f'adb pull "{path}" "{output}"',
        shell=True,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

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


def force_stop(process: str):
    adb_shell(f"am force-stop {process}")


def get_pid(process: str):
    return int(adb_shell(f"pgrep -f -n {process}"))


def try_get_pid(process: str):
    try:
        return get_pid(process)
    except subprocess.CalledProcessError:
        return None


def get_package_version(package: str):
    res = adb_shell(f"dumpsys package {package} | grep versionName")
    return res.strip().removeprefix("versionName=")


def _get_apk_paths(package: str):
    def get_path(split: str):
        return adb_shell(f"pm path {package} | grep {split}\\.apk").removeprefix(
            "package:"
        )

    return get_path("base"), get_path("arm64_v8a")


def pull_apks(package: str, output: Path):
    def pull(path: str):
        apk_name = Path(path).name
        output_apk = output / apk_name
        subprocess.run(
            f'adb pull "{path}" "{output_apk}"',
            shell=True,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return output_apk

    base, arm = _get_apk_paths(package)
    out_base = pull(base)
    arm_base = pull(arm)
    return out_base, arm_base

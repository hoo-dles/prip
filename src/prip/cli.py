import argparse
import json
import os
import sys
import tempfile
from pathlib import Path
from time import sleep

from loguru import logger
from rich.console import Console

from .adb import force_stop, get_package_version, launch_app, pull_base_apk, try_get_pid
from .dex import find_reflected, parse_dex
from .frida import attach_and_run_script, start_frida_server


def main():
    # suppress noisy output from androguard
    logger.remove()
    logger.add(sys.stderr, level="WARNING")

    console = Console()
    console._log_render.omit_repeated_times = False

    ap = argparse.ArgumentParser(
        prog="prip",
        description="pRIP - Automatic extraction of pairipcore virtualized strings and methods.",
    )
    ap.add_argument(
        "target",
        help="package name of target app (com.my.example)",
    )
    ap.add_argument(
        "-o",
        "--out",
        dest="output",
        help="path to JSON for extracted reflection values",
    )
    ap.add_argument(
        "-w",
        "--wait",
        help="seconds to wait for app initialization (default: 3)",
        type=int,
        default=3,
    )

    args = ap.parse_args()
    console.log("Starting")

    with console.status("[yellow]Pulling base APK from device...") as status:
        temp_apk_path = None

        try:
            # find base apk location on device and pull
            version = get_package_version(args.target)
            temp_apk_path = Path(tempfile.gettempdir()) / f"{args.target}_{version}.apk"
            pull_base_apk(args.target, temp_apk_path)
            status.console.log(f"Pulled base APK: [green bold]{temp_apk_path}")

            # load DEX from apk
            status.update("[yellow]Parsing DEX...")
            dex_objects = parse_dex(temp_apk_path)
            status.console.log(
                f"Loaded [bold green]{len(dex_objects)}[/bold green] DEX files"
            )

            # search for classes/fields that need reflection
            status.update("[yellow]Searching for classes...")
            reflected = find_reflected(dex_objects)
            status.console.log(
                f"Found [bold green]{len(reflected.methods)} Method[/bold green] classes and [bold green]{len(reflected.strings)} String[/bold green] classes"
            )

            # start frida-server
            status.update("[yellow]Starting frida-server...")
            frida_pid = try_get_pid("frida-server")
            if frida_pid:
                status.console.log(
                    f"Frida-server already running [bold green](pid={frida_pid})"
                )
            else:
                frida_pid = start_frida_server()
                status.console.log(
                    f"Frida-server started [bold green](pid={frida_pid})"
                )

            # launch app and wait for load
            app_pid = launch_app(args.target)
            status.console.log(
                f"Launched app [green bold]({args.target}, pid={app_pid})"
            )
            status.update(f"[yellow]Waiting {args.wait}s for app initialization...")
            sleep(args.wait)

            # attach frida script
            status.update("[yellow]Attaching to process and running Frida script...")
            results = attach_and_run_script(app_pid, reflected)
            force_stop(args.target)
            status.console.log("Captured reflected values and stopped app")

            # write results to ouput JSON
            status.update("[yellow]Writing JSON...")
            output = Path(args.output or f"output/{args.target}_{version}.json")
            output.parent.mkdir(parents=True, exist_ok=True)
            with open(output, "w", encoding="utf-8") as file:
                file.write(json.dumps(results.serialize(), indent=2))
            status.console.log(f"Saved JSON output: [bold green]{output}")

        finally:
            status.update("[yellow]Cleaning up...")
            if temp_apk_path and os.path.exists(temp_apk_path):
                os.remove(temp_apk_path)

    console.print("[bold yellow]Finished!")


if __name__ == "__main__":
    main()

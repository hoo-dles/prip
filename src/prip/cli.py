import argparse
import base64
import os
import shutil
import sys
import tempfile
from pathlib import Path
from time import sleep

from loguru import logger
from pydantic import TypeAdapter
from rich.console import Console

from .adb import force_stop, get_package_version, launch_app, pull_apks, try_get_pid
from .dex import find_reflected, parse_dex
from .frida import attach_and_run_script, start_frida_server
from .models import LibraryData
from .native import analyze_natives, keystream


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
    ap.add_argument(
        "--no-clean",
        dest="clean",
        help="skip cleaning up temp directory with pulled APKs",
        action="store_false",
    )

    args = ap.parse_args()
    console.log("Starting")

    with console.status("[yellow]Pulling APK splits from device...") as status:
        temp_path = None

        try:
            # find base apk location on device and pull
            version = get_package_version(args.target)
            temp_path = Path(tempfile.gettempdir()) / f"{args.target}_{version}"
            temp_path.mkdir(parents=True, exist_ok=True)
            base_apk_path, arm_apk_path = pull_apks(args.target, temp_path)
            status.console.log(
                f"Pulled base and arm64_v8a APKs to [green bold]{temp_path}"
            )

            # load DEX from apk
            status.update("[yellow]Parsing DEX...")
            dex_objects = parse_dex(base_apk_path)
            status.console.log(
                f"Loaded [bold green]{len(dex_objects)}[/bold green] DEX files"
            )

            # search for classes/fields that need reflection
            status.update("[yellow]Searching for classes...")
            reflection_to_hydrate = find_reflected(dex_objects)
            status.console.log(
                f"Found [bold green]{len(reflection_to_hydrate.methods)} Method[/bold green] classes and [bold green]{len(reflection_to_hydrate.strings)} String[/bold green] classes"
            )

            # analyze native libraries
            status.update("[yellow]Analyzing native libraries...")
            frida_natives, encrypted = analyze_natives(arm_apk_path)
            status.console.log(
                f"Found protected libraries: [bold green]{', '.join(frida_natives) if frida_natives else 'None'}"
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
            java_results, native_results = attach_and_run_script(
                app_pid, reflection_to_hydrate, frida_natives
            )
            force_stop(args.target)
            status.console.log("Extracted runtime data and stopped app")

            # generate keystreams
            keystreams: dict[str, bytes] = {}
            if encrypted:
                status.update("[yellow]Generating decryption keystreams...")
                keystreams = {
                    lib: keystream(encrypted[lib], native_results[lib].decrypted)
                    for lib in encrypted
                }
                status.console.log("Generated decryption keystreams")

            # create output directory
            output_dir = Path(args.output or f"output/{args.target}_{version}")
            output_dir.mkdir(parents=True, exist_ok=True)

            # write results to ouput JSON
            status.update("[yellow]Writing JSON...")
            with open(output_dir / "java.json", "w", encoding="utf-8") as file:
                file.write(java_results.model_dump_json(indent=2))
            native_json = {
                lib: LibraryData(
                    keystream=base64.b64encode(keystreams[lib]).decode("utf-8"),
                    relocations=native_results[lib].relocations,
                )
                for lib in native_results
            }
            with open(output_dir / "native.json", "w", encoding="utf-8") as file:
                file.write(
                    TypeAdapter(dict[str, LibraryData])
                    .dump_json(native_json, indent=2)
                    .decode()
                )
            status.console.log(f"Saved JSON output: [bold green]{output_dir}")

        finally:
            if args.clean:
                status.update("[yellow]Cleaning up...")
                if temp_path and os.path.exists(temp_path):
                    shutil.rmtree(temp_path)

    console.print("[bold yellow]Finished!")


if __name__ == "__main__":
    main()

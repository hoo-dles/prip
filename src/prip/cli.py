import argparse
import os
import shutil
import sys
import tempfile
from collections import defaultdict
from importlib.metadata import version
from pathlib import Path
from time import sleep

from loguru import logger
from rich.console import Console

__version__ = version("prip")

title = """
          ███████████   █████ ███████████ 
          ░░███░░░░░███ ░░███ ░░███░░░░░███
 ████████  ░███    ░███  ░███  ░███    ░███
░░███░░███ ░██████████   ░███  ░██████████
 ░███ ░███ ░███░░░░░███  ░███  ░███░░░░░░
 ░███ ░███ ░███    ░███  ░███  ░███
 ░███████  █████   █████ █████ █████
 ░███░░░  ░░░░░   ░░░░░ ░░░░░ ░░░░░
 ░███
 █████   [green]by hoodles[/green]
░░░░░"""


def main():
    # suppress noisy output from androguard
    logger.remove()
    logger.add(sys.stderr, level="WARNING")

    console = Console(log_path=False)
    console._log_render.omit_repeated_times = False

    ap = argparse.ArgumentParser(
        prog="prip",
        description="pRIP - Automatic extraction of pairipcore virtualized strings/methods and native library metadata.",
        formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=40),
    )
    ap.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    ap.add_argument(
        "target",
        help="package name of target app (com.my.example)",
    )
    ap.add_argument(
        "-o",
        "--out",
        dest="out_dir",
        help="path to JSON for extracted reflection values (default: ./output)",
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

    console.print(title + "\n")

    with console.status("[yellow]Loading dependencies...") as status:
        # lazy load
        from prip.json import write_json

        from .adb import (
            force_stop,
            get_package_version,
            launch_app,
            pull,
            pull_apks,
            try_get_pid,
        )
        from .dex import find_reflected, parse_dex
        from .frida import attach_and_run_script, start_frida_server
        from .models import LibraryData
        from .native import analyze_natives, clean_symbol_name, find_symbols, keystream

        temp_path = None

        try:
            # find base apk location on device and pull
            status.update("[yellow]Pulling APK splits from device...")
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
            missing_symbols = {
                (reloc.missing.module_path, reloc.missing.offset): ""
                for data in native_results.values()
                for reloc in data.relocations
                if reloc.missing
            }
            missing_count = len(missing_symbols)
            status.console.log(
                f"Extracted runtime data and stopped app {f'[yellow]({missing_count} unique missing symbols)' if missing_count else ''}"
            )

            # find missing symbols
            if missing_count:
                status.update("[yellow]Discovering missing symbols")
                # group offsets by lib
                lib_to_offsets: defaultdict[str, list[int]] = defaultdict(list)
                for path, offset in missing_symbols:
                    lib_to_offsets[path].append(offset)
                # find symbols and map (path, offset) -> symbol name
                for path, offsets in lib_to_offsets.items():
                    temp_lib_path = pull(path, temp_path)
                    symbols = find_symbols(temp_lib_path, offsets)
                    for offset, symbol in symbols.items():
                        missing_symbols[(path, offset)] = symbol
                # fix missing relocation
                for data in native_results.values():
                    for reloc in data.relocations:
                        if reloc.missing:
                            reloc.symbol = clean_symbol_name(
                                missing_symbols[
                                    (reloc.missing.module_path, reloc.missing.offset)
                                ]
                            )
                status.console.log("Fixed missing symbols")

            # generate keystreams and final data aggregate
            library_data: dict[str, LibraryData] = {}
            status.update("[yellow]Generating decryption keystreams...")
            for lib, enc in encrypted.items():
                res = native_results[lib]
                library_data[lib] = LibraryData(
                    keystream=keystream(enc, res.decrypted),
                    relocations=res.relocations,
                )
            status.console.log("Generated decryption keystreams")

            # write results to ouput JSON
            status.update("[yellow]Writing JSON...")
            output_dir = Path(args.out_dir or f"output/{args.target}_{version}")
            write_json(output_dir, java_results, library_data)
            status.console.log(f"Saved JSON output: [bold green]{output_dir.resolve()}")

        finally:
            if args.clean:
                status.update("[yellow]Cleaning up...")
                if temp_path and os.path.exists(temp_path):
                    shutil.rmtree(temp_path)

    console.print("[bold yellow]Finished!")


if __name__ == "__main__":
    main()

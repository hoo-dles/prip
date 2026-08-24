from pathlib import Path

from pydantic import TypeAdapter

from .models import JavaReflection, LibraryData


def _is_all_zero(data: bytes) -> bool:
    return data == b"\x00" * len(data)


def write_json(
    output_dir: Path, java_results: JavaReflection, library_data: dict[str, LibraryData]
):
    output_dir.mkdir(parents=True, exist_ok=True)

    with open(output_dir / "java.json", "w", encoding="utf-8") as file:
        file.write(java_results.model_dump_json(indent=2))

    # filter lib data that has no relocs and zerod keystream
    filtered = {
        k: v
        for k, v in library_data.items()
        if v.relocations and not _is_all_zero(v.keystream)
    }

    with open(output_dir / "native.json", "w", encoding="utf-8") as file:
        file.write(
            TypeAdapter(dict[str, LibraryData]).dump_json(filtered, indent=2).decode()
        )

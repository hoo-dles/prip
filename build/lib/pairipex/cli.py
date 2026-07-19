#!/usr/bin/env python3
"""
find_pure_field_classes.py

Scan a DEX (or APK) file with androguard (https://github.com/androguard/androguard,
`pip install androguard`) for classes that:

  - contain NO methods at all (direct or virtual, including constructors) -
    any class with a single method/constructor is skipped entirely
  - contain one or more fields, where EVERY field matches a requested
    type descriptor and access flags

All matching fields for each surviving class are captured and printed.

Install:
    pip install androguard

Usage:
    python find_pure_field_classes.py classes.dex --type I --flags public,static,final
    python find_pure_field_classes.py app.apk --type "Ljava/lang/String;" \
        --flags 0x19 --exact
    python find_pure_field_classes.py classes.dex --type I --flags public --debug
"""

import argparse
import sys

from androguard.core.dex import DEX

# Standard Dalvik access_flags bit values (dex-format spec)
ACCESS_FLAGS = {
    "public": 0x1,
    "private": 0x2,
    "protected": 0x4,
    "static": 0x8,
    "final": 0x10,
    "synchronized": 0x20,
    "volatile": 0x40,
    "bridge": 0x40,
    "transient": 0x80,
    "varargs": 0x80,
    "native": 0x100,
    "interface": 0x200,
    "abstract": 0x400,
    "strict": 0x800,
    "synthetic": 0x1000,
    "annotation": 0x2000,
    "enum": 0x4000,
    "constructor": 0x10000,
    "declared_synchronized": 0x20000,
}


def parse_flags(spec):
    """Accept either an int (decimal or 0x-hex string) or comma-separated
    flag names like 'public,static,final'."""
    spec = spec.strip()
    try:
        return int(spec, 0)
    except ValueError:
        pass
    total = 0
    for name in spec.split(","):
        name = name.strip().lower()
        if not name:
            continue
        if name not in ACCESS_FLAGS:
            raise ValueError(
                f"Unknown access flag name: {name!r}. "
                f"Known: {', '.join(sorted(ACCESS_FLAGS))}"
            )
        total |= ACCESS_FLAGS[name]
    return total


def load_dex_objects(path):
    """Return a list of androguard DEX objects for the given .dex or .apk file."""
    if path.lower().endswith(".apk"):
        from androguard.misc import AnalyzeAPK

        _, dex_list, _ = AnalyzeAPK(path)
        return dex_list if isinstance(dex_list, list) else [dex_list]
    else:
        with open(path, "rb") as fh:
            data = fh.read()
        return [DEX(data)]


def class_methods(cls):
    """Return the combined list of direct + virtual EncodedMethod objects
    for a class (constructors are direct methods, so they're included)."""
    class_data = cls.get_class_data()
    if class_data is None:
        return []
    return list(class_data.get_direct_methods()) + list(
        class_data.get_virtual_methods()
    )


def class_fields(cls):
    """Return all EncodedField objects (static + instance) for a class."""
    class_data = cls.get_class_data()
    if class_data is None:
        return []
    return list(class_data.get_static_fields()) + list(class_data.get_instance_fields())


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("dex_or_apk_file", help="Path to a .dex or .apk file")
    ap.add_argument(
        "--type",
        required=True,
        dest="field_type",
        help="Field type descriptor to match, e.g. 'I', 'Z', 'Ljava/lang/String;'",
    )
    ap.add_argument(
        "--flags",
        required=True,
        dest="field_flags",
        help="Required field access flags, e.g. 'public,static,final' or '0x19'",
    )
    ap.add_argument(
        "--exact",
        action="store_true",
        help="Require field access flags to match EXACTLY, instead of the "
        "default 'at least these flags are set' subset match",
    )
    ap.add_argument(
        "--debug",
        action="store_true",
        help="Print attribute listings for the first class/field/method found, then exit",
    )
    args = ap.parse_args()

    wanted_flags = parse_flags(args.field_flags)
    wanted_type = args.field_type

    dex_objects = load_dex_objects(args.dex_or_apk_file)

    if args.debug:
        for d in dex_objects:
            classes = list(d.get_classes())
            if not classes:
                continue
            cls = classes[0]
            print("Class attrs:", [a for a in dir(cls) if not a.startswith("_")])
            fields = class_fields(cls)
            if fields:
                print(
                    "Field attrs:", [a for a in dir(fields[0]) if not a.startswith("_")]
                )
            methods = class_methods(cls)
            if methods:
                print(
                    "Method attrs:",
                    [a for a in dir(methods[0]) if not a.startswith("_")],
                )
            break
        return

    results = []
    for d in dex_objects:
        for cls in d.get_classes():
            if class_methods(cls):
                continue  # any method/constructor -> disqualified

            fields = class_fields(cls)
            if not fields:
                continue  # nothing to capture

            matching_fields = []
            all_match = True
            for f in fields:
                f_type = f.get_descriptor()
                f_flags = f.get_access_flags()

                type_ok = f_type == wanted_type
                if args.exact:
                    flags_ok = f_flags == wanted_flags
                else:
                    flags_ok = (f_flags & wanted_flags) == wanted_flags

                if type_ok and flags_ok:
                    matching_fields.append(f)
                else:
                    all_match = False
                    break  # a field doesn't fit -> whole class disqualified

            if all_match and matching_fields:
                results.append((cls.get_name(), matching_fields))

    if not results:
        print("No matching classes found.")
        return

    for cls_name, flds in results:
        print(f"\nClass: {cls_name}")
        for f in flds:
            print(
                f"  field: {f.get_name()} : {f.get_descriptor()} "
                f"[{f.get_access_flags_string()}]"
            )


if __name__ == "__main__":
    main()

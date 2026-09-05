from enum import StrEnum
from pathlib import Path

from androguard.core.dex import ClassDataItem, EncodedField
from androguard.misc import apk, dex

from .models import JavaField, JavaReflection


class _ValidType(StrEnum):
    STRING = "Ljava/lang/String;"
    METHOD = "Ljava/lang/reflect/Method;"


_VALID_FLAGS = 0x1 | 0x8  # public static
_VALID_TYPES = [type.value for type in _ValidType]


def _to_java_name(cls: str):
    return cls[1:-1].replace("/", ".")


def _is_valid(field: EncodedField):
    return (
        field.get_descriptor() in _VALID_TYPES
        and field.get_access_flags() == _VALID_FLAGS
    )


def _match_class(class_data: ClassDataItem):
    if (
        not class_data
        or class_data.direct_methods_size + class_data.virtual_methods_size
        or class_data.instance_fields_size
        or not class_data.static_fields_size
    ):
        return None

    static_fields = class_data.get_static_fields()
    first_type = static_fields[0].get_descriptor()
    for f in static_fields:
        if not _is_valid(f) or f.get_descriptor() != first_type or f.get_init_value():
            return None

    return _ValidType(first_type)


def find_reflected(dexs: list[dex.DEX]):
    result = JavaReflection()

    for d in dexs:
        for cls in d.get_classes():
            cls_data = cls.get_class_data()
            fields_type = _match_class(cls_data)
            if not fields_type:
                continue

            entries = [
                JavaField(name=f.get_name()) for f in cls_data.get_static_fields()
            ]

            java_class = _to_java_name(cls.get_name())
            match fields_type:
                case _ValidType.STRING:
                    result.strings[java_class] = entries
                case _ValidType.METHOD:
                    result.methods[java_class] = entries

    return result


def parse_dex(apk_path: Path):
    a = apk.APK(str(apk_path))
    dex_list: list[dex.DEX] = []
    for dex_b in a.get_all_dex():
        d = dex.DEX(dex_b, using_api=a.get_effective_target_sdk_version())
        dex_list.append(d)

    return dex_list

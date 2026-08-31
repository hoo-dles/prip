import base64

from pydantic import BaseModel, Field, field_serializer, field_validator

# --- Java Reflection ---


class JavaField(BaseModel):
    name: str
    value: str | None = None


class JavaReflection(BaseModel):
    methods: dict[str, list[JavaField]] = Field(default_factory=dict)
    strings: dict[str, list[JavaField]] = Field(default_factory=dict)


# --- Native Libraries ---


class TextSectionInfo(BaseModel):
    v_addr: int
    size: int


class LibraryFridaInfo(BaseModel):
    text_info: TextSectionInfo
    got_vaddrs: list[int]


class MissingSymbol(BaseModel):
    module_path: str
    offset: int


class Relocation(BaseModel):
    address: int
    symbol: str
    missing: MissingSymbol | None = Field(default=None, exclude=True)


class LibraryFridaResult(BaseModel):
    decrypted: bytes
    relocations: list[Relocation]

    @field_validator("decrypted", mode="before")
    @classmethod
    def convert_int_list_to_bytes(cls, v):
        if isinstance(v, list):
            return bytes(v)
        return v


class LibraryData(BaseModel):
    keystream: bytes
    relocations: list[Relocation]

    @field_serializer("keystream", when_used="json")
    def serialize_keystream(self, keystream: bytes) -> str:
        return base64.b64encode(keystream).decode("utf-8")

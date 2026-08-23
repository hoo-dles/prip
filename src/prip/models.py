from pydantic import BaseModel, Field, field_validator

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


class Relocation(BaseModel):
    address: int
    symbol: str


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
    keystream: str
    relocations: list[Relocation]

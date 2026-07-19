from dataclasses import asdict, dataclass, field


@dataclass
class Field:
    name: str
    value: str = ""


@dataclass
class Reflected:
    methods: dict[str, list[Field]] = field(default_factory=dict)
    strings: dict[str, list[Field]] = field(default_factory=dict)

    def serialize(self):
        return asdict(self)

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Iterable, Optional


def _parse_hex_int(value: str | int | None) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    value = value.strip()
    if value.startswith("0x") or value.startswith("0X"):
        return int(value, 16)
    return int(value)


@dataclass
class BinaryInfo:
    name: str
    hash: Optional[str] = None
    arch: Optional[str] = None
    image_base: Optional[int] = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "BinaryInfo":
        return cls(
            name=data["name"],
            hash=data.get("hash"),
            arch=data.get("arch"),
            image_base=_parse_hex_int(data.get("image_base")),
        )

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        if self.image_base is not None:
            result["image_base"] = hex(self.image_base)
        return result


@dataclass
class CalleeRef:
    type: str
    name: Optional[str] = None
    rva: Optional[int] = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CalleeRef":
        return cls(
            type=data.get("type", "local"),
            name=data.get("name"),
            rva=_parse_hex_int(data.get("rva")),
        )

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        if self.rva is not None:
            result["rva"] = hex(self.rva)
        return result


@dataclass
class FunctionMeta:
    va: Optional[int]
    rva: Optional[int]
    name: Optional[str] = None
    size: Optional[int] = None
    basic_blocks: Optional[int] = None
    callers: list[int] = field(default_factory=list)
    callees: list[CalleeRef] = field(default_factory=list)
    strings: list[str] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    raw_bytes: Optional[str] = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FunctionMeta":
        callers = [_parse_hex_int(v) for v in data.get("callers", []) if v is not None]
        callees = [CalleeRef.from_dict(item) for item in data.get("callees", [])]
        return cls(
            va=_parse_hex_int(data.get("va")),
            rva=_parse_hex_int(data.get("rva")),
            name=data.get("name"),
            size=data.get("size"),
            basic_blocks=data.get("basic_blocks"),
            callers=[c for c in callers if c is not None],
            callees=callees,
            strings=data.get("strings", []),
            imports=data.get("imports", []),
            raw_bytes=data.get("raw_bytes"),
        )

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        if self.va is not None:
            result["va"] = hex(self.va)
        if self.rva is not None:
            result["rva"] = hex(self.rva)
        result["callers"] = [hex(v) for v in self.callers]
        result["callees"] = [callee.to_dict() for callee in self.callees]
        return result


@dataclass
class StaticMeta:
    binary: BinaryInfo
    functions: list[FunctionMeta]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "StaticMeta":
        binary = BinaryInfo.from_dict(data["binary"])
        functions = [FunctionMeta.from_dict(fn) for fn in data.get("functions", [])]
        return cls(binary=binary, functions=functions)

    def to_dict(self) -> dict[str, Any]:
        return {
            "binary": self.binary.to_dict(),
            "functions": [fn.to_dict() for fn in self.functions],
        }


@dataclass
class EndpointMeta:
    module: str
    arch: str
    rva: int
    score: int
    tags: list[str] = field(default_factory=list)
    reason: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EndpointMeta":
        rva = _parse_hex_int(data.get("rva"))
        if rva is None:
            raise ValueError("EndpointMeta requires an RVA")
        return cls(
            module=data["module"],
            arch=data["arch"],
            rva=rva,
            score=data.get("score", 0),
            tags=data.get("tags", []),
            reason=data.get("reason", []),
        )

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["rva"] = hex(self.rva)
        return result


@dataclass
class HookProto:
    ret: Optional[str] = None
    args: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "HookProto":
        return cls(ret=data.get("ret"), args=data.get("args", []))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class OnEnterHook:
    log_args: list[int] = field(default_factory=list)
    hexdump_args: list[int] = field(default_factory=list)
    log_stack: bool = False

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "OnEnterHook":
        return cls(
            log_args=data.get("log_args", []),
            hexdump_args=data.get("hexdump_args", []),
            log_stack=data.get("log_stack", False),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class OnLeaveHook:
    log_ret: bool = True
    hexdump_ret: bool = False

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "OnLeaveHook":
        return cls(log_ret=data.get("log_ret", True), hexdump_ret=data.get("hexdump_ret", False))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class HookConfig:
    onEnter: OnEnterHook = field(default_factory=OnEnterHook)
    onLeave: OnLeaveHook = field(default_factory=OnLeaveHook)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "HookConfig":
        return cls(
            onEnter=OnEnterHook.from_dict(data.get("onEnter", {})),
            onLeave=OnLeaveHook.from_dict(data.get("onLeave", {})),
        )

    def to_dict(self) -> dict[str, Any]:
        return {"onEnter": self.onEnter.to_dict(), "onLeave": self.onLeave.to_dict()}


@dataclass
class HookSpec:
    module: str
    arch: str
    offset: int
    sig: Optional[str] = None
    name: Optional[str] = None
    tags: list[str] = field(default_factory=list)
    proto: Optional[HookProto] = None
    hook: HookConfig = field(default_factory=HookConfig)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "HookSpec":
        offset = _parse_hex_int(data.get("offset"))
        if offset is None:
            raise ValueError("HookSpec requires an offset")
        proto_data = data.get("proto")
        proto = HookProto.from_dict(proto_data) if proto_data else None
        hook_cfg = HookConfig.from_dict(data.get("hook", {}))
        return cls(
            module=data["module"],
            arch=data["arch"],
            offset=offset,
            sig=data.get("sig"),
            name=data.get("name"),
            tags=data.get("tags", []),
            proto=proto,
            hook=hook_cfg,
        )

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "module": self.module,
            "arch": self.arch,
            "offset": hex(self.offset),
            "sig": self.sig,
            "name": self.name,
            "tags": list(self.tags),
            "hook": self.hook.to_dict(),
        }
        if self.proto:
            payload["proto"] = self.proto.to_dict()
        return payload


def iter_hookspecs(items: Iterable[dict[str, Any]]) -> list[HookSpec]:
    return [HookSpec.from_dict(item) for item in items]

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
    os: Optional[str] = None  # "windows" | "linux" | "android" | "macos" | "ios" | None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "BinaryInfo":
        return cls(
            name=data["name"],
            hash=data.get("hash"),
            arch=data.get("arch"),
            image_base=_parse_hex_int(data.get("image_base")),
            os=data.get("os"),
        )

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        if self.image_base is not None:
            result["image_base"] = hex(self.image_base)
        # Drop os when None to keep parity with existing JSON shapes
        if self.os is None:
            result.pop("os", None)
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
    module: str  # primary module name (Frida tries this first)
    arch: str
    offset: int
    sig: Optional[str] = None
    name: Optional[str] = None
    tags: list[str] = field(default_factory=list)
    proto: Optional[HookProto] = None
    hook: HookConfig = field(default_factory=HookConfig)
    # Alternate module names tried in order if `module` doesn't resolve.
    # Useful for ELF version suffixes (libfoo.so vs libfoo.so.1.2.3),
    # Mach-O dylib variants (libfoo.dylib vs libfoo.1.dylib), and PE/wine
    # name differences (app.exe vs app).
    module_aliases: list[str] = field(default_factory=list)

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
            module_aliases=list(data.get("module_aliases", [])),
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
        # Omit when empty to keep parity with pre-PR-4 JSON shapes
        if self.module_aliases:
            payload["module_aliases"] = list(self.module_aliases)
        return payload


def iter_hookspecs(items: Iterable[dict[str, Any]]) -> list[HookSpec]:
    return [HookSpec.from_dict(item) for item in items]


@dataclass
class JavaNativeMethod:
    """A `native` method declaration recovered from Java/Kotlin sources.

    Produced by `jadx_runner.extract_native_methods`. Consumed by the JNI bridge
    module (PR #7) to predict the corresponding C symbol name (`Java_<pkg>_<cls>_<m>`)
    or to anchor RegisterNatives correlation.

    `arg_types` and `return_type` are raw Java type strings as they appeared in
    source (e.g. `"byte[]"`, `"Map<String, String>"`); JNI signature conversion
    (`Ljava/util/Map;`) is intentionally deferred to the bridge so this module
    stays a pure extractor.
    """

    class_fqn: str  # fully-qualified class name, e.g. "com.example.foo.Bar"
    method_name: str
    return_type: str
    arg_types: list[str] = field(default_factory=list)
    is_static: bool = False  # affects JNI second-arg type (jclass vs jobject)
    source_file: Optional[str] = None  # path relative to jadx output root

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "JavaNativeMethod":
        return cls(
            class_fqn=data["class_fqn"],
            method_name=data["method_name"],
            return_type=data.get("return_type", "void"),
            arg_types=list(data.get("arg_types", [])),
            is_static=bool(data.get("is_static", False)),
            source_file=data.get("source_file"),
        )

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "class_fqn": self.class_fqn,
            "method_name": self.method_name,
            "return_type": self.return_type,
            "arg_types": list(self.arg_types),
            "is_static": self.is_static,
        }
        if self.source_file is not None:
            result["source_file"] = self.source_file
        return result


@dataclass
class JniBridge:
    """Mapping between a Java native method and its predicted/matched C symbol.

    Produced by ``jni_bridge.build_bridges`` from a list of JavaNativeMethod
    records. ``predicted_short`` is always present (Java_<class>_<method>);
    ``predicted_long`` is set only when overload disambiguation is needed
    (multiple natives in the same class share a name). ``matched_symbol`` is
    populated by ``jni_bridge.correlate_symbols`` when an actual exported
    symbol matches one of the predictions.

    ``unresolved_arg_types`` lists Java type expressions that could not be
    converted to a JNI signature (typically third-party classes whose FQN
    isn't recoverable from the source alone). When non-empty, the long-form
    prediction may be unavailable or imprecise.
    """

    java_method: JavaNativeMethod
    predicted_short: str
    predicted_long: Optional[str] = None
    matched_symbol: Optional[str] = None
    unresolved_arg_types: list[str] = field(default_factory=list)

    @property
    def is_matched(self) -> bool:
        return self.matched_symbol is not None

    @property
    def is_overloaded(self) -> bool:
        return self.predicted_long is not None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "JniBridge":
        return cls(
            java_method=JavaNativeMethod.from_dict(data["java_method"]),
            predicted_short=data["predicted_short"],
            predicted_long=data.get("predicted_long"),
            matched_symbol=data.get("matched_symbol"),
            unresolved_arg_types=list(data.get("unresolved_arg_types", [])),
        )

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "java_method": self.java_method.to_dict(),
            "predicted_short": self.predicted_short,
        }
        if self.predicted_long is not None:
            result["predicted_long"] = self.predicted_long
        if self.matched_symbol is not None:
            result["matched_symbol"] = self.matched_symbol
        if self.unresolved_arg_types:
            result["unresolved_arg_types"] = list(self.unresolved_arg_types)
        return result


@dataclass
class AndroidComponent:
    """An activity / service / receiver / provider declared in AndroidManifest.xml.

    Class names are resolved relative to the application package per Android
    convention: leading '.' is replaced with the package, and bare names get
    the package prepended. Already-qualified names pass through unchanged.

    `exported` reflects only the literal `android:exported="true"` attribute;
    Android's full inference rule (which depends on intent-filter presence
    and target SDK) is intentionally NOT applied here — callers can layer it
    on top using `intent_actions` if needed.
    """

    type: str  # "activity" | "service" | "receiver" | "provider"
    name: str  # FQN class name (resolved against package)
    exported: bool = False
    permission: Optional[str] = None
    intent_actions: list[str] = field(default_factory=list)
    # Provider-only attribute audited by manifest_audit (PR #11). Defaults to
    # False; True signals possible URI-based path traversal if not validated.
    grant_uri_permissions: bool = False

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AndroidComponent":
        return cls(
            type=data["type"],
            name=data["name"],
            exported=bool(data.get("exported", False)),
            permission=data.get("permission"),
            intent_actions=list(data.get("intent_actions", [])),
            grant_uri_permissions=bool(data.get("grant_uri_permissions", False)),
        )

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "type": self.type,
            "name": self.name,
            "exported": self.exported,
        }
        if self.permission is not None:
            result["permission"] = self.permission
        if self.intent_actions:
            result["intent_actions"] = list(self.intent_actions)
        if self.grant_uri_permissions:
            result["grant_uri_permissions"] = True
        return result


@dataclass
class AndroidAppMeta:
    """Decoded Android application metadata extracted from AndroidManifest.xml.

    Produced by `apk_decoder.parse_android_manifest`. Consumed by the Android
    pipeline (PR #9) to score components, identify entry points that load
    native libraries, and surface attack-surface info for the report layer.
    """

    package_name: str
    application_class: Optional[str] = None
    permissions: list[str] = field(default_factory=list)
    components: list[AndroidComponent] = field(default_factory=list)
    min_sdk: Optional[int] = None
    target_sdk: Optional[int] = None
    debuggable: bool = False
    extract_native_libs: Optional[bool] = None
    # PR #11 additions for manifest audit. None = "attribute not specified" —
    # distinct from explicit True/False, because Android's actual default
    # depends on targetSdkVersion (audit rules apply that logic).
    uses_cleartext_traffic: Optional[bool] = None  # default: targetSdk<28 → true
    allow_backup: Optional[bool] = None              # default: targetSdk<31 → true
    network_security_config: Optional[str] = None  # resource ref like "@xml/nsc"

    @property
    def activities(self) -> list[AndroidComponent]:
        return [c for c in self.components if c.type == "activity"]

    @property
    def services(self) -> list[AndroidComponent]:
        return [c for c in self.components if c.type == "service"]

    @property
    def receivers(self) -> list[AndroidComponent]:
        return [c for c in self.components if c.type == "receiver"]

    @property
    def providers(self) -> list[AndroidComponent]:
        return [c for c in self.components if c.type == "provider"]

    @property
    def exported_components(self) -> list[AndroidComponent]:
        return [c for c in self.components if c.exported]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AndroidAppMeta":
        return cls(
            package_name=data.get("package_name", ""),
            application_class=data.get("application_class"),
            permissions=list(data.get("permissions", [])),
            components=[AndroidComponent.from_dict(c) for c in data.get("components", [])],
            min_sdk=data.get("min_sdk"),
            target_sdk=data.get("target_sdk"),
            debuggable=bool(data.get("debuggable", False)),
            extract_native_libs=data.get("extract_native_libs"),
            uses_cleartext_traffic=data.get("uses_cleartext_traffic"),
            allow_backup=data.get("allow_backup"),
            network_security_config=data.get("network_security_config"),
        )

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "package_name": self.package_name,
            "permissions": list(self.permissions),
            "components": [c.to_dict() for c in self.components],
            "debuggable": self.debuggable,
        }
        if self.application_class is not None:
            result["application_class"] = self.application_class
        if self.min_sdk is not None:
            result["min_sdk"] = self.min_sdk
        if self.target_sdk is not None:
            result["target_sdk"] = self.target_sdk
        if self.extract_native_libs is not None:
            result["extract_native_libs"] = self.extract_native_libs
        if self.uses_cleartext_traffic is not None:
            result["uses_cleartext_traffic"] = self.uses_cleartext_traffic
        if self.allow_backup is not None:
            result["allow_backup"] = self.allow_backup
        if self.network_security_config is not None:
            result["network_security_config"] = self.network_security_config
        return result


@dataclass
class ManifestFinding:
    """A single rule violation surfaced by manifest_audit.

    Self-contained record so callers can render reports without re-running
    rules. `severity` ∈ {critical, high, medium, low, info}; `references`
    are usually OWASP MASVS / CWE / Android docs identifiers.
    """

    rule_id: str           # e.g. "MANIFEST-001"
    title: str             # short human-readable label
    severity: str          # critical | high | medium | low | info
    detail: str = ""
    remediation: str = ""
    component: Optional[str] = None  # FQN of the offending component, or None for app-level
    references: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ManifestFinding":
        return cls(
            rule_id=data["rule_id"],
            title=data["title"],
            severity=data.get("severity", "info"),
            detail=data.get("detail", ""),
            remediation=data.get("remediation", ""),
            component=data.get("component"),
            references=list(data.get("references", [])),
        )

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
        }
        if self.detail:
            result["detail"] = self.detail
        if self.remediation:
            result["remediation"] = self.remediation
        if self.component is not None:
            result["component"] = self.component
        if self.references:
            result["references"] = list(self.references)
        return result


@dataclass
class AndroidAuditReport:
    """Aggregated manifest_audit findings for an APK.

    `findings` order matches rule registration order in manifest_audit.RULES;
    callers wanting severity-grouped output use `by_severity`.
    """

    package_name: str
    findings: list[ManifestFinding] = field(default_factory=list)

    _SEVERITY_ORDER: tuple[str, ...] = field(
        default=("critical", "high", "medium", "low", "info"),
        init=False,
        repr=False,
    )

    @property
    def by_severity(self) -> dict[str, list[ManifestFinding]]:
        result: dict[str, list[ManifestFinding]] = {}
        for f in self.findings:
            result.setdefault(f.severity, []).append(f)
        return result

    @property
    def severity_counts(self) -> dict[str, int]:
        return {sev: len(items) for sev, items in self.by_severity.items()}

    def has_severity_at_least(self, threshold: str) -> bool:
        """True if any finding's severity is >= threshold (critical highest).

        Useful for CI/CD gates: ``report.has_severity_at_least("high")``.
        """
        order = self._SEVERITY_ORDER
        if threshold not in order:
            return False
        cutoff = order.index(threshold)
        for f in self.findings:
            if f.severity in order and order.index(f.severity) <= cutoff:
                return True
        return False

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AndroidAuditReport":
        return cls(
            package_name=data.get("package_name", ""),
            findings=[ManifestFinding.from_dict(f) for f in data.get("findings", [])],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "package_name": self.package_name,
            "findings": [f.to_dict() for f in self.findings],
            "severity_counts": self.severity_counts,
        }

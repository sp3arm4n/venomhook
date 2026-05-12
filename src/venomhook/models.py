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
    # Optional Android-specific metadata. Populated by android_pipeline when
    # the input is an APK; remains None for plain PE/ELF/Mach-O inputs so
    # existing JSON shapes stay backward-compatible.
    android: Optional["AndroidAppMeta"] = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "StaticMeta":
        binary = BinaryInfo.from_dict(data["binary"])
        functions = [FunctionMeta.from_dict(fn) for fn in data.get("functions", [])]
        android_data = data.get("android")
        android = AndroidAppMeta.from_dict(android_data) if android_data else None
        return cls(binary=binary, functions=functions, android=android)

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "binary": self.binary.to_dict(),
            "functions": [fn.to_dict() for fn in self.functions],
        }
        if self.android is not None:
            result["android"] = self.android.to_dict()
        return result


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
    # Phase 5 ③ — natural-language one-liner describing the Java↔Native
    # flow. Populated only when --use-llm-flow is enabled; remains None
    # in pure-rule output, so existing JSON consumers stay backward-
    # compatible (omitted from to_dict when None).
    description: Optional[str] = None

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
            description=data.get("description"),
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
        if self.description is not None:
            payload["description"] = self.description
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
class IntentDataSpec:
    """A single ``<data>`` element inside an intent-filter.

    Phase 6-3. Captures every URI/MIME attribute Android matches against so
    PoC builders can construct realistic ``am start -a VIEW -d <uri>``
    recipes. Each attribute is optional — Android takes the cross product
    of attributes within one filter, which the PoC builder reconstructs.
    """
    scheme: Optional[str] = None
    host: Optional[str] = None
    port: Optional[str] = None
    path: Optional[str] = None
    path_prefix: Optional[str] = None
    path_pattern: Optional[str] = None
    path_suffix: Optional[str] = None
    mime_type: Optional[str] = None
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "IntentDataSpec":
        return cls(
            scheme=data.get("scheme"),
            host=data.get("host"),
            port=data.get("port"),
            path=data.get("path"),
            path_prefix=data.get("path_prefix"),
            path_pattern=data.get("path_pattern"),
            path_suffix=data.get("path_suffix"),
            mime_type=data.get("mime_type"),
        )
    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in (
            ("scheme", self.scheme),
            ("host", self.host),
            ("port", self.port),
            ("path", self.path),
            ("path_prefix", self.path_prefix),
            ("path_pattern", self.path_pattern),
            ("path_suffix", self.path_suffix),
            ("mime_type", self.mime_type),
        ):
            if value is not None:
                result[key] = value
        return result


@dataclass
class IntentFilter:
    """A single ``<intent-filter>`` declared on a component.

    Preserves the action / category / data grouping that ``AndroidComponent.
    intent_actions`` (a flat list) loses. PoC builders need this grouping to
    decide whether a category=BROWSABLE filter is paired with a deeplink
    scheme (i.e. attacker-reachable from a web page) or whether action.MAIN
    + LAUNCHER stands alone.
    """
    actions: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    data: list[IntentDataSpec] = field(default_factory=list)
    @property
    def is_browsable(self) -> bool:
        return "android.intent.category.BROWSABLE" in self.categories
    @property
    def is_launcher(self) -> bool:
        return "android.intent.category.LAUNCHER" in self.categories
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "IntentFilter":
        return cls(
            actions=list(data.get("actions", [])),
            categories=list(data.get("categories", [])),
            data=[IntentDataSpec.from_dict(d) for d in data.get("data", [])],
        )
    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {}
        if self.actions:
            result["actions"] = list(self.actions)
        if self.categories:
            result["categories"] = list(self.categories)
        if self.data:
            result["data"] = [d.to_dict() for d in self.data]
        return result


@dataclass
class AndroidComponent:
    """An activity / service / receiver / provider declared in AndroidManifest.xml.
    Class names are resolved relative to the application package per Android
    convention: leading '.' is replaced with the package, and bare names get
    the package prepended. Already-qualified names pass through unchanged.
    `exported` reflects the literal `android:exported` value when present.
    `exported_declared=False` means the attribute was absent in the manifest;
    audit code can then apply Android's target-SDK-dependent default rules.
    """
    type: str  # "activity" | "service" | "receiver" | "provider"
    name: str  # FQN class name (resolved against package)
    exported: bool = False
    exported_declared: bool = True
    permission: Optional[str] = None
    intent_actions: list[str] = field(default_factory=list)
    # Provider-only attribute audited by manifest_audit (PR #11). Defaults to
    # False; True signals possible URI-based path traversal if not validated.
    grant_uri_permissions: bool = False
    # Provider-only — list of `android:authorities` values, semicolon-split.
    # PoC generator (Phase 3) substitutes the first authority into
    # content:// recipes when present; empty for non-provider components.
    authorities: list[str] = field(default_factory=list)
    # Phase 6-3 — structured intent-filter records (action/category/data
    # preserved together). intent_actions above remains as a flat compat
    # accessor; new code should prefer this list.
    intent_filters: list[IntentFilter] = field(default_factory=list)
    @property
    def is_browsable(self) -> bool:
        """True if any filter on this component carries category.BROWSABLE.

        BROWSABLE means the activity is reachable via a web link (i.e. the
        OS will route a `https://...` or `<scheme>://...` from a browser /
        another app's Intent here). Pentest priority: every browsable
        activity is an external attack surface, regardless of `exported`.
        """
        return any(f.is_browsable for f in self.intent_filters)
    @property
    def data_schemes(self) -> list[str]:
        """Sorted, deduplicated set of URI schemes from all filters."""
        seen: set[str] = set()
        for f in self.intent_filters:
            for d in f.data:
                if d.scheme:
                    seen.add(d.scheme)
        return sorted(seen)
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AndroidComponent":
        return cls(
            type=data["type"],
            name=data["name"],
            exported=bool(data.get("exported", False)),
            exported_declared=bool(data.get("exported_declared", "exported" in data)),
            permission=data.get("permission"),
            intent_actions=list(data.get("intent_actions", [])),
            grant_uri_permissions=bool(data.get("grant_uri_permissions", False)),
            authorities=list(data.get("authorities", [])),
            intent_filters=[IntentFilter.from_dict(f) for f in data.get("intent_filters", [])],
        )
    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "type": self.type,
            "name": self.name,
            "exported": self.exported,
        }
        if not self.exported_declared:
            result["exported_declared"] = False
        if self.permission is not None:
            result["permission"] = self.permission
        if self.intent_actions:
            result["intent_actions"] = list(self.intent_actions)
        if self.grant_uri_permissions:
            result["grant_uri_permissions"] = True
        if self.authorities:
            result["authorities"] = list(self.authorities)
        if self.intent_filters:
            result["intent_filters"] = [f.to_dict() for f in self.intent_filters]
        return result
@dataclass
class NetworkSecurityConfigMeta:
    """Resolved contents of the network-security-config XML resource.

    The manifest only references the resource by name ("@xml/nsc"); the
    actual cleartext / trust / pin policy lives in res/xml/<nsc>.xml. This
    record captures the subset that drives audit rules (Phase 6-2).
    base_cleartext_permitted is None when no <base-config> is present.
    """
    base_cleartext_permitted: Optional[bool] = None
    cleartext_domains: list[str] = field(default_factory=list)
    base_trusts_user_certs: bool = False
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "NetworkSecurityConfigMeta":
        return cls(
            base_cleartext_permitted=data.get("base_cleartext_permitted"),
            cleartext_domains=list(data.get("cleartext_domains", [])),
            base_trusts_user_certs=bool(data.get("base_trusts_user_certs", False)),
        )
    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {}
        if self.base_cleartext_permitted is not None:
            result["base_cleartext_permitted"] = self.base_cleartext_permitted
        if self.cleartext_domains:
            result["cleartext_domains"] = list(self.cleartext_domains)
        if self.base_trusts_user_certs:
            result["base_trusts_user_certs"] = True
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
    # Phase 6-2: parsed NSC body. Populated only when the resource was found
    # alongside the manifest (apktool dir layout). None = "no NSC referenced
    # OR not resolved" — audit rules treat None as "no policy override".
    nsc: Optional["NetworkSecurityConfigMeta"] = None
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
        nsc_data = data.get("nsc")
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
            nsc=NetworkSecurityConfigMeta.from_dict(nsc_data) if nsc_data else None,
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
        if self.nsc is not None:
            nsc_dict = self.nsc.to_dict()
            if nsc_dict:
                result["nsc"] = nsc_dict
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


@dataclass
class CodeOccurrence:
    """One additional line where the same (rule_id, class_fqn) fired.

    Phase 11-1. Used to compress duplicate findings inside one class —
    the audit engine still scans every line, but the report shows one
    representative finding per (rule, class) and rolls the rest into
    ``CodeFinding.occurrences`` so the operator sees "URL hardcoded
    here, plus 11 more lines in this class" instead of 12 separate
    cards.
    """

    line_no: int
    line_text: str = ""
    file: str = ""
    evidence_tier: str = "java"  # follows the parent finding's tier by default

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CodeOccurrence":
        return cls(
            line_no=int(data.get("line_no", 0)),
            line_text=data.get("line_text", ""),
            file=data.get("file", ""),
            evidence_tier=data.get("evidence_tier", "java"),
        )

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"line_no": self.line_no}
        if self.line_text:
            result["line_text"] = self.line_text
        if self.file:
            result["file"] = self.file
        if self.evidence_tier and self.evidence_tier != "java":
            result["evidence_tier"] = self.evidence_tier
        return result


@dataclass
class CodeFinding:
    """A single code-level rule violation found in jadx-decompiled Java sources.

    Phase 7. Counterpart to ManifestFinding for static patterns inside
    code (hardcoded HTTP, weak Cipher mode, WebView JS enable, etc.).
    `file` is the path relative to the jadx output root so the operator
    can navigate without knowing the absolute analysis dir; `line_no`
    and `line_text` together let a report renderer cite evidence.
    `class_fqn` is filled when the rule can recover the enclosing class
    (typically by mapping ``foo/bar/Baz.java`` -> ``foo.bar.Baz``); empty
    string when the file lives outside any package directory.
    """

    rule_id: str
    title: str
    severity: str
    file: str
    line_no: int = 0
    line_text: str = ""
    class_fqn: str = ""
    detail: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    # Phase 10-4: which decompiled representation produced this finding.
    # ``"java"`` (default) means a .java pattern via code_audit; ``"smali"``
    # means the smali fallback that runs whenever apktool produces
    # smali_classes*/ directories (always for any decoded APK), giving
    # us a guarantee of *some* code findings even when jadx fails
    # entirely. HTML / JSON consumers surface the tier next to each
    # finding so the reader knows the evidence form.
    evidence_tier: str = "java"
    # Phase 11-1: additional matches of the same (rule_id, class_fqn) in
    # the same class — kept as references to the line that fired so the
    # operator sees the spread without 12 duplicated cards. The
    # representative finding lives in the top-level fields above; this
    # list carries the rest (skip the first match — it's already in
    # the primary record).
    occurrences: list[CodeOccurrence] = field(default_factory=list)

    @property
    def occurrence_count(self) -> int:
        """Total matches (primary + extra occurrences). Useful for HTML."""
        return 1 + len(self.occurrences)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CodeFinding":
        return cls(
            rule_id=data["rule_id"],
            title=data["title"],
            severity=data.get("severity", "info"),
            file=data.get("file", ""),
            line_no=int(data.get("line_no", 0)),
            line_text=data.get("line_text", ""),
            class_fqn=data.get("class_fqn", ""),
            detail=data.get("detail", ""),
            remediation=data.get("remediation", ""),
            references=list(data.get("references", [])),
            evidence_tier=data.get("evidence_tier", "java"),
            occurrences=[
                CodeOccurrence.from_dict(o)
                for o in data.get("occurrences", [])
            ],
        )

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "file": self.file,
        }
        if self.line_no:
            result["line_no"] = self.line_no
        if self.line_text:
            result["line_text"] = self.line_text
        if self.class_fqn:
            result["class_fqn"] = self.class_fqn
        if self.detail:
            result["detail"] = self.detail
        if self.remediation:
            result["remediation"] = self.remediation
        if self.references:
            result["references"] = list(self.references)
        # Only serialize non-default tier to keep older JSON dumps clean.
        if self.evidence_tier and self.evidence_tier != "java":
            result["evidence_tier"] = self.evidence_tier
        if self.occurrences:
            result["occurrences"] = [o.to_dict() for o in self.occurrences]
        return result


@dataclass
class CodeAuditReport:
    """Aggregated code_audit findings for an APK's decompiled Java sources.

    Mirrors AndroidAuditReport: severity bucketing + CI gate helper.
    ``files_scanned`` lets reports show the audit's denominator
    (e.g. "47 findings across 312 .java files") so the operator knows
    whether a quiet result reflects a clean app or a small scan.
    """

    package_name: str
    findings: list[CodeFinding] = field(default_factory=list)
    files_scanned: int = 0
    # Phase 10-3: True when the underlying jadx decompile hit its timeout
    # but produced enough .java files for an audit. Operators reading the
    # HTML report need to know the audit ran on a subset so an empty
    # bucket can be distinguished from "rule didn't fire on partial input".
    partial: bool = False

    _SEVERITY_ORDER: tuple[str, ...] = field(
        default=("critical", "high", "medium", "low", "info"),
        init=False,
        repr=False,
    )

    @property
    def by_severity(self) -> dict[str, list[CodeFinding]]:
        result: dict[str, list[CodeFinding]] = {}
        for f in self.findings:
            result.setdefault(f.severity, []).append(f)
        return result

    @property
    def severity_counts(self) -> dict[str, int]:
        return {sev: len(items) for sev, items in self.by_severity.items()}

    def has_severity_at_least(self, threshold: str) -> bool:
        order = self._SEVERITY_ORDER
        if threshold not in order:
            return False
        cutoff = order.index(threshold)
        for f in self.findings:
            if f.severity in order and order.index(f.severity) <= cutoff:
                return True
        return False

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CodeAuditReport":
        return cls(
            package_name=data.get("package_name", ""),
            findings=[CodeFinding.from_dict(f) for f in data.get("findings", [])],
            files_scanned=int(data.get("files_scanned", 0)),
            partial=bool(data.get("partial", False)),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "package_name": self.package_name,
            "findings": [f.to_dict() for f in self.findings],
            "files_scanned": self.files_scanned,
            "severity_counts": self.severity_counts,
            "partial": self.partial,
        }


@dataclass
class PoCArtifact:
    """A single proof-of-concept recipe derived from a ManifestFinding.

    Self-contained: each artifact carries enough context (package_name,
    component, commands, expected evidence) to be rendered or executed
    without re-running the audit. `kind` distinguishes recipe transports
    so renderers can group artifacts under per-channel sections.
    """

    rule_id: str             # source ManifestFinding.rule_id
    title: str               # short human-readable label
    severity: str            # mirror of source finding's severity
    kind: str                # "adb" | "frida" | "shell" | "info"
    package_name: str
    component: Optional[str] = None
    description: str = ""
    commands: list[str] = field(default_factory=list)
    expected_evidence: str = ""
    notes: str = ""
    references: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PoCArtifact":
        return cls(
            rule_id=data["rule_id"],
            title=data["title"],
            severity=data.get("severity", "info"),
            kind=data.get("kind", "info"),
            package_name=data.get("package_name", ""),
            component=data.get("component"),
            description=data.get("description", ""),
            commands=list(data.get("commands", [])),
            expected_evidence=data.get("expected_evidence", ""),
            notes=data.get("notes", ""),
            references=list(data.get("references", [])),
        )

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "kind": self.kind,
            "package_name": self.package_name,
        }
        if self.component is not None:
            result["component"] = self.component
        if self.description:
            result["description"] = self.description
        if self.commands:
            result["commands"] = list(self.commands)
        if self.expected_evidence:
            result["expected_evidence"] = self.expected_evidence
        if self.notes:
            result["notes"] = self.notes
        if self.references:
            result["references"] = list(self.references)
        return result

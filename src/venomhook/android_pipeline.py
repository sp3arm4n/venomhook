"""Android pipeline — orchestrates APK → manifest + java natives + .so + JNI bridges.

Phase 2's keystone, extended in Phase 3 with manifest_audit + poc_generator
so a single `analyze_apk` call yields the full Android-side picture:
metadata, native correlation, vulnerability findings, and runnable PoC
recipes. Wires together the Phase 2 building blocks plus the Phase 1
binary-metadata extractor and the Phase 3 audit/PoC layer:

  apk_extractor   ->  ApkMeta + extracted .so file
  apk_decoder     ->  AndroidAppMeta            (optional; skipped if apktool absent)
  jadx_runner     ->  list[JavaNativeMethod]    (optional; skipped if jadx absent)
  binary_meta     ->  BinaryMeta of the .so     (lief; required by default)
  jni_bridge      ->  list[JniBridge]           (correlated against .so exports)
  manifest_audit  ->  AndroidAuditReport        (Phase 3; runs when app_meta present)
  poc_generator   ->  list[PoCArtifact]         (Phase 3; derived from audit report)

`apktool` and `jadx` are *optional*. When unavailable the pipeline records a
warning on the result and continues with reduced fidelity (the .so analysis
path remains intact). `lief` is required by default because BinaryMeta.exports
is what JNI correlation matches against; without it, no bridges can be
produced. Callers that only need manifest audit data may opt out of native
analysis requirements.

Ghidra-level function analysis is intentionally NOT invoked here. Callers
who want full FunctionMeta should run static_pipeline on
`AndroidAnalysis.extracted_so_path` separately. This keeps the Android
pipeline fast (lief is millisecond-scale; Ghidra is minutes-scale) and
composable.

Pure-Python orchestration; depends on apk_extractor, apk_decoder, jadx_runner,
jni_bridge, binary_meta, and the extended models.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from venomhook.apk_decoder import (
    ApkDecoderError,
    ApktoolConfig,
    ApktoolNotFoundError,
    decode_apk,
)
from venomhook.apk_extractor import (
    ApkExtractError,
    ApkMeta,
    extract_apk_meta,
    extract_native_lib,
    select_abi,
)
from venomhook.binary_meta import BinaryMeta, BinaryMetaError, extract_binary_meta
from venomhook.jadx_runner import (
    JadxConfig,
    JadxError,
    JadxNotFoundError,
    decompile_apk,
)
from venomhook.jni_bridge import build_bridges, correlate_symbols
from venomhook.manifest_audit import audit_manifest
from venomhook.models import (
    AndroidAppMeta,
    AndroidAuditReport,
    JavaNativeMethod,
    JniBridge,
    PoCArtifact,
)
from venomhook.poc_generator import generate_pocs


__all__ = [
    "AndroidAnalysis",
    "AndroidPipelineError",
    "analyze_apk",
]


class AndroidPipelineError(RuntimeError):
    """Raised when a non-recoverable step of the Android pipeline fails.

    Tool-availability failures (apktool/jadx missing) are recorded as warnings
    on the result instead of raising — see ``analyze_apk`` for the exact rule.
    """


@dataclass
class AndroidAnalysis:
    """End-to-end Android APK static analysis result.

    Captures the per-APK static prep needed before native-side hooking. Designed
    as input to the hookspec builder and as a snapshot that can be persisted
    (via to_dict) and reloaded for re-runs without redoing the heavy lifting.
    """

    apk_meta: ApkMeta
    selected_abi: Optional[str]
    extracted_so_path: Optional[str]  # absolute path to the extracted .so on disk
    so_meta: Optional[BinaryMeta]
    app_meta: Optional[AndroidAppMeta] = None  # None if apktool unavailable / failed
    java_natives: list[JavaNativeMethod] = field(default_factory=list)  # empty if jadx skipped
    bridges: list[JniBridge] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    # Phase 3 additions: vulnerability surface + runnable PoC recipes.
    # Both are derived from app_meta — None / empty when apktool was absent.
    audit_report: Optional[AndroidAuditReport] = None
    pocs: list[PoCArtifact] = field(default_factory=list)

    @property
    def matched_bridges(self) -> list[JniBridge]:
        return [b for b in self.bridges if b.is_matched]

    @property
    def unmatched_bridges(self) -> list[JniBridge]:
        return [b for b in self.bridges if not b.is_matched]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AndroidAnalysis":
        """Reconstruct an AndroidAnalysis from a previously serialized dict.

        Inverse of ``to_dict``; tolerates absent optional sections so older
        stored payloads (pre-Phase 3, missing audit_report/pocs) and the
        post-9d0dbca safety mode (selected_abi/extracted_so_path/so_meta
        possibly None when no native libs) round-trip cleanly. Used by
        the analysis cache to replay a prior run without rerunning
        apktool / lief / jadx.
        """
        from venomhook.apk_extractor import ApkMeta as _ApkMeta
        from venomhook.binary_meta import BinaryMeta as _BinaryMeta

        so_meta_data = data.get("so_meta")
        app_meta_data = data.get("app_meta")
        audit_data = data.get("audit_report")
        return cls(
            apk_meta=_ApkMeta.from_dict(data["apk_meta"]),
            selected_abi=data.get("selected_abi"),
            extracted_so_path=data.get("extracted_so_path"),
            so_meta=_BinaryMeta.from_dict(so_meta_data) if so_meta_data else None,
            app_meta=AndroidAppMeta.from_dict(app_meta_data) if app_meta_data else None,
            java_natives=[
                JavaNativeMethod.from_dict(m) for m in data.get("java_natives", [])
            ],
            bridges=[JniBridge.from_dict(b) for b in data.get("bridges", [])],
            warnings=list(data.get("warnings", [])),
            audit_report=AndroidAuditReport.from_dict(audit_data) if audit_data else None,
            pocs=[PoCArtifact.from_dict(p) for p in data.get("pocs", [])],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "apk_meta": self.apk_meta.to_dict(),
            "selected_abi": self.selected_abi,
            "extracted_so_path": self.extracted_so_path,
            "so_meta": self.so_meta.to_dict() if self.so_meta else None,
            "app_meta": self.app_meta.to_dict() if self.app_meta else None,
            "java_natives": [m.to_dict() for m in self.java_natives],
            "bridges": [b.to_dict() for b in self.bridges],
            "audit_report": self.audit_report.to_dict() if self.audit_report else None,
            "pocs": [p.to_dict() for p in self.pocs],
            "warnings": list(self.warnings),
        }


def analyze_apk(
    apk_path: str | Path,
    work_dir: str | Path,
    *,
    abi: str = "auto",
    lib_name: Optional[str] = None,
    use_apktool: bool = True,
    use_jadx: bool = True,
    apktool_config: Optional[ApktoolConfig] = None,
    jadx_config: Optional[JadxConfig] = None,
    fail_on_missing_tools: bool = False,
    require_native: bool = True,
) -> AndroidAnalysis:
    """Run the full Android-side static analysis pipeline on an APK.

    Steps (each may add a warning instead of raising, except where noted):
      1. Inspect APK with apk_extractor (REQUIRED — no fallback)
      2. Select ABI & extract chosen .so to ``work_dir/lib/`` (REQUIRED by default)
      3. Run lief on the extracted .so to produce BinaryMeta (REQUIRED by default)
      4. (if use_apktool) Decode AndroidManifest.xml; missing apktool → warning
      5. (if use_jadx) Decompile DEX & extract native methods; missing jadx → warning
      6. (if any java_natives) Build JniBridges and correlate against
         ``so_meta.exports``
      7. (if app_meta is set) Run manifest_audit + poc_generator to populate
         ``audit_report`` and ``pocs``. Pure-Python; never raises.

    `fail_on_missing_tools=True` upgrades apktool/jadx unavailability from
    warnings to AndroidPipelineError. Useful when the caller wants strict
    Tier 1 Android workflow guarantees.

    `require_native=False` lets manifest-only callers keep going when the APK
    has no native libraries, the requested ABI is unavailable, or BinaryMeta
    extraction fails. Native fields are then None / empty and JNI bridge
    correlation is skipped.

    Returns ``AndroidAnalysis``. Raises ``AndroidPipelineError`` on REQUIRED-
    step failures or (when strict) tool unavailability.
    """
    apk = Path(apk_path).resolve()
    work = Path(work_dir).resolve()
    work.mkdir(parents=True, exist_ok=True)

    warnings: list[str] = []

    # ----- Step 1: APK metadata -----
    try:
        apk_meta = extract_apk_meta(apk)
    except ApkExtractError as e:
        raise AndroidPipelineError(f"apk_extractor failed: {e}") from e

    selected_abi: Optional[str] = None
    so_path: Optional[Path] = None
    so_meta: Optional[BinaryMeta] = None

    if not apk_meta.abis:
        msg = f"APK contains no native libraries under lib/<abi>/: {apk}"
        if require_native:
            raise AndroidPipelineError(msg)
        warnings.append(f"{msg}; native analysis skipped")
    else:
        # ----- Step 2: ABI selection + .so extraction -----
        try:
            selected_abi = select_abi(apk_meta, abi)
        except ApkExtractError as e:
            msg = f"ABI selection failed: {e}"
            if require_native:
                raise AndroidPipelineError(msg) from e
            warnings.append(f"{msg}; native analysis skipped")

        if selected_abi is not None:
            so_dir = work / "lib"
            try:
                so_path = extract_native_lib(apk, selected_abi, lib_name, so_dir)
            except ApkExtractError as e:
                msg = f".so extraction failed (abi={selected_abi}, lib={lib_name}): {e}"
                if require_native:
                    raise AndroidPipelineError(msg) from e
                warnings.append(f"{msg}; native analysis skipped")

        # ----- Step 3: BinaryMeta of the .so (REQUIRED for JNI correlation) -----
        if so_path is not None:
            try:
                so_meta = extract_binary_meta(so_path)
            except BinaryMetaError as e:
                msg = f"binary_meta failed on {so_path}: {e}"
                if require_native:
                    raise AndroidPipelineError(msg) from e
                warnings.append(f"{msg}; native analysis skipped")

    # ----- Step 4: AndroidManifest decode (optional) -----
    app_meta: Optional[AndroidAppMeta] = None
    if use_apktool:
        apktool_out = work / "apktool"
        try:
            _, app_meta = decode_apk(apk, apktool_out, config=apktool_config)
        except ApktoolNotFoundError as e:
            msg = f"apktool unavailable, skipping manifest decode: {e}"
            if fail_on_missing_tools:
                raise AndroidPipelineError(msg) from e
            warnings.append(msg)
        except ApkDecoderError as e:
            warnings.append(f"apktool decode failed (continuing): {e}")

    # ----- Step 5: jadx decompile + native method extract (optional) -----
    java_natives: list[JavaNativeMethod] = []
    if use_jadx:
        jadx_out = work / "jadx"
        try:
            _, java_natives = decompile_apk(apk, jadx_out, config=jadx_config)
        except JadxNotFoundError as e:
            msg = f"jadx unavailable, skipping Java decompile: {e}"
            if fail_on_missing_tools:
                raise AndroidPipelineError(msg) from e
            warnings.append(msg)
        except JadxError as e:
            warnings.append(f"jadx decompile failed (continuing): {e}")

    # ----- Step 6: JNI bridge construction + correlation -----
    bridges: list[JniBridge] = []
    if java_natives and so_meta is not None:
        bridges = build_bridges(java_natives)
        correlate_symbols(bridges, so_meta.exports)

    # ----- Step 7: manifest audit + PoC generation (Phase 3) -----
    audit_report: Optional[AndroidAuditReport] = None
    pocs: list[PoCArtifact] = []
    if app_meta is not None:
        audit_report = audit_manifest(app_meta)
        pocs = generate_pocs(app_meta, audit_report)

    return AndroidAnalysis(
        apk_meta=apk_meta,
        selected_abi=selected_abi,
        extracted_so_path=str(so_path) if so_path else None,
        so_meta=so_meta,
        app_meta=app_meta,
        java_natives=java_natives,
        bridges=bridges,
        warnings=warnings,
        audit_report=audit_report,
        pocs=pocs,
    )

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
    extract_all_native_libs,
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
from venomhook.code_audit import audit_code
from venomhook.jni_bridge import build_bridges, correlate_symbols
from venomhook.manifest_audit import audit_manifest
from venomhook.models import (
    AndroidAppMeta,
    AndroidAuditReport,
    CodeAuditReport,
    JavaNativeMethod,
    JniBridge,
    PoCArtifact,
)
from venomhook.native_strings import NativeStringHints, categorize_strings
from venomhook.poc_generator import generate_code_pocs, generate_pocs


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
    # Phase 7 — code-level static audit findings over jadx Java sources.
    # None when jadx was skipped or didn't produce a sources directory.
    code_audit_report: Optional[CodeAuditReport] = None
    # Phase 7-3 — pentest-relevant strings harvested from the .so. None
    # when no native lib was analysed; otherwise present even with all-
    # empty buckets so the report shape stays stable.
    native_string_hints: Optional[NativeStringHints] = None
    # Phase 9-1 — additional .so libraries beyond the primary one. Populated
    # only when the caller passed analyze_all_libs=True (CLI: --apk-lib all).
    # The primary .so stays in ``so_meta`` / ``extracted_so_path`` so legacy
    # consumers keep working; ``additional_so_metas`` carries the rest in
    # the same order as ``additional_so_paths``. Empty for single-lib runs.
    additional_so_metas: list[BinaryMeta] = field(default_factory=list)
    additional_so_paths: list[str] = field(default_factory=list)

    @property
    def matched_bridges(self) -> list[JniBridge]:
        return [b for b in self.bridges if b.is_matched]

    @property
    def unmatched_bridges(self) -> list[JniBridge]:
        return [b for b in self.bridges if not b.is_matched]

    @property
    def all_so_metas(self) -> list[BinaryMeta]:
        """Primary + additional .so metadata in a single iterable.

        Convenience for HTML / PoC layers that should treat the bundle
        uniformly. Single-lib runs return ``[so_meta]`` (or ``[]`` when
        no native lib was analysed); multi-lib runs return the primary
        followed by ``additional_so_metas``.
        """
        out: list[BinaryMeta] = []
        if self.so_meta is not None:
            out.append(self.so_meta)
        out.extend(self.additional_so_metas)
        return out

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
        code_audit_data = data.get("code_audit_report")
        nsh_data = data.get("native_string_hints")
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
            code_audit_report=(
                CodeAuditReport.from_dict(code_audit_data)
                if code_audit_data else None
            ),
            native_string_hints=(
                NativeStringHints.from_dict(nsh_data)
                if nsh_data is not None else None
            ),
            additional_so_metas=[
                _BinaryMeta.from_dict(m)
                for m in data.get("additional_so_metas", [])
            ],
            additional_so_paths=list(data.get("additional_so_paths", [])),
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
            "code_audit_report": (
                self.code_audit_report.to_dict()
                if self.code_audit_report else None
            ),
            "native_string_hints": (
                self.native_string_hints.to_dict()
                if self.native_string_hints else None
            ),
            "additional_so_metas": [
                m.to_dict() for m in self.additional_so_metas
            ],
            "additional_so_paths": list(self.additional_so_paths),
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
    analyze_all_libs: bool = False,
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

    `analyze_all_libs=True` (CLI: ``--apk-lib all``) extracts every ``.so``
    under the selected ABI and runs lief on each. The first sorted .so still
    fills ``so_meta`` / ``extracted_so_path`` for legacy consumers; the rest
    populates ``additional_so_metas`` / ``additional_so_paths``. JNI bridge
    correlation then matches against the union of every analysed .so's
    exports, and ``native_string_hints`` is built from the merged string
    pool. ``lib_name`` is ignored when this flag is set (the primary is
    chosen by sort order, matching the single-lib default).

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
    additional_so_metas: list[BinaryMeta] = []
    additional_so_paths: list[str] = []

    if not apk_meta.abis:
        msg = f"APK lib/<abi>/ 하위에 네이티브 라이브러리가 없습니다: {apk}"
        if require_native:
            raise AndroidPipelineError(msg)
        warnings.append(f"{msg} — 네이티브 분석을 건너뜁니다")
    else:
        # ----- Step 2: ABI selection + .so extraction -----
        try:
            selected_abi = select_abi(apk_meta, abi)
        except ApkExtractError as e:
            msg = f"ABI 선택 실패: {e}"
            if require_native:
                raise AndroidPipelineError(msg) from e
            warnings.append(f"{msg} — 네이티브 분석을 건너뜁니다")

        if selected_abi is not None:
            so_dir = work / "lib"
            extracted_paths: list[Path] = []
            try:
                if analyze_all_libs:
                    extracted_paths = extract_all_native_libs(apk, selected_abi, so_dir)
                    so_path = extracted_paths[0] if extracted_paths else None
                else:
                    so_path = extract_native_lib(apk, selected_abi, lib_name, so_dir)
                    extracted_paths = [so_path] if so_path else []
            except ApkExtractError as e:
                msg = (
                    f".so 추출 실패 (abi={selected_abi}, "
                    f"lib={'all' if analyze_all_libs else lib_name}): {e}"
                )
                if require_native:
                    raise AndroidPipelineError(msg) from e
                warnings.append(f"{msg} — 네이티브 분석을 건너뜁니다")

            # 본 파이프라인은 기본적으로 .so 1개만 분석합니다 (메모리/시간 상한
            # 유지). --apk-lib all로 호출되면 같은 ABI 안의 모든 .so를 추출하고
            # JNI 브리지 매칭도 union exports에 대해 수행하므로 이 경고는 띄우지
            # 않습니다. 단일 .so 모드에서 sibling이 있을 때만 운영자에게 다시
            # 실행하도록 안내.
            siblings = apk_meta.native_libs.get(selected_abi, [])
            if (
                not analyze_all_libs
                and so_path is not None
                and len(siblings) > 1
            ):
                analyzed = so_path.name
                others = [s for s in siblings if s != analyzed]
                warnings.append(
                    f"'{analyzed}'만 분석되었습니다. APK는 '{selected_abi}' "
                    f"ABI에 {len(siblings)}개의 .so를 포함하고 있습니다 "
                    f"({', '.join(others)}). 빠진 .so를 분석하려면 --apk-lib "
                    "<이름> 또는 --apk-lib all로 재실행하세요. 그쪽 .so를 "
                    "로드하는 클래스의 JNI 브리지는 본 보고서에서 "
                    "'unmatched'로 표시됩니다."
                )

        # ----- Step 3: BinaryMeta of the .so (REQUIRED for JNI correlation) -----
        if so_path is not None:
            try:
                so_meta = extract_binary_meta(so_path)
            except BinaryMetaError as e:
                msg = f"{so_path}에 대한 binary_meta 추출 실패: {e}"
                if require_native:
                    raise AndroidPipelineError(msg) from e
                warnings.append(f"{msg} — 네이티브 분석을 건너뜁니다")

            if analyze_all_libs and so_meta is not None:
                # Run lief on each remaining .so. A failure on a non-primary
                # library is recorded as a warning and the rest of the
                # analysis continues — losing one library's exports degrades
                # JNI correlation but does not invalidate the report.
                for extra_path in extracted_paths[1:]:
                    try:
                        extra_meta = extract_binary_meta(extra_path)
                    except BinaryMetaError as e:
                        warnings.append(
                            f"{extra_path}에 대한 binary_meta 추출 실패 "
                            f"(계속 진행): {e}"
                        )
                        continue
                    additional_so_metas.append(extra_meta)
                    additional_so_paths.append(str(extra_path))

    # ----- Step 4: AndroidManifest decode (optional) -----
    app_meta: Optional[AndroidAppMeta] = None
    if use_apktool:
        apktool_out = work / "apktool"
        try:
            _, app_meta = decode_apk(apk, apktool_out, config=apktool_config)
        except ApktoolNotFoundError as e:
            msg = f"apktool을 사용할 수 없습니다 — manifest 디코드를 건너뜁니다: {e}"
            if fail_on_missing_tools:
                raise AndroidPipelineError(msg) from e
            warnings.append(msg)
        except ApkDecoderError as e:
            warnings.append(f"apktool 디코드 실패 (계속 진행): {e}")

    # ----- Step 5: jadx decompile + native method extract (optional) -----
    java_natives: list[JavaNativeMethod] = []
    jadx_sources_dir: Optional[Path] = None
    if use_jadx:
        jadx_out = work / "jadx"
        try:
            jadx_result, java_natives = decompile_apk(
                apk, jadx_out, config=jadx_config
            )
            # jadx writes Java sources under <output_dir>/sources by default;
            # remember the path for Step 8 (code audit). Tolerate alternate
            # layouts by falling back to the output_dir itself if sources/
            # is missing.
            sources_candidate = Path(jadx_result.output_dir) / "sources"
            jadx_sources_dir = (
                sources_candidate if sources_candidate.is_dir()
                else Path(jadx_result.output_dir)
            )
        except JadxNotFoundError as e:
            msg = f"jadx를 사용할 수 없습니다 — Java 디컴파일을 건너뜁니다: {e}"
            if fail_on_missing_tools:
                raise AndroidPipelineError(msg) from e
            warnings.append(msg)
        except JadxError as e:
            warnings.append(f"jadx 디컴파일 실패 (계속 진행): {e}")

    # ----- Step 6: JNI bridge construction + correlation -----
    bridges: list[JniBridge] = []
    if java_natives and so_meta is not None:
        bridges = build_bridges(java_natives)
        union_exports: list[str] = list(so_meta.exports)
        for extra in additional_so_metas:
            union_exports.extend(extra.exports)
        correlate_symbols(bridges, union_exports)

    # ----- Step 7: manifest audit + PoC generation (Phase 3) -----
    audit_report: Optional[AndroidAuditReport] = None
    pocs: list[PoCArtifact] = []
    if app_meta is not None:
        audit_report = audit_manifest(app_meta)
        pocs = generate_pocs(app_meta, audit_report)

    # ----- Step 8: code-level static audit over jadx sources (Phase 7-1/2/4) -----
    # Runs only when jadx produced sources. Pure text-pattern scan; failure
    # to read individual files is tolerated inside audit_code itself. Code
    # PoCs are appended to the same `pocs` bundle so HTML / export layers
    # don't need to special-case them.
    code_audit_report: Optional[CodeAuditReport] = None
    if jadx_sources_dir is not None:
        try:
            code_audit_report = audit_code(jadx_sources_dir, app_meta)
            if code_audit_report and app_meta is not None:
                pocs.extend(generate_code_pocs(app_meta, code_audit_report))
        except OSError as e:
            warnings.append(f"코드 감사 실패 (계속 진행): {e}")

    # ----- Step 9: categorize native-library strings (Phase 7-3) -----
    # so_meta.strings is harvested by binary_meta from .rodata-style sections.
    # Categorizing here turns raw bytes into pentest-actionable hints
    # (URLs the .so calls home to, sensitive paths, embedded shell commands,
    # crypto algorithm names, secret-shaped tokens). None when no .so was
    # analyzed.
    native_string_hints: Optional[NativeStringHints] = None
    if so_meta is not None:
        merged_strings: list[str] = list(so_meta.strings)
        for extra in additional_so_metas:
            merged_strings.extend(extra.strings)
        native_string_hints = categorize_strings(merged_strings)

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
        code_audit_report=code_audit_report,
        native_string_hints=native_string_hints,
        additional_so_metas=additional_so_metas,
        additional_so_paths=additional_so_paths,
    )

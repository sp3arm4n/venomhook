"""apktool wrapper — decode AndroidManifest, smali, resources from APK.

Complementary to apk_extractor (PR #3) which uses stdlib zipfile to extract
native libraries. This module adds the apktool layer that decodes the *binary*
AndroidManifest.xml into readable XML and (optionally) emits smali for
downstream analysis.

  apk_extractor : APK -> .so  (zipfile, no external dep)
  apk_decoder   : APK -> AndroidManifest.xml + smali/  (apktool subprocess)

Together they form Phase 2's APK input layer. The Android pipeline (PR #9)
will run both, then correlate manifest metadata with native libs and the
JNI bridge findings (PR #6/#7) to score endpoints.

apktool is treated as an *optional* dependency. When unavailable the public
functions raise `ApktoolNotFoundError` with installation guidance — the
higher-level pipeline graceful-falls-back to native-only analysis.

The manifest parser uses Python's stdlib ElementTree. Real APKs ship a
*binary* AndroidManifest.xml that ElementTree can't read directly; apktool
decodes it to text first. Direct binary-XML parsing is out of scope for
this module (it would duplicate apktool's job).

Pure-Python; depends only on models.{AndroidAppMeta, AndroidComponent}.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional
from xml.etree import ElementTree as ET

from venomhook.models import AndroidAppMeta, AndroidComponent


__all__ = [
    "ApkDecoderError",
    "ApktoolNotFoundError",
    "ApktoolRunError",
    "ManifestParseError",
    "ApktoolConfig",
    "ApktoolResult",
    "find_apktool",
    "run_apktool_decode",
    "parse_android_manifest",
    "decode_apk",
    "APKTOOL_ENV_VAR",
    "ANDROID_NS",
]


APKTOOL_ENV_VAR = "VENOMHOOK_APKTOOL"
_APKTOOL_CANDIDATES = ("apktool",)
ANDROID_NS = "{http://schemas.android.com/apk/res/android}"


# ---------- exceptions ----------


class ApkDecoderError(RuntimeError):
    """Base class for apk_decoder failures."""


class ApktoolNotFoundError(ApkDecoderError):
    """apktool could not be located on PATH or via env var."""


class ApktoolRunError(ApkDecoderError):
    """apktool invocation returned a non-zero exit code, timed out, or could not start."""


class ManifestParseError(ApkDecoderError):
    """AndroidManifest.xml could not be read or parsed (e.g., still binary, malformed)."""


# ---------- config / result ----------


@dataclass
class ApktoolConfig:
    """Tunable apktool invocation parameters.

    Defaults err on the side of producing complete output: smali is included
    (for future RegisterNatives correlation) and resources are decoded (for
    permission/string surface). Toggle off via `no_src` / `no_res` to speed up
    when only the manifest is needed.
    """

    apktool_path: Optional[str] = None  # explicit binary path; None = auto-detect
    no_src: bool = False                # --no-src (skip smali decompile)
    no_res: bool = False                # --no-res (skip resource decode)
    force: bool = True                  # --force (overwrite existing output)
    timeout_sec: int = 600
    extra_args: list[str] = field(default_factory=list)


@dataclass
class ApktoolResult:
    """Outcome of an apktool decode invocation."""

    apk_path: str
    output_dir: str
    returncode: int
    manifest_path: Optional[str] = None  # absolute path to decoded AndroidManifest.xml
    smali_present: bool = False          # any smali*/ subdir was emitted
    stdout_tail: str = ""
    stderr_tail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "apk_path": self.apk_path,
            "output_dir": self.output_dir,
            "returncode": self.returncode,
            "manifest_path": self.manifest_path,
            "smali_present": self.smali_present,
            "stdout_tail": self.stdout_tail,
            "stderr_tail": self.stderr_tail,
        }


# ---------- discovery ----------


def find_apktool(env_var: str = APKTOOL_ENV_VAR) -> str:
    """Locate the apktool binary (a wrapper script or the apktool.jar launcher).

    Resolution order:
      1. ``$VENOMHOOK_APKTOOL`` — must point to an executable file
      2. ``apktool`` on PATH

    Raises ``ApktoolNotFoundError`` if none resolve.
    """
    explicit = os.environ.get(env_var)
    if explicit:
        path = Path(explicit)
        if path.is_file() and os.access(explicit, os.X_OK):
            return explicit
        raise ApktoolNotFoundError(
            f"{env_var}={explicit!r} is set but does not point to an executable file"
        )
    for cand in _APKTOOL_CANDIDATES:
        found = shutil.which(cand)
        if found:
            return found
    raise ApktoolNotFoundError(
        "apktool not found. Install apktool (https://apktool.org) and "
        f"either add it to PATH or set {env_var}=/path/to/apktool."
    )


# ---------- subprocess invocation ----------


def run_apktool_decode(
    apk_path: str | Path,
    output_dir: str | Path,
    config: Optional[ApktoolConfig] = None,
) -> ApktoolResult:
    """Invoke ``apktool d`` on ``apk_path``, writing decoded contents to ``output_dir``.

    Creates ``output_dir`` if missing. Uses ``--force`` by default so a stale
    output dir doesn't make apktool error; callers managing their own clean-
    slate dirs can disable this via the config.

    Raises:
      - ``ApktoolNotFoundError`` if apktool is not on PATH/env
      - ``ApktoolRunError`` for missing input, timeout, or non-zero exit with
        no AndroidManifest.xml produced
    """
    cfg = config or ApktoolConfig()
    apk = Path(apk_path).resolve()
    out = Path(output_dir).resolve()

    if not apk.exists():
        raise ApktoolRunError(f"APK not found: {apk}")
    if not apk.is_file():
        raise ApktoolRunError(f"not a regular file: {apk}")
    out.mkdir(parents=True, exist_ok=True)

    binary = cfg.apktool_path or find_apktool()

    cmd: list[str] = [binary, "d"]
    if cfg.force:
        cmd.append("--force")
    if cfg.no_src:
        cmd.append("--no-src")
    if cfg.no_res:
        cmd.append("--no-res")
    cmd.extend(["-o", str(out)])
    cmd.extend(cfg.extra_args)
    cmd.append(str(apk))

    try:
        completed = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=cfg.timeout_sec,
        )
    except subprocess.TimeoutExpired as e:
        raise ApktoolRunError(
            f"apktool timed out after {cfg.timeout_sec}s on {apk}"
        ) from e
    except FileNotFoundError as e:
        raise ApktoolNotFoundError(
            f"could not exec apktool binary at {binary!r}: {e}"
        ) from e

    manifest = out / "AndroidManifest.xml"
    smali_present = any(out.glob("smali*"))
    stdout_tail = (completed.stdout or "")[-4096:]
    stderr_tail = (completed.stderr or "")[-4096:]

    # Treat success as: manifest produced, regardless of returncode (apktool
    # routinely warns/exits non-zero on tricky resources but still decodes
    # the manifest correctly).
    if not manifest.exists():
        tail = stderr_tail or stdout_tail
        raise ApktoolRunError(
            f"apktool failed (exit={completed.returncode}, no AndroidManifest.xml produced): {tail}"
        )

    return ApktoolResult(
        apk_path=str(apk),
        output_dir=str(out),
        returncode=completed.returncode,
        manifest_path=str(manifest),
        smali_present=smali_present,
        stdout_tail=stdout_tail,
        stderr_tail=stderr_tail,
    )


# ---------- manifest parsing ----------


def _safe_int(s: Optional[str]) -> Optional[int]:
    if s is None:
        return None
    try:
        return int(s)
    except (TypeError, ValueError):
        return None


def _resolve_class_name(name: Optional[str], package: str) -> Optional[str]:
    """Resolve a component class name relative to the application package.

    Android convention:
      - leading '.' is replaced with the package: ``.MainActivity`` -> ``com.app.MainActivity``
      - bare name (no '.') gets the package prepended: ``Foo`` -> ``com.app.Foo``
      - already-qualified names pass through unchanged
    """
    if not name:
        return None
    if name.startswith("."):
        return f"{package}{name}" if package else name[1:]
    if "." not in name:
        return f"{package}.{name}" if package else name
    return name


def _parse_component(elem: ET.Element, comp_type: str, package: str) -> AndroidComponent:
    name = _resolve_class_name(elem.attrib.get(f"{ANDROID_NS}name"), package) or ""
    exported_attr = elem.attrib.get(f"{ANDROID_NS}exported")
    exported = exported_attr == "true"
    permission = elem.attrib.get(f"{ANDROID_NS}permission")
    # grantUriPermissions is meaningful for providers; harmless on others
    # (manifest_audit only fires the rule when type == "provider").
    grant_uri = elem.attrib.get(f"{ANDROID_NS}grantUriPermissions") == "true"

    intent_actions: list[str] = []
    for ifilter in elem.findall("intent-filter"):
        for action in ifilter.findall("action"):
            action_name = action.attrib.get(f"{ANDROID_NS}name")
            if action_name:
                intent_actions.append(action_name)

    return AndroidComponent(
        type=comp_type,
        name=name,
        exported=exported,
        permission=permission,
        intent_actions=intent_actions,
        grant_uri_permissions=grant_uri,
    )


_COMPONENT_TAGS: tuple[tuple[str, str], ...] = (
    ("activity", "activity"),
    ("activity-alias", "activity"),
    ("service", "service"),
    ("receiver", "receiver"),
    ("provider", "provider"),
)


def parse_android_manifest(manifest_path: str | Path) -> AndroidAppMeta:
    """Parse a *decoded* (text) AndroidManifest.xml into AndroidAppMeta.

    Raises ``ManifestParseError`` if the file is missing, unreadable, still in
    binary AXML form (heuristic: starts with the 0x03000800 magic), or
    malformed XML.
    """
    p = Path(manifest_path)
    if not p.exists():
        raise ManifestParseError(f"manifest not found: {p}")

    try:
        raw = p.read_bytes()
    except OSError as e:
        raise ManifestParseError(f"could not read {p}: {e}") from e

    # Heuristic check for binary AXML — first 4 bytes are 0x03000800 little-endian
    if raw[:4] == b"\x03\x00\x08\x00":
        raise ManifestParseError(
            f"{p} is still binary AXML; run apktool first to decode it"
        )

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as e:
        raise ManifestParseError(f"{p} is not valid UTF-8: {e}") from e

    try:
        root = ET.fromstring(text)
    except ET.ParseError as e:
        raise ManifestParseError(f"failed to parse XML in {p}: {e}") from e

    if root.tag != "manifest":
        raise ManifestParseError(
            f"root element of {p} is <{root.tag}>, expected <manifest>"
        )

    package_name = root.attrib.get("package", "")

    permissions: list[str] = []
    for elem in root.findall("uses-permission"):
        perm = elem.attrib.get(f"{ANDROID_NS}name")
        if perm:
            permissions.append(perm)

    sdk_elem = root.find("uses-sdk")
    if sdk_elem is not None:
        min_sdk = _safe_int(sdk_elem.attrib.get(f"{ANDROID_NS}minSdkVersion"))
        target_sdk = _safe_int(sdk_elem.attrib.get(f"{ANDROID_NS}targetSdkVersion"))
    else:
        min_sdk = None
        target_sdk = None

    application_class: Optional[str] = None
    components: list[AndroidComponent] = []
    debuggable = False
    extract_native_libs: Optional[bool] = None
    uses_cleartext_traffic: Optional[bool] = None
    allow_backup: Optional[bool] = None
    network_security_config: Optional[str] = None

    app = root.find("application")
    if app is not None:
        application_class = _resolve_class_name(
            app.attrib.get(f"{ANDROID_NS}name"), package_name
        )
        debuggable = app.attrib.get(f"{ANDROID_NS}debuggable") == "true"
        ext_attr = app.attrib.get(f"{ANDROID_NS}extractNativeLibs")
        if ext_attr in ("true", "false"):
            extract_native_libs = ext_attr == "true"
        # PR #11 manifest_audit feeds — preserve the unset/true/false trichotomy
        # because Android's actual default depends on targetSdk.
        ct_attr = app.attrib.get(f"{ANDROID_NS}usesCleartextTraffic")
        if ct_attr in ("true", "false"):
            uses_cleartext_traffic = ct_attr == "true"
        ab_attr = app.attrib.get(f"{ANDROID_NS}allowBackup")
        if ab_attr in ("true", "false"):
            allow_backup = ab_attr == "true"
        nsc_attr = app.attrib.get(f"{ANDROID_NS}networkSecurityConfig")
        if nsc_attr:
            network_security_config = nsc_attr

        for tag, comp_type in _COMPONENT_TAGS:
            for elem in app.findall(tag):
                components.append(_parse_component(elem, comp_type, package_name))

    return AndroidAppMeta(
        package_name=package_name,
        application_class=application_class,
        permissions=permissions,
        components=components,
        min_sdk=min_sdk,
        target_sdk=target_sdk,
        debuggable=debuggable,
        extract_native_libs=extract_native_libs,
        uses_cleartext_traffic=uses_cleartext_traffic,
        allow_backup=allow_backup,
        network_security_config=network_security_config,
    )


# ---------- convenience ----------


def decode_apk(
    apk_path: str | Path,
    output_dir: str | Path,
    config: Optional[ApktoolConfig] = None,
) -> tuple[ApktoolResult, AndroidAppMeta]:
    """Convenience: run apktool, then parse the resulting manifest.

    Returns ``(apktool_result, android_app_meta)``. Propagates
    ``ApktoolNotFoundError`` / ``ApktoolRunError`` from the runner stage and
    ``ManifestParseError`` from the parser stage.
    """
    result = run_apktool_decode(apk_path, output_dir, config=config)
    if result.manifest_path is None:
        raise ManifestParseError(
            "apktool did not produce AndroidManifest.xml — cannot continue"
        )
    meta = parse_android_manifest(result.manifest_path)
    return result, meta

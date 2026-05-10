"""APK metadata inspection and native library (.so) extraction.

APKs are ZIP files; we use Python's stdlib `zipfile` to enumerate ABIs under
`lib/<abi>/` and extract a chosen `.so` for downstream Ghidra analysis.
This is the gateway for VenomHook's Tier 1 Android workflow:

    APK -> apk_extractor (this module) -> .so file
        -> Ghidra headless -> StaticMeta
        -> scoring (JNI 1st-class) -> HookSpec
        -> Frida JS

Manifest parsing (binary AndroidManifest.xml) and DEX/Java↔Native correlation
are deferred to Phase 2 (apktool/jadx integration). This module deliberately
sticks to the native-library extraction concern.
"""

from __future__ import annotations

import hashlib
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

__all__ = [
    "ApkMeta",
    "ApkExtractError",
    "extract_apk_meta",
    "select_abi",
    "extract_native_lib",
    "extract_all_native_libs",
    "ABI_PREFERENCE",
]


# Default preference when --abi auto: ARM64 first (modern devices), then 32-bit ARM,
# then x86_64 (emulators), then 32-bit x86.
ABI_PREFERENCE = ("arm64-v8a", "armeabi-v7a", "x86_64", "x86")

# Known Android ABIs (used to filter lib/ subdirectories that are not actual ABIs).
_KNOWN_ABIS = frozenset({"arm64-v8a", "armeabi-v7a", "armeabi", "x86", "x86_64", "mips", "mips64"})


class ApkExtractError(RuntimeError):
    """Raised for any APK extraction failure (not a ZIP, no native libs, missing ABI, etc.)."""


@dataclass
class ApkMeta:
    """Lightweight metadata for an APK file (no decompilation; native libs only)."""

    path: str  # absolute path to the APK file
    name: str  # basename
    hash: str  # "sha256:<hex>"
    abis: list[str] = field(default_factory=list)  # ABIs found in lib/, sorted
    native_libs: dict[str, list[str]] = field(default_factory=dict)  # abi -> sorted .so basenames

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ApkMeta":
        return cls(
            path=data["path"],
            name=data["name"],
            hash=data["hash"],
            abis=list(data.get("abis", [])),
            native_libs={
                abi: list(libs) for abi, libs in data.get("native_libs", {}).items()
            },
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "name": self.name,
            "hash": self.hash,
            "abis": list(self.abis),
            "native_libs": {abi: list(libs) for abi, libs in self.native_libs.items()},
        }


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fp:
        for chunk in iter(lambda: fp.read(8192), b""):
            h.update(chunk)
    return f"sha256:{h.hexdigest()}"


def extract_apk_meta(apk_path: str | Path) -> ApkMeta:
    """Inspect an APK without unpacking. Lists ABIs and .so files only.

    Raises ApkExtractError on missing file, non-ZIP input, or other parse errors.
    Returns an ApkMeta even when no native libraries are present (empty abis list).
    """
    p = Path(apk_path).resolve()
    if not p.exists():
        raise ApkExtractError(f"APK not found: {p}")
    if not p.is_file():
        raise ApkExtractError(f"not a regular file: {p}")
    if not zipfile.is_zipfile(p):
        raise ApkExtractError(f"not a valid APK (ZIP) archive: {p}")

    abis_set: set[str] = set()
    native_libs: dict[str, list[str]] = {}

    try:
        with zipfile.ZipFile(p, "r") as zf:
            for entry in zf.namelist():
                # Match lib/<abi>/<file>.so
                parts = entry.split("/")
                if len(parts) < 3:
                    continue
                if parts[0] != "lib":
                    continue
                abi = parts[1]
                lib_name = parts[-1]
                # Only consider .so files
                if not lib_name.endswith(".so"):
                    continue
                # Only known ABIs (filter out edge-case dirs like lib/_FAKE/)
                if abi not in _KNOWN_ABIS:
                    continue
                abis_set.add(abi)
                native_libs.setdefault(abi, []).append(lib_name)
    except zipfile.BadZipFile as e:
        raise ApkExtractError(f"corrupt APK archive: {p}: {e}") from e

    # Sort everything for deterministic output
    sorted_abis = sorted(abis_set)
    sorted_libs = {abi: sorted(libs) for abi, libs in native_libs.items()}

    return ApkMeta(
        path=str(p),
        name=p.name,
        hash=_sha256(p),
        abis=sorted_abis,
        native_libs=sorted_libs,
    )


def select_abi(meta: ApkMeta, requested: str = "auto") -> str:
    """Choose an ABI from those available in the APK.

    `requested` may be:
      - "auto": pick the first ABI from ABI_PREFERENCE that exists in the APK.
      - an explicit ABI like "arm64-v8a": returned as-is if present.

    Raises ApkExtractError if no native libs exist or the requested ABI is unavailable.
    """
    if not meta.abis:
        raise ApkExtractError(
            f"APK has no native libraries under lib/<abi>/: {meta.path}"
        )

    if requested == "auto":
        for candidate in ABI_PREFERENCE:
            if candidate in meta.abis:
                return candidate
        # All ABIs in the APK are exotic (e.g., mips); return the first sorted one.
        return meta.abis[0]

    if requested not in meta.abis:
        raise ApkExtractError(
            f"requested ABI {requested!r} not found in APK; available: {meta.abis}"
        )
    return requested


def extract_native_lib(
    apk_path: str | Path,
    abi: str,
    lib_name: Optional[str],
    dest_dir: str | Path,
) -> Path:
    """Extract a single .so from `lib/<abi>/` to `dest_dir`.

    If `lib_name` is None, picks the first .so available in that ABI
    (sorted lexicographically). Returns the path of the extracted file.

    Creates `dest_dir` if it doesn't exist. Overwrites any existing file
    of the same name silently (caller's responsibility to choose a clean dir
    when overwrite is undesired).
    """
    p = Path(apk_path).resolve()
    dest = Path(dest_dir).resolve()
    dest.mkdir(parents=True, exist_ok=True)

    if not zipfile.is_zipfile(p):
        raise ApkExtractError(f"not a valid APK (ZIP) archive: {p}")

    prefix = f"lib/{abi}/"
    chosen_entry: Optional[str] = None

    try:
        with zipfile.ZipFile(p, "r") as zf:
            candidates = sorted(
                e for e in zf.namelist() if e.startswith(prefix) and e.endswith(".so")
            )
            if not candidates:
                raise ApkExtractError(
                    f"no .so files in {prefix} (APK={p}); did you select the right ABI?"
                )

            if lib_name is None:
                chosen_entry = candidates[0]
            else:
                wanted = f"{prefix}{lib_name}"
                if wanted not in candidates:
                    raise ApkExtractError(
                        f"lib {lib_name!r} not found in {prefix}; available: "
                        f"{[c.split('/')[-1] for c in candidates]}"
                    )
                chosen_entry = wanted

            out_path = dest / Path(chosen_entry).name
            with zf.open(chosen_entry, "r") as src, out_path.open("wb") as out:
                # Copy in chunks to avoid loading large .so into memory
                while True:
                    chunk = src.read(64 * 1024)
                    if not chunk:
                        break
                    out.write(chunk)
    except zipfile.BadZipFile as e:
        raise ApkExtractError(f"corrupt APK archive: {p}: {e}") from e

    return out_path


def extract_all_native_libs(
    apk_path: str | Path,
    abi: str,
    dest_dir: str | Path,
) -> list[Path]:
    """Extract every ``.so`` under ``lib/<abi>/`` to ``dest_dir``.

    Returns the extracted paths sorted lexicographically (stable across
    runs). Used by the multi-.so pipeline path (``--apk-lib all``) when
    operators want JNI bridge correlation against every native library
    the APK ships, not just the first one.

    Same overwrite semantics as ``extract_native_lib``: existing files
    of the same name are silently replaced. The caller is expected to
    pass a clean directory when overwrite is undesired.

    Raises ApkExtractError when no ``.so`` files exist for the ABI or
    the archive itself is corrupt.
    """
    p = Path(apk_path).resolve()
    dest = Path(dest_dir).resolve()
    dest.mkdir(parents=True, exist_ok=True)

    if not zipfile.is_zipfile(p):
        raise ApkExtractError(f"not a valid APK (ZIP) archive: {p}")

    prefix = f"lib/{abi}/"
    out_paths: list[Path] = []
    try:
        with zipfile.ZipFile(p, "r") as zf:
            candidates = sorted(
                e for e in zf.namelist() if e.startswith(prefix) and e.endswith(".so")
            )
            if not candidates:
                raise ApkExtractError(
                    f"no .so files in {prefix} (APK={p}); did you select the right ABI?"
                )
            for entry in candidates:
                out_path = dest / Path(entry).name
                with zf.open(entry, "r") as src, out_path.open("wb") as out:
                    while True:
                        chunk = src.read(64 * 1024)
                        if not chunk:
                            break
                        out.write(chunk)
                out_paths.append(out_path)
    except zipfile.BadZipFile as e:
        raise ApkExtractError(f"corrupt APK archive: {p}: {e}") from e

    return out_paths

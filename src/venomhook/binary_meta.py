"""Binary-format-agnostic metadata extractor (PE / ELF / Mach-O) via lief.

Complements Ghidra's function-level analysis with module-level metadata
(format, arch, OS hint, image base, ASLR/PIE, sections, imports). Used as
the single entry point regardless of OS — the unified output lets downstream
consumers (scoring, HookSpec builder, signature DB) treat all formats uniformly.

This module is intentionally self-contained and does not import any other
venomhook modules, so it can be exercised in isolation when lief is the only
available dependency.

Requires the `static` extra (lief). When lief is not installed, the public
functions raise ``BinaryMetaError`` with a clear message rather than failing
at import time.
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

try:
    import lief  # type: ignore
except ImportError:  # pragma: no cover - exercised only when extra missing
    lief = None  # type: ignore


__all__ = [
    "BinaryMeta",
    "BinaryMetaError",
    "SectionMeta",
    "extract_binary_meta",
]


class BinaryMetaError(RuntimeError):
    """Raised when binary metadata cannot be extracted (missing dep, parse failure, unknown format)."""


@dataclass
class SectionMeta:
    name: str
    virtual_address: int
    virtual_size: int
    executable: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "virtual_address": hex(self.virtual_address),
            "virtual_size": self.virtual_size,
            "executable": self.executable,
        }


@dataclass
class BinaryMeta:
    """Module-level binary metadata, format-agnostic."""

    name: str  # basename of the file
    path: str  # absolute path used for extraction
    hash: str  # "sha256:<hex>"
    format: str  # "PE" | "ELF" | "MACHO"
    arch: str  # "x86" | "x64" | "arm" | "arm64" | "unknown"
    os_hint: str  # "windows" | "linux" | "android" | "macos" | "ios" | "unknown"
    image_base: int
    aslr: bool  # PE: DYNAMIC_BASE; ELF/Mach-O: PIE
    sections: list[SectionMeta] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)  # flat function symbol names (imported)
    exports: list[str] = field(default_factory=list)  # flat function symbol names (exported)
    libraries: list[str] = field(default_factory=list)  # imported DLL/.so names

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "path": self.path,
            "hash": self.hash,
            "format": self.format,
            "arch": self.arch,
            "os_hint": self.os_hint,
            "image_base": hex(self.image_base),
            "aslr": self.aslr,
            "sections": [s.to_dict() for s in self.sections],
            "imports": list(self.imports),
            "exports": list(self.exports),
            "libraries": list(self.libraries),
        }


# ---------- arch / OS detection helpers ----------


_PE_MACHINE_TO_ARCH = {
    "AMD64": "x64",
    "I386": "x86",
    "ARM64": "arm64",
    "ARMNT": "arm",
    "ARM": "arm",
    "IA64": "x64",
}

_ELF_MACHINE_TO_ARCH = {
    "X86_64": "x64",
    "AMD64": "x64",
    "I386": "x86",
    "AARCH64": "arm64",
    "ARM": "arm",
}

_MACHO_CPU_TO_ARCH = {
    "x86_64": "x64",
    "X86_64": "x64",
    "x86": "x86",
    "X86": "x86",
    "ARM64": "arm64",
    "ARM": "arm",
}


def _pe_arch(b) -> str:
    try:
        machine = b.header.machine.name  # e.g., "AMD64"
    except Exception:
        return "unknown"
    return _PE_MACHINE_TO_ARCH.get(machine, "unknown")


def _elf_arch(b) -> str:
    try:
        machine = b.header.machine_type.name  # e.g., "X86_64", "AARCH64"
    except Exception:
        return "unknown"
    return _ELF_MACHINE_TO_ARCH.get(machine, "unknown")


def _macho_arch(b) -> str:
    try:
        cpu = b.header.cpu_type.name  # e.g., "x86_64", "ARM64"
    except Exception:
        return "unknown"
    return _MACHO_CPU_TO_ARCH.get(cpu, "unknown")


def _detect_os_hint(format_name: str, imports: list[str], arch: str) -> str:
    """Best-effort OS hint from format + imports.

    PE -> windows, Mach-O -> macos (could be ios; we don't differentiate yet).
    ELF is ambiguous (linux vs android) — use Android-specific imports as evidence.
    """
    if format_name == "PE":
        return "windows"
    if format_name == "MACHO":
        return "macos"
    if format_name == "ELF":
        # Heuristic: Android Bionic exposes specific symbols rare in glibc binaries.
        android_markers = {
            "__android_log_print",
            "__android_log_write",
            "JNI_OnLoad",
            "AAsset_open",
            "AAssetManager_open",
        }
        if any(sym in android_markers for sym in imports):
            return "android"
        return "linux"
    return "unknown"


# ---------- main extraction ----------


def _section_executable(section, format_name: str) -> bool:
    """Best-effort 'is executable' across formats."""
    # PE: characteristics IMAGE_SCN_MEM_EXECUTE = 0x20000000
    if format_name == "PE":
        try:
            return bool(int(section.characteristics) & 0x20000000)
        except Exception:
            return False
    # ELF: SHF_EXECINSTR = 0x4
    if format_name == "ELF":
        try:
            return bool(int(section.flags) & 0x4)
        except Exception:
            return False
    # Mach-O: section.flags has S_ATTR_PURE_INSTRUCTIONS (0x80000000) or sectname like __text
    if format_name == "MACHO":
        try:
            if str(section.name).lower() in {"__text", ".text"}:
                return True
            return bool(int(section.flags) & 0x80000000)
        except Exception:
            return False
    return False


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fp:
        for chunk in iter(lambda: fp.read(8192), b""):
            h.update(chunk)
    return f"sha256:{h.hexdigest()}"


def extract_binary_meta(path: str | Path) -> BinaryMeta:
    """Parse a binary file with lief and return unified BinaryMeta.

    Raises BinaryMetaError if lief is missing, the file cannot be read,
    or the format is unsupported.
    """
    if lief is None:
        raise BinaryMetaError(
            "lief is required for binary metadata extraction. "
            "Install via `pip install lief` or `pip install -e '.[static]'`."
        )

    p = Path(path).resolve()
    if not p.exists():
        raise BinaryMetaError(f"binary not found: {p}")
    if not p.is_file():
        raise BinaryMetaError(f"not a regular file: {p}")

    try:
        binary = lief.parse(str(p))
    except Exception as e:
        raise BinaryMetaError(f"lief failed to parse {p}: {e}") from e

    if binary is None:
        raise BinaryMetaError(f"lief returned None for {p} — unsupported format?")

    # Format detection (FORMATS enum: PE / ELF / MACHO)
    try:
        format_name = binary.format.name  # "PE" / "ELF" / "MACHO"
    except Exception:
        raise BinaryMetaError(f"could not determine format for {p}") from None

    # Arch
    if format_name == "PE":
        arch = _pe_arch(binary)
    elif format_name == "ELF":
        arch = _elf_arch(binary)
    elif format_name == "MACHO":
        arch = _macho_arch(binary)
    else:
        arch = "unknown"

    # Image base (lief unifies on b.imagebase)
    try:
        image_base = int(binary.imagebase)
    except Exception:
        image_base = 0

    # ASLR / PIE (unified via b.is_pie — for PE this corresponds to DYNAMIC_BASE)
    try:
        aslr = bool(binary.is_pie)
    except Exception:
        aslr = False

    # Sections
    sections: list[SectionMeta] = []
    try:
        for sec in binary.sections:
            try:
                sec_name = str(sec.name)
            except Exception:
                sec_name = "<unknown>"
            try:
                vaddr = int(getattr(sec, "virtual_address", 0))
            except Exception:
                vaddr = 0
            try:
                vsize = int(getattr(sec, "virtual_size", 0) or getattr(sec, "size", 0))
            except Exception:
                vsize = 0
            sections.append(
                SectionMeta(
                    name=sec_name,
                    virtual_address=vaddr,
                    virtual_size=vsize,
                    executable=_section_executable(sec, format_name),
                )
            )
    except Exception:
        # Sections are advisory; don't fail the whole extraction.
        sections = []

    # Imported function symbols (flat)
    imports: list[str] = []
    try:
        for sym in binary.imported_functions:
            # lief's imported_functions yields Symbol-like objects; str() varies by format.
            # Prefer .name if available.
            name = getattr(sym, "name", None)
            if name:
                imports.append(str(name))
            else:
                imports.append(str(sym))
    except Exception:
        imports = []
    # Deduplicate while preserving order
    seen: set[str] = set()
    imports = [s for s in imports if not (s in seen or seen.add(s))]

    # Exported function symbols (flat). Critical for Android JNI correlation
    # — the JVM looks up `Java_<class>_<method>` in the .so's export table.
    exports: list[str] = []
    try:
        for sym in binary.exported_functions:
            name = getattr(sym, "name", None)
            if name:
                exports.append(str(name))
            else:
                exports.append(str(sym))
    except Exception:
        exports = []
    seen_e: set[str] = set()
    exports = [s for s in exports if not (s in seen_e or seen_e.add(s))]

    # Libraries (DLL / .so / .dylib names). PE returns strings; Mach-O returns
    # DylibCommand objects with a .name attribute; ELF returns strings.
    libraries: list[str] = []
    try:
        for lib in binary.libraries:
            name = getattr(lib, "name", None)
            libraries.append(str(name) if name is not None else str(lib))
    except Exception:
        libraries = []

    os_hint = _detect_os_hint(format_name, imports, arch)

    return BinaryMeta(
        name=p.name,
        path=str(p),
        hash=_sha256(p),
        format=format_name,
        arch=arch,
        os_hint=os_hint,
        image_base=image_base,
        aslr=aslr,
        sections=sections,
        imports=imports,
        exports=exports,
        libraries=libraries,
    )

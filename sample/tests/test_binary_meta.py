"""Tests for binary_meta — lief-based PE/ELF/Mach-O metadata extractor.

Skipped (not failed) when lief or sample binary is missing, since:
- lief is an optional dep (`static` extra)
- sample/putty.exe is gitignored convention-dependent

Also covers the BinaryInfo.os field round-trip (PR #2 model extension).
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

try:
    import lief  # type: ignore  # noqa: F401
    _HAS_LIEF = True
except ImportError:
    _HAS_LIEF = False

from venomhook.binary_meta import (
    BinaryMeta,
    BinaryMetaError,
    SectionMeta,
    extract_binary_meta,
)
from venomhook.models import BinaryInfo

PUTTY_EXE = ROOT / "putty.exe"
SYS_LS = Path("/bin/ls")


@unittest.skipUnless(_HAS_LIEF, "lief not installed; binary metadata tests skipped")
class BinaryMetaPETests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not PUTTY_EXE.exists():
            raise unittest.SkipTest(f"sample binary not present: {PUTTY_EXE}")
        cls.meta = extract_binary_meta(PUTTY_EXE)

    def test_format_and_arch(self) -> None:
        self.assertEqual(self.meta.format, "PE")
        self.assertEqual(self.meta.arch, "x64")
        self.assertEqual(self.meta.os_hint, "windows")

    def test_image_base_is_pe_typical(self) -> None:
        # x64 PE images typically use 0x140000000
        self.assertEqual(self.meta.image_base, 0x140000000)

    def test_aslr_detected(self) -> None:
        self.assertTrue(self.meta.aslr)

    def test_has_text_section(self) -> None:
        names = {sec.name for sec in self.meta.sections}
        self.assertIn(".text", names)
        text = next(sec for sec in self.meta.sections if sec.name == ".text")
        self.assertTrue(text.executable)
        self.assertGreater(text.virtual_size, 0)

    def test_imports_have_known_winapi(self) -> None:
        # putty links GDI32, USER32, KERNEL32 → known function names should appear
        self.assertIn("BitBlt", self.meta.imports)  # GDI32
        # Imports should be deduplicated
        self.assertEqual(len(self.meta.imports), len(set(self.meta.imports)))

    def test_libraries_are_dll_strings(self) -> None:
        self.assertIn("KERNEL32.dll", self.meta.libraries)
        self.assertTrue(all(isinstance(lib, str) for lib in self.meta.libraries))

    def test_hash_is_sha256_prefixed(self) -> None:
        self.assertTrue(self.meta.hash.startswith("sha256:"))
        # 64 hex chars after the prefix
        self.assertEqual(len(self.meta.hash), len("sha256:") + 64)

    def test_to_dict_round_trip_shape(self) -> None:
        d = self.meta.to_dict()
        self.assertEqual(d["format"], "PE")
        self.assertEqual(d["arch"], "x64")
        # image_base serialized as hex string
        self.assertTrue(d["image_base"].startswith("0x"))


@unittest.skipUnless(_HAS_LIEF, "lief not installed")
@unittest.skipUnless(SYS_LS.exists(), "/bin/ls not present (non-macOS env?)")
class BinaryMetaMachoTests(unittest.TestCase):
    """Exercises Mach-O code path on macOS via /bin/ls."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.meta = extract_binary_meta(SYS_LS)

    def test_format_arch_os(self) -> None:
        self.assertEqual(self.meta.format, "MACHO")
        self.assertIn(self.meta.arch, {"x64", "arm64"})  # depends on Mac CPU
        self.assertEqual(self.meta.os_hint, "macos")

    def test_libraries_resolved_to_dylib_paths(self) -> None:
        # Mach-O libraries come back as DylibCommand objects; we must extract .name
        self.assertTrue(any("libSystem" in lib for lib in self.meta.libraries))
        # Must NOT contain the LoadCommand debug repr
        self.assertFalse(any("Command: LOAD_DYLIB" in lib for lib in self.meta.libraries))

    def test_pie_detected(self) -> None:
        self.assertTrue(self.meta.aslr)


@unittest.skipUnless(_HAS_LIEF, "lief not installed")
class BinaryMetaErrorTests(unittest.TestCase):
    def test_missing_file_raises(self) -> None:
        with self.assertRaises(BinaryMetaError):
            extract_binary_meta("/nonexistent/path/foo.exe")


class BinaryInfoOsFieldTests(unittest.TestCase):
    """Backward-compat for BinaryInfo: legacy JSON parses, os round-trips, None is omitted."""

    def test_legacy_json_without_os_parses(self) -> None:
        b = BinaryInfo.from_dict(
            {"name": "sample.exe", "hash": "sha256:abc", "arch": "x64", "image_base": "0x140000000"}
        )
        self.assertIsNone(b.os)

    def test_to_dict_omits_os_when_none(self) -> None:
        b = BinaryInfo(name="sample.exe")
        d = b.to_dict()
        self.assertNotIn("os", d)

    def test_to_dict_includes_os_when_set(self) -> None:
        b = BinaryInfo(name="libfoo.so", arch="arm64", os="android")
        d = b.to_dict()
        self.assertEqual(d["os"], "android")

    def test_round_trip_with_os(self) -> None:
        original = BinaryInfo(name="libfoo.so", arch="arm64", os="android")
        d = original.to_dict()
        restored = BinaryInfo.from_dict(d)
        self.assertEqual(restored.os, "android")
        self.assertEqual(restored.arch, "arm64")


if __name__ == "__main__":
    unittest.main()

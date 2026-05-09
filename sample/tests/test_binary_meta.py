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
    _extract_strings_from_bytes,
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


class BinaryMetaRoundtripTests(unittest.TestCase):
    """from_dict / to_dict roundtrip for BinaryMeta and SectionMeta.

    No lief dependency — operates on synthetic dicts only. Required for
    Phase 4 analysis cache: an AndroidAnalysis stored to JSON must
    rebuild into an equivalent object.
    """

    def _bm(self) -> BinaryMeta:
        return BinaryMeta(
            name="libfoo.so", path="/abs/lib/libfoo.so",
            hash="sha256:deadbeef", format="ELF", arch="arm64",
            os_hint="android", image_base=0x1000, aslr=True,
            sections=[
                SectionMeta(name=".text", virtual_address=0x1000,
                            virtual_size=0x800, executable=True),
                SectionMeta(name=".rodata", virtual_address=0x1800,
                            virtual_size=0x200, executable=False),
            ],
            imports=["JNI_OnLoad", "free"],
            exports=["Java_com_x_A_native"],
            libraries=["libc.so", "libdl.so"],
        )

    def test_section_round_trip(self) -> None:
        s = SectionMeta(name=".text", virtual_address=0x4000,
                        virtual_size=128, executable=True)
        restored = SectionMeta.from_dict(s.to_dict())
        self.assertEqual(restored, s)

    def test_section_accepts_decimal_string(self) -> None:
        # Forward compat: accept plain decimal strings as well as 0x hex.
        s = SectionMeta.from_dict({
            "name": ".data", "virtual_address": "8192",
            "virtual_size": 64, "executable": False,
        })
        self.assertEqual(s.virtual_address, 8192)

    def test_binary_round_trip(self) -> None:
        original = self._bm()
        restored = BinaryMeta.from_dict(original.to_dict())
        self.assertEqual(restored, original)
        self.assertEqual(restored.image_base, 0x1000)
        self.assertEqual(len(restored.sections), 2)
        self.assertTrue(restored.sections[0].executable)

    def test_binary_image_base_accepts_int(self) -> None:
        d = self._bm().to_dict()
        d["image_base"] = 0x4000   # already an int — must still parse
        restored = BinaryMeta.from_dict(d)
        self.assertEqual(restored.image_base, 0x4000)

    def test_binary_minimal_dict(self) -> None:
        # Optional sections/imports/exports/libraries default to empty.
        restored = BinaryMeta.from_dict({
            "name": "x.so", "path": "/x.so", "hash": "sha256:00",
            "format": "ELF", "arch": "arm64", "os_hint": "android",
            "image_base": "0x0", "aslr": False,
        })
        self.assertEqual(restored.sections, [])
        self.assertEqual(restored.imports, [])


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


# ---------- Phase 7-3 string extraction (no lief required) ----------


class ExtractStringsFromBytesTests(unittest.TestCase):
    def test_finds_runs_separated_by_nul(self) -> None:
        data = b"hello\x00world\x00\x01garbage\x02ok\x00"
        out = _extract_strings_from_bytes(data, min_len=4)
        self.assertIn("hello", out)
        self.assertIn("world", out)
        self.assertIn("garbage", out)
        # "ok" is too short for min_len=4
        self.assertNotIn("ok", out)

    def test_min_len_filters_short_runs(self) -> None:
        data = b"abc\x00abcd\x00abcde\x00"
        out = _extract_strings_from_bytes(data, min_len=5)
        self.assertEqual(out, ["abcde"])

    def test_max_len_truncates_long_runs(self) -> None:
        # A run longer than max_len is split, not skipped
        data = ("X" * 600).encode() + b"\x00"
        out = _extract_strings_from_bytes(data, min_len=4, max_len=256)
        # Two chunks: 256 + 256 + 88 (above min_len 4)
        self.assertEqual(len(out), 3)
        self.assertEqual(len(out[0]), 256)

    def test_non_ascii_is_a_separator(self) -> None:
        # Bytes 0x80+ act as terminators (we only keep printable ASCII).
        data = b"hello\xc3\xa9world"
        out = _extract_strings_from_bytes(data, min_len=4)
        self.assertIn("hello", out)
        self.assertIn("world", out)

    def test_empty_input(self) -> None:
        self.assertEqual(_extract_strings_from_bytes(b""), [])


@unittest.skipUnless(_HAS_LIEF, "lief not installed")
@unittest.skipUnless(SYS_LS.exists(), "/bin/ls not present")
class BinaryMetaStringsExtractionTests(unittest.TestCase):
    """Verify .strings populates from a real binary's read-only sections."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.meta = extract_binary_meta(SYS_LS)

    def test_strings_field_populated(self) -> None:
        self.assertIsInstance(self.meta.strings, list)
        # /bin/ls always has identifiable strings (e.g. usage messages,
        # error labels). Even on minimal builds we expect a few hundred.
        self.assertGreater(len(self.meta.strings), 50)

    def test_strings_are_unique_and_sorted(self) -> None:
        # Implementation guarantee: dedupe + sort.
        self.assertEqual(self.meta.strings, sorted(set(self.meta.strings)))

    def test_strings_round_trip_via_to_dict(self) -> None:
        d = self.meta.to_dict()
        self.assertIn("strings", d)
        restored = BinaryMeta.from_dict(d)
        self.assertEqual(restored.strings, self.meta.strings)


class BinaryMetaStringsRoundtripTests(unittest.TestCase):
    """Strings field round-trips even without lief."""

    def test_strings_preserved(self) -> None:
        bm = BinaryMeta(
            name="x.so", path="/x.so", hash="sha256:0", format="ELF",
            arch="arm64", os_hint="android", image_base=0, aslr=True,
            strings=["alpha", "beta", "gamma"],
        )
        restored = BinaryMeta.from_dict(bm.to_dict())
        self.assertEqual(restored.strings, ["alpha", "beta", "gamma"])

    def test_strings_default_empty_list(self) -> None:
        bm = BinaryMeta.from_dict({
            "name": "x.so", "path": "/x.so", "hash": "sha256:0",
            "format": "ELF", "arch": "arm64", "os_hint": "android",
            "image_base": "0x0", "aslr": True,
        })
        self.assertEqual(bm.strings, [])


if __name__ == "__main__":
    unittest.main()

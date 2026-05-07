"""Tests for apk_extractor — APK ZIP inspection and native library extraction.

Synthetic APK fixtures (created in setUp via zipfile) avoid any binary blob
dependencies. This validates the extractor's ZIP/ABI/lib logic in isolation;
real APK end-to-end testing is operational concern (and the .so payload need
not be a valid ELF for the extractor's correctness).
"""

from __future__ import annotations

import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from venomhook.apk_extractor import (
    ABI_PREFERENCE,
    ApkExtractError,
    ApkMeta,
    extract_apk_meta,
    extract_native_lib,
    select_abi,
)


def _make_apk(
    tmp: Path,
    libs_by_abi: dict[str, list[str]],
    extra_entries: dict[str, bytes] | None = None,
    name: str = "synthetic.apk",
) -> Path:
    """Create a tiny APK-like ZIP for testing."""
    apk_path = tmp / name
    with zipfile.ZipFile(apk_path, "w", zipfile.ZIP_DEFLATED) as zf:
        # Minimal manifest placeholder so the zip looks more APK-like
        zf.writestr("AndroidManifest.xml", b"\x00\x00\x00\x00")
        for abi, libs in libs_by_abi.items():
            for lib in libs:
                zf.writestr(f"lib/{abi}/{lib}", b"\x7fELF" + b"\x00" * 60 + lib.encode())
        for entry, content in (extra_entries or {}).items():
            zf.writestr(entry, content)
    return apk_path


class ExtractApkMetaTests(unittest.TestCase):
    def test_enumerates_multi_abi_apk(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            apk = _make_apk(
                Path(tmp),
                {
                    "arm64-v8a": ["libfoo.so", "libbar.so"],
                    "armeabi-v7a": ["libfoo.so"],
                    "x86_64": ["libfoo.so"],
                },
            )
            meta = extract_apk_meta(apk)
            self.assertEqual(meta.abis, ["arm64-v8a", "armeabi-v7a", "x86_64"])
            self.assertEqual(meta.native_libs["arm64-v8a"], ["libbar.so", "libfoo.so"])
            self.assertEqual(meta.native_libs["armeabi-v7a"], ["libfoo.so"])
            self.assertTrue(meta.hash.startswith("sha256:"))
            self.assertEqual(meta.name, "synthetic.apk")

    def test_filters_unknown_abi_dirs(self) -> None:
        """A bogus ABI subdir like lib/_FAKE/ must NOT show up in abis."""
        with tempfile.TemporaryDirectory() as tmp:
            apk = _make_apk(
                Path(tmp),
                {"arm64-v8a": ["libfoo.so"]},
                extra_entries={"lib/_FAKE/libnope.so": b"junk"},
            )
            meta = extract_apk_meta(apk)
            self.assertEqual(meta.abis, ["arm64-v8a"])
            self.assertNotIn("_FAKE", meta.native_libs)

    def test_ignores_non_so_files_in_lib(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            apk = _make_apk(
                Path(tmp),
                {"arm64-v8a": ["libfoo.so"]},
                extra_entries={"lib/arm64-v8a/README.txt": b"not a lib"},
            )
            meta = extract_apk_meta(apk)
            self.assertEqual(meta.native_libs["arm64-v8a"], ["libfoo.so"])

    def test_apk_with_no_native_libs_returns_empty(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            apk = _make_apk(Path(tmp), {})
            meta = extract_apk_meta(apk)
            self.assertEqual(meta.abis, [])
            self.assertEqual(meta.native_libs, {})

    def test_to_dict_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            apk = _make_apk(Path(tmp), {"arm64-v8a": ["libfoo.so"]})
            meta = extract_apk_meta(apk)
            d = meta.to_dict()
            self.assertIn("path", d)
            self.assertIn("hash", d)
            self.assertEqual(d["abis"], ["arm64-v8a"])
            self.assertEqual(d["native_libs"]["arm64-v8a"], ["libfoo.so"])

    def test_from_dict_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            apk = _make_apk(Path(tmp), {"arm64-v8a": ["libfoo.so"],
                                          "x86_64": ["libfoo.so"]})
            original = extract_apk_meta(apk)
            restored = ApkMeta.from_dict(original.to_dict())
            self.assertEqual(restored, original)

    def test_from_dict_minimal(self) -> None:
        # No native libs / abis fields default to empty.
        m = ApkMeta.from_dict({
            "path": "/x.apk", "name": "x.apk", "hash": "sha256:00",
        })
        self.assertEqual(m.abis, [])
        self.assertEqual(m.native_libs, {})


class SelectAbiTests(unittest.TestCase):
    def _meta(self, abis: list[str]) -> ApkMeta:
        return ApkMeta(
            path="/fake.apk",
            name="fake.apk",
            hash="sha256:00",
            abis=abis,
            native_libs={abi: ["libfoo.so"] for abi in abis},
        )

    def test_auto_prefers_arm64(self) -> None:
        meta = self._meta(["arm64-v8a", "armeabi-v7a", "x86_64"])
        self.assertEqual(select_abi(meta, "auto"), "arm64-v8a")

    def test_auto_falls_back_when_arm64_missing(self) -> None:
        meta = self._meta(["armeabi-v7a", "x86_64"])
        self.assertEqual(select_abi(meta, "auto"), "armeabi-v7a")

    def test_auto_falls_back_to_x86_64(self) -> None:
        meta = self._meta(["x86_64", "x86"])
        self.assertEqual(select_abi(meta, "auto"), "x86_64")

    def test_explicit_abi_returned_when_present(self) -> None:
        meta = self._meta(["arm64-v8a", "armeabi-v7a"])
        self.assertEqual(select_abi(meta, "armeabi-v7a"), "armeabi-v7a")

    def test_explicit_abi_missing_raises(self) -> None:
        meta = self._meta(["arm64-v8a"])
        with self.assertRaises(ApkExtractError):
            select_abi(meta, "armeabi-v7a")

    def test_no_abis_raises(self) -> None:
        meta = self._meta([])
        with self.assertRaises(ApkExtractError):
            select_abi(meta, "auto")

    def test_preference_order_is_documented_constant(self) -> None:
        """Sanity: ABI_PREFERENCE matches what we tested above."""
        self.assertEqual(ABI_PREFERENCE, ("arm64-v8a", "armeabi-v7a", "x86_64", "x86"))


class ExtractNativeLibTests(unittest.TestCase):
    def test_extracts_first_so_when_lib_name_is_none(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            apk = _make_apk(tmp_path, {"arm64-v8a": ["libbar.so", "libfoo.so"]})
            dest = tmp_path / "out"
            so = extract_native_lib(apk, abi="arm64-v8a", lib_name=None, dest_dir=dest)
            # Sorted lex: libbar.so comes first
            self.assertEqual(so.name, "libbar.so")
            self.assertTrue(so.exists())
            # Content starts with our fake ELF magic
            self.assertTrue(so.read_bytes().startswith(b"\x7fELF"))

    def test_extracts_named_lib(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            apk = _make_apk(tmp_path, {"arm64-v8a": ["libbar.so", "libfoo.so"]})
            dest = tmp_path / "out"
            so = extract_native_lib(apk, abi="arm64-v8a", lib_name="libfoo.so", dest_dir=dest)
            self.assertEqual(so.name, "libfoo.so")
            # The encoded basename is in our fake content
            self.assertIn(b"libfoo.so", so.read_bytes())

    def test_creates_dest_dir_if_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            apk = _make_apk(tmp_path, {"arm64-v8a": ["libfoo.so"]})
            dest = tmp_path / "deep" / "nested" / "dir"
            so = extract_native_lib(apk, abi="arm64-v8a", lib_name=None, dest_dir=dest)
            self.assertTrue(so.exists())
            self.assertTrue(dest.exists())

    def test_unknown_lib_name_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            apk = _make_apk(tmp_path, {"arm64-v8a": ["libfoo.so"]})
            with self.assertRaises(ApkExtractError):
                extract_native_lib(
                    apk, abi="arm64-v8a", lib_name="libnope.so", dest_dir=tmp_path / "out"
                )

    def test_missing_abi_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            apk = _make_apk(tmp_path, {"arm64-v8a": ["libfoo.so"]})
            with self.assertRaises(ApkExtractError):
                extract_native_lib(
                    apk, abi="armeabi-v7a", lib_name=None, dest_dir=tmp_path / "out"
                )


class ErrorHandlingTests(unittest.TestCase):
    def test_missing_file_raises(self) -> None:
        with self.assertRaises(ApkExtractError):
            extract_apk_meta("/nonexistent/path/foo.apk")

    def test_non_zip_file_raises(self) -> None:
        with tempfile.NamedTemporaryFile("wb", suffix=".apk", delete=False) as fp:
            fp.write(b"this is not a zip")
            path = fp.name
        try:
            with self.assertRaises(ApkExtractError):
                extract_apk_meta(path)
        finally:
            Path(path).unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()

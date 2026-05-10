"""Tests for android_pipeline — orchestration of APK -> manifest + natives + .so + bridges.

The pipeline composes apk_extractor, apk_decoder, jadx_runner, binary_meta,
and jni_bridge. Tests focus on:
  - successful end-to-end flow with all tools available
  - graceful fallback when apktool/jadx are missing
  - strict mode (`fail_on_missing_tools`) propagates errors
  - REQUIRED-step failures (no .so, no exports, etc.) raise correctly
  - AndroidAnalysis to_dict round-trip surface

The .so is mocked via a stub BinaryMeta object so we don't need real lief
fixtures. apktool/jadx subprocesses are stubbed via shell scripts.
"""

from __future__ import annotations

import stat
import sys
import tempfile
import textwrap
import unittest
import zipfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from venomhook.android_pipeline import (
    AndroidAnalysis,
    AndroidPipelineError,
    analyze_apk,
)
from venomhook.apk_decoder import ApktoolConfig, ApktoolNotFoundError
from venomhook.binary_meta import BinaryMeta
from venomhook.jadx_runner import JadxConfig, JadxNotFoundError
from venomhook.models import JavaNativeMethod, JniBridge


def _make_apk_with_lib(tmp: Path, abis_to_libs: dict[str, list[str]]) -> Path:
    apk = tmp / "synth.apk"
    with zipfile.ZipFile(apk, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", b"\x00\x00\x00\x00")
        for abi, libs in abis_to_libs.items():
            for lib in libs:
                # Minimal ELF header so the .so isn't completely empty
                zf.writestr(f"lib/{abi}/{lib}", b"\x7fELF" + b"\x00" * 60)
    return apk


def _executable(path: Path, body: str) -> Path:
    path.write_text(body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


def _stub_binary_meta(path: str, exports: list[str]) -> BinaryMeta:
    return BinaryMeta(
        name=Path(path).name,
        path=path,
        hash="sha256:stub",
        format="ELF",
        arch="arm64",
        os_hint="android",
        image_base=0,
        aslr=True,
        exports=exports,
    )


class TestAnalyzeApkRequiredFailures(unittest.TestCase):
    def test_apk_with_no_abis_raises(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            apk = tdp / "empty.apk"
            with zipfile.ZipFile(apk, "w") as zf:
                zf.writestr("AndroidManifest.xml", b"\x00\x00\x00\x00")
            with self.assertRaises(AndroidPipelineError) as ctx:
                analyze_apk(apk, tdp / "work")
            self.assertIn("네이티브 라이브러리가 없습니다", str(ctx.exception))

    def test_missing_apk_raises(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(AndroidPipelineError):
                analyze_apk(Path(td) / "no.apk", Path(td) / "work")

    def test_binary_meta_failure_propagates(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            apk = _make_apk_with_lib(tdp, {"arm64-v8a": ["libfoo.so"]})
            with mock.patch(
                "venomhook.android_pipeline.extract_binary_meta",
                side_effect=__import__("venomhook.binary_meta", fromlist=["BinaryMetaError"]).BinaryMetaError("nope"),
            ):
                with self.assertRaises(AndroidPipelineError) as ctx:
                    analyze_apk(apk, tdp / "work", use_apktool=False, use_jadx=False)
                self.assertIn("binary_meta 추출 실패", str(ctx.exception))


class TestAnalyzeApkOptionalTools(unittest.TestCase):
    def test_skips_apktool_when_missing_and_records_warning(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            apk = _make_apk_with_lib(tdp, {"arm64-v8a": ["libfoo.so"]})
            with mock.patch(
                "venomhook.android_pipeline.extract_binary_meta",
                return_value=_stub_binary_meta("/tmp/libfoo.so", []),
            ), mock.patch(
                "venomhook.android_pipeline.decode_apk",
                side_effect=ApktoolNotFoundError("not on PATH"),
            ):
                result = analyze_apk(apk, tdp / "work", use_jadx=False)
            self.assertIsNone(result.app_meta)
            self.assertTrue(any("apktool" in w for w in result.warnings))

    def test_skips_jadx_when_missing_and_records_warning(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            apk = _make_apk_with_lib(tdp, {"arm64-v8a": ["libfoo.so"]})
            with mock.patch(
                "venomhook.android_pipeline.extract_binary_meta",
                return_value=_stub_binary_meta("/tmp/libfoo.so", []),
            ), mock.patch(
                "venomhook.android_pipeline.decompile_apk",
                side_effect=JadxNotFoundError("not on PATH"),
            ):
                result = analyze_apk(apk, tdp / "work", use_apktool=False)
            self.assertEqual(result.java_natives, [])
            self.assertTrue(any("jadx" in w for w in result.warnings))

    def test_strict_mode_raises_when_apktool_missing(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            apk = _make_apk_with_lib(tdp, {"arm64-v8a": ["libfoo.so"]})
            with mock.patch(
                "venomhook.android_pipeline.extract_binary_meta",
                return_value=_stub_binary_meta("/tmp/libfoo.so", []),
            ), mock.patch(
                "venomhook.android_pipeline.decode_apk",
                side_effect=ApktoolNotFoundError("not on PATH"),
            ):
                with self.assertRaises(AndroidPipelineError):
                    analyze_apk(
                        apk, tdp / "work",
                        use_jadx=False,
                        fail_on_missing_tools=True,
                    )

    def test_strict_mode_raises_when_jadx_missing(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            apk = _make_apk_with_lib(tdp, {"arm64-v8a": ["libfoo.so"]})
            with mock.patch(
                "venomhook.android_pipeline.extract_binary_meta",
                return_value=_stub_binary_meta("/tmp/libfoo.so", []),
            ), mock.patch(
                "venomhook.android_pipeline.decompile_apk",
                side_effect=JadxNotFoundError("not on PATH"),
            ):
                with self.assertRaises(AndroidPipelineError):
                    analyze_apk(
                        apk, tdp / "work",
                        use_apktool=False,
                        fail_on_missing_tools=True,
                    )


class TestAnalyzeApkBridgeCorrelation(unittest.TestCase):
    def test_bridges_built_and_correlated_against_so_exports(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            apk = _make_apk_with_lib(tdp, {"arm64-v8a": ["libcrypto.so"]})

            stub_natives = [
                JavaNativeMethod(
                    class_fqn="com.app.Crypto",
                    method_name="encrypt",
                    return_type="byte[]",
                    arg_types=["byte[]"],
                ),
                JavaNativeMethod(
                    class_fqn="com.app.Crypto",
                    method_name="hash",
                    return_type="String",
                    arg_types=["String"],
                ),
            ]

            with mock.patch(
                "venomhook.android_pipeline.extract_binary_meta",
                return_value=_stub_binary_meta(
                    "/tmp/libcrypto.so",
                    [
                        "Java_com_app_Crypto_encrypt",
                        "JNI_OnLoad",
                        # `hash` symbol intentionally missing from exports
                    ],
                ),
            ), mock.patch(
                "venomhook.android_pipeline.decompile_apk",
                return_value=(mock.MagicMock(), stub_natives),
            ):
                result = analyze_apk(apk, tdp / "work", use_apktool=False)

            self.assertEqual(len(result.bridges), 2)
            self.assertEqual(len(result.matched_bridges), 1)
            self.assertEqual(
                result.matched_bridges[0].matched_symbol,
                "Java_com_app_Crypto_encrypt",
            )
            self.assertEqual(len(result.unmatched_bridges), 1)
            self.assertEqual(
                result.unmatched_bridges[0].java_method.method_name, "hash"
            )

    def test_no_natives_means_no_bridges(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            apk = _make_apk_with_lib(tdp, {"arm64-v8a": ["libfoo.so"]})
            with mock.patch(
                "venomhook.android_pipeline.extract_binary_meta",
                return_value=_stub_binary_meta("/tmp/libfoo.so", ["JNI_OnLoad"]),
            ), mock.patch(
                "venomhook.android_pipeline.decompile_apk",
                return_value=(mock.MagicMock(), []),
            ):
                result = analyze_apk(apk, tdp / "work", use_apktool=False)
            self.assertEqual(result.bridges, [])


class TestAnalyzeApkMultiLib(unittest.TestCase):
    """Phase 9-1: --apk-lib all extracts every .so and merges exports/strings."""

    def test_analyze_all_libs_populates_additional_so_metas(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            apk = _make_apk_with_lib(
                tdp,
                {"arm64-v8a": ["libcrypto.so", "libssl.so", "libnetwork.so"]},
            )

            # Primary is libcrypto.so (sorted lex first).
            def _meta_per_path(path):
                name = Path(path).name
                if name == "libcrypto.so":
                    return _stub_binary_meta(str(path), ["Java_com_app_C_e", "JNI_OnLoad"])
                if name == "libssl.so":
                    return _stub_binary_meta(str(path), ["Java_com_app_S_handshake"])
                if name == "libnetwork.so":
                    return _stub_binary_meta(str(path), ["Java_com_app_N_connect"])
                raise AssertionError(f"unexpected path: {path}")

            with mock.patch(
                "venomhook.android_pipeline.extract_binary_meta",
                side_effect=_meta_per_path,
            ):
                result = analyze_apk(
                    apk,
                    tdp / "work",
                    use_apktool=False,
                    use_jadx=False,
                    analyze_all_libs=True,
                )

            self.assertIsNotNone(result.so_meta)
            self.assertEqual(result.so_meta.name, "libcrypto.so")
            self.assertEqual(len(result.additional_so_metas), 2)
            extra_names = {m.name for m in result.additional_so_metas}
            self.assertEqual(extra_names, {"libssl.so", "libnetwork.so"})
            self.assertEqual(len(result.additional_so_paths), 2)
            # all_so_metas convenience aggregates primary + extras
            self.assertEqual(len(result.all_so_metas), 3)

    def test_jni_bridges_correlate_against_union_of_exports(self):
        """A JNI symbol exported only by a non-primary .so must still match."""
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            apk = _make_apk_with_lib(
                tdp,
                {"arm64-v8a": ["libcrypto.so", "libssl.so"]},
            )

            def _meta_per_path(path):
                name = Path(path).name
                if name == "libcrypto.so":
                    return _stub_binary_meta(str(path), ["Java_com_app_Crypto_encrypt"])
                if name == "libssl.so":
                    # the SSL native belongs to a different .so
                    return _stub_binary_meta(str(path), ["Java_com_app_Ssl_handshake"])
                raise AssertionError(path)

            stub_natives = [
                JavaNativeMethod(
                    class_fqn="com.app.Crypto", method_name="encrypt",
                    return_type="void", arg_types=[],
                ),
                JavaNativeMethod(
                    class_fqn="com.app.Ssl", method_name="handshake",
                    return_type="void", arg_types=[],
                ),
            ]

            with mock.patch(
                "venomhook.android_pipeline.extract_binary_meta",
                side_effect=_meta_per_path,
            ), mock.patch(
                "venomhook.android_pipeline.decompile_apk",
                return_value=(mock.MagicMock(), stub_natives),
            ):
                result = analyze_apk(
                    apk,
                    tdp / "work",
                    use_apktool=False,
                    analyze_all_libs=True,
                )

            self.assertEqual(len(result.matched_bridges), 2)
            matched_syms = {b.matched_symbol for b in result.matched_bridges}
            self.assertEqual(
                matched_syms,
                {"Java_com_app_Crypto_encrypt", "Java_com_app_Ssl_handshake"},
            )

    def test_skipped_libs_warning_suppressed_in_all_mode(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            apk = _make_apk_with_lib(
                tdp,
                {"arm64-v8a": ["libcrypto.so", "libssl.so"]},
            )
            with mock.patch(
                "venomhook.android_pipeline.extract_binary_meta",
                side_effect=lambda p: _stub_binary_meta(str(p), []),
            ):
                result = analyze_apk(
                    apk,
                    tdp / "work",
                    use_apktool=False,
                    use_jadx=False,
                    analyze_all_libs=True,
                )
            joined = " | ".join(result.warnings)
            self.assertNotIn("--apk-lib", joined)
            self.assertNotIn("만 분석되었습니다", joined)

    def test_single_lib_mode_still_warns_about_siblings(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            apk = _make_apk_with_lib(
                tdp,
                {"arm64-v8a": ["libcrypto.so", "libssl.so"]},
            )
            with mock.patch(
                "venomhook.android_pipeline.extract_binary_meta",
                return_value=_stub_binary_meta("/tmp/libcrypto.so", []),
            ):
                result = analyze_apk(
                    apk,
                    tdp / "work",
                    use_apktool=False,
                    use_jadx=False,
                )
            joined = " | ".join(result.warnings)
            self.assertIn("--apk-lib", joined)

    def test_strings_by_symbol_populated_when_bridges_match(self):
        """Phase 9-4: bridge-matched JNI symbols receive co-locality hints."""
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            apk = _make_apk_with_lib(tdp, {"arm64-v8a": ["libcrypto.so"]})

            # Stub a binary whose .rodata yielded crypto + URL strings, so
            # the categorizer fills both buckets.
            def _meta(path):
                m = _stub_binary_meta(
                    str(path),
                    ["Java_com_app_Crypto_encrypt", "JNI_OnLoad"],
                )
                m.strings = ["AES/CBC/PKCS5Padding", "http://a.example/cb", "MD5"]
                return m

            stub_natives = [
                JavaNativeMethod(
                    class_fqn="com.app.Crypto", method_name="encrypt",
                    return_type="void", arg_types=[],
                ),
            ]
            with mock.patch(
                "venomhook.android_pipeline.extract_binary_meta",
                side_effect=_meta,
            ), mock.patch(
                "venomhook.android_pipeline.decompile_apk",
                return_value=(mock.MagicMock(), stub_natives),
            ):
                result = analyze_apk(apk, tdp / "work", use_apktool=False)

            attributed = result.strings_by_symbol.get("Java_com_app_Crypto_encrypt")
            self.assertIsNotNone(attributed)
            self.assertIn("AES/CBC/PKCS5Padding", attributed)
            self.assertIn("MD5", attributed)
            # URL must NOT bleed into a crypto-named symbol
            self.assertNotIn("http://a.example/cb", attributed)

    def test_strings_by_symbol_empty_when_no_hints(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            apk = _make_apk_with_lib(tdp, {"arm64-v8a": ["libfoo.so"]})

            def _meta(path):
                m = _stub_binary_meta(str(path), ["Java_com_app_X_y"])
                m.strings = ["nothing relevant"]
                return m

            with mock.patch(
                "venomhook.android_pipeline.extract_binary_meta",
                side_effect=_meta,
            ), mock.patch(
                "venomhook.android_pipeline.decompile_apk",
                return_value=(mock.MagicMock(), []),
            ):
                result = analyze_apk(apk, tdp / "work", use_apktool=False)

            self.assertEqual(result.strings_by_symbol, {})

    def test_extra_lief_failure_does_not_abort_run(self):
        """Failure on a non-primary .so degrades gracefully with a warning.

        Sort order makes ``libcrypto.so`` (lex-first) the primary; the
        synthetically broken ``libzbroken.so`` is iterated as an extra,
        so its parse failure is downgraded to a warning rather than
        aborting the analysis.
        """
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            apk = _make_apk_with_lib(
                tdp,
                {"arm64-v8a": ["libcrypto.so", "libzbroken.so"]},
            )
            from venomhook.binary_meta import BinaryMetaError

            def _meta_per_path(path):
                name = Path(path).name
                if name == "libcrypto.so":
                    return _stub_binary_meta(str(path), ["JNI_OnLoad"])
                raise BinaryMetaError(f"synthetic parse failure for {name}")

            with mock.patch(
                "venomhook.android_pipeline.extract_binary_meta",
                side_effect=_meta_per_path,
            ):
                result = analyze_apk(
                    apk,
                    tdp / "work",
                    use_apktool=False,
                    use_jadx=False,
                    analyze_all_libs=True,
                )

            self.assertIsNotNone(result.so_meta)
            self.assertEqual(result.so_meta.name, "libcrypto.so")
            self.assertEqual(result.additional_so_metas, [])
            self.assertTrue(
                any("libzbroken.so" in w for w in result.warnings),
                f"expected warning mentioning libzbroken.so, got {result.warnings!r}",
            )

    def test_first_lief_failure_still_analyzes_later_libs(self):
        """A broken lex-first .so must not hide valid libraries in all mode."""
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            apk = _make_apk_with_lib(
                tdp,
                {"arm64-v8a": ["libaaa_broken.so", "libcrypto.so"]},
            )
            from venomhook.binary_meta import BinaryMetaError

            def _meta_per_path(path):
                name = Path(path).name
                if name == "libaaa_broken.so":
                    raise BinaryMetaError(f"synthetic parse failure for {name}")
                if name == "libcrypto.so":
                    return _stub_binary_meta(str(path), ["JNI_OnLoad"])
                raise AssertionError(path)

            with mock.patch(
                "venomhook.android_pipeline.extract_binary_meta",
                side_effect=_meta_per_path,
            ):
                result = analyze_apk(
                    apk,
                    tdp / "work",
                    use_apktool=False,
                    use_jadx=False,
                    analyze_all_libs=True,
                )

            self.assertIsNotNone(result.so_meta)
            self.assertEqual(result.so_meta.name, "libcrypto.so")
            self.assertEqual(result.additional_so_metas, [])
            self.assertTrue(
                any("libaaa_broken.so" in w for w in result.warnings),
                f"expected warning mentioning libaaa_broken.so, got {result.warnings!r}",
            )


class TestAnalyzeApkAbiSelection(unittest.TestCase):
    def test_explicit_abi(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            apk = _make_apk_with_lib(
                tdp,
                {"arm64-v8a": ["libfoo.so"], "armeabi-v7a": ["libfoo.so"]},
            )
            with mock.patch(
                "venomhook.android_pipeline.extract_binary_meta",
                return_value=_stub_binary_meta("/tmp/libfoo.so", []),
            ):
                result = analyze_apk(
                    apk, tdp / "work",
                    abi="armeabi-v7a",
                    use_apktool=False,
                    use_jadx=False,
                )
            self.assertEqual(result.selected_abi, "armeabi-v7a")
            self.assertTrue(result.extracted_so_path.endswith("libfoo.so"))

    def test_auto_abi_picks_arm64(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            apk = _make_apk_with_lib(
                tdp,
                {"x86_64": ["libfoo.so"], "arm64-v8a": ["libfoo.so"]},
            )
            with mock.patch(
                "venomhook.android_pipeline.extract_binary_meta",
                return_value=_stub_binary_meta("/tmp/libfoo.so", []),
            ):
                result = analyze_apk(
                    apk, tdp / "work",
                    use_apktool=False,
                    use_jadx=False,
                )
            self.assertEqual(result.selected_abi, "arm64-v8a")

    def test_unavailable_abi_raises(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            apk = _make_apk_with_lib(tdp, {"arm64-v8a": ["libfoo.so"]})
            with self.assertRaises(AndroidPipelineError):
                analyze_apk(
                    apk, tdp / "work",
                    abi="x86_64",
                    use_apktool=False,
                    use_jadx=False,
                )


class TestAndroidAnalysisModel(unittest.TestCase):
    def test_positional_warnings_argument_remains_compatible(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            apk = _make_apk_with_lib(tdp, {"arm64-v8a": ["libfoo.so"]})
            with mock.patch(
                "venomhook.android_pipeline.extract_binary_meta",
                return_value=_stub_binary_meta("/tmp/libfoo.so", []),
            ):
                baseline = analyze_apk(
                    apk, tdp / "work", use_apktool=False, use_jadx=False
                )
            result = AndroidAnalysis(
                baseline.apk_meta,
                baseline.selected_abi,
                baseline.extracted_so_path,
                baseline.so_meta,
                baseline.app_meta,
                baseline.java_natives,
                baseline.bridges,
                ["legacy warning"],
            )
            self.assertEqual(result.warnings, ["legacy warning"])
            self.assertIsNone(result.audit_report)
            self.assertEqual(result.pocs, [])

    def test_to_dict_includes_all_fields(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            apk = _make_apk_with_lib(tdp, {"arm64-v8a": ["libfoo.so"]})
            with mock.patch(
                "venomhook.android_pipeline.extract_binary_meta",
                return_value=_stub_binary_meta("/tmp/libfoo.so", []),
            ):
                result = analyze_apk(
                    apk, tdp / "work", use_apktool=False, use_jadx=False
                )
            d = result.to_dict()
            for key in (
                "apk_meta", "selected_abi", "extracted_so_path",
                "so_meta", "app_meta", "java_natives", "bridges",
                "audit_report", "pocs", "warnings",
            ):
                self.assertIn(key, d)
            self.assertEqual(d["selected_abi"], "arm64-v8a")
            self.assertIsNone(d["app_meta"])  # apktool was disabled
            # Audit and PoCs are derived from app_meta; both should be empty
            # when manifest decode was skipped.
            self.assertIsNone(d["audit_report"])
            self.assertEqual(d["pocs"], [])


# ---------- Real subprocess stubs (jadx + apktool both available) ----------


class TestAnalyzeApkWithStubbedTools(unittest.TestCase):
    """Exercise the full subprocess path with shell-script stubs.

    These tests verify the orchestration writes outputs to the expected paths
    and propagates results from the stubbed jadx/apktool binaries.
    """

    def test_full_pipeline_with_stub_tools(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            apk = _make_apk_with_lib(tdp, {"arm64-v8a": ["libcore.so"]})

            apktool_stub = _executable(
                tdp / "stub-apktool.sh",
                textwrap.dedent("""\
                    #!/bin/sh
                    while [ $# -gt 0 ]; do
                        case "$1" in
                            -o) shift; OUT="$1"; shift; ;;
                            *) shift; ;;
                        esac
                    done
                    mkdir -p "$OUT"
                    cat > "$OUT/AndroidManifest.xml" <<'EOF'
                    <?xml version="1.0"?>
                    <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.demo">
                        <application/>
                    </manifest>
                    EOF
                    exit 0
                """),
            )

            jadx_stub = _executable(
                tdp / "stub-jadx.sh",
                textwrap.dedent("""\
                    #!/bin/sh
                    while [ $# -gt 0 ]; do
                        case "$1" in
                            -d) shift; OUT="$1"; shift; ;;
                            *) shift; ;;
                        esac
                    done
                    mkdir -p "$OUT/sources/com/demo"
                    cat > "$OUT/sources/com/demo/Main.java" <<'EOF'
                    package com.demo;
                    public class Main {
                        public native String getVersion();
                    }
                    EOF
                    exit 0
                """),
            )

            with mock.patch(
                "venomhook.android_pipeline.extract_binary_meta",
                return_value=_stub_binary_meta(
                    "/tmp/libcore.so",
                    ["Java_com_demo_Main_getVersion", "JNI_OnLoad"],
                ),
            ):
                result = analyze_apk(
                    apk,
                    tdp / "work",
                    apktool_config=ApktoolConfig(apktool_path=str(apktool_stub)),
                    jadx_config=JadxConfig(jadx_path=str(jadx_stub)),
                )

            self.assertIsNotNone(result.app_meta)
            self.assertEqual(result.app_meta.package_name, "com.demo")
            self.assertEqual(len(result.java_natives), 1)
            self.assertEqual(result.java_natives[0].method_name, "getVersion")
            self.assertEqual(len(result.bridges), 1)
            self.assertTrue(result.bridges[0].is_matched)
            self.assertEqual(
                result.bridges[0].matched_symbol,
                "Java_com_demo_Main_getVersion",
            )
            self.assertEqual(result.warnings, [])


class TestAnalyzeApkAuditAndPocsIntegration(unittest.TestCase):
    """Phase 3 wiring: analyze_apk should populate audit_report + pocs
    automatically whenever app_meta is available. When apktool is absent
    (app_meta is None) both must remain unpopulated.
    """

    def test_audit_and_pocs_skipped_when_app_meta_absent(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            apk = _make_apk_with_lib(tdp, {"arm64-v8a": ["libfoo.so"]})
            with mock.patch(
                "venomhook.android_pipeline.extract_binary_meta",
                return_value=_stub_binary_meta("/tmp/libfoo.so", []),
            ), mock.patch(
                "venomhook.android_pipeline.decode_apk",
                side_effect=ApktoolNotFoundError("not on PATH"),
            ):
                result = analyze_apk(
                    apk, tdp / "work", use_jadx=False
                )
            self.assertIsNone(result.app_meta)
            self.assertIsNone(result.audit_report)
            self.assertEqual(result.pocs, [])

    def test_audit_findings_and_pocs_populated_when_manifest_decoded(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            apk = _make_apk_with_lib(tdp, {"arm64-v8a": ["libcore.so"]})

            # Stub apktool produces a manifest with debuggable=true →
            # MANIFEST-001 fires → poc_generator emits jdb + run-as recipes.
            apktool_stub = _executable(
                tdp / "stub-apktool.sh",
                textwrap.dedent("""\
                    #!/bin/sh
                    while [ $# -gt 0 ]; do
                        case "$1" in
                            -o) shift; OUT="$1"; shift; ;;
                            *) shift; ;;
                        esac
                    done
                    mkdir -p "$OUT"
                    cat > "$OUT/AndroidManifest.xml" <<'EOF'
                    <?xml version="1.0"?>
                    <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.demo">
                        <application android:debuggable="true"/>
                    </manifest>
                    EOF
                    exit 0
                """),
            )

            with mock.patch(
                "venomhook.android_pipeline.extract_binary_meta",
                return_value=_stub_binary_meta("/tmp/libcore.so", []),
            ):
                result = analyze_apk(
                    apk,
                    tdp / "work",
                    apktool_config=ApktoolConfig(apktool_path=str(apktool_stub)),
                    use_jadx=False,
                )

            self.assertIsNotNone(result.app_meta)
            self.assertTrue(result.app_meta.debuggable)
            self.assertIsNotNone(result.audit_report)
            rule_ids = [f.rule_id for f in result.audit_report.findings]
            self.assertIn("MANIFEST-001", rule_ids)
            # PoCs should include both debuggable artifacts (jdb + run-as).
            poc_rule_ids = [p.rule_id for p in result.pocs]
            self.assertEqual(poc_rule_ids.count("MANIFEST-001"), 2)
            self.assertTrue(any("jdb" in p.title.lower() for p in result.pocs))

    def test_clean_manifest_yields_empty_pocs_but_non_null_report(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            apk = _make_apk_with_lib(tdp, {"arm64-v8a": ["libcore.so"]})

            # Manifest with no findings: target_sdk=33, debuggable absent,
            # no exported components, no cleartext, no allowBackup.
            apktool_stub = _executable(
                tdp / "stub-apktool.sh",
                textwrap.dedent("""\
                    #!/bin/sh
                    while [ $# -gt 0 ]; do
                        case "$1" in
                            -o) shift; OUT="$1"; shift; ;;
                            *) shift; ;;
                        esac
                    done
                    mkdir -p "$OUT"
                    cat > "$OUT/AndroidManifest.xml" <<'EOF'
                    <?xml version="1.0"?>
                    <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.clean">
                        <uses-sdk android:minSdkVersion="26" android:targetSdkVersion="33"/>
                        <application android:allowBackup="false" android:usesCleartextTraffic="false"/>
                    </manifest>
                    EOF
                    exit 0
                """),
            )
            with mock.patch(
                "venomhook.android_pipeline.extract_binary_meta",
                return_value=_stub_binary_meta("/tmp/libcore.so", []),
            ):
                result = analyze_apk(
                    apk,
                    tdp / "work",
                    apktool_config=ApktoolConfig(apktool_path=str(apktool_stub)),
                    use_jadx=False,
                )
            self.assertIsNotNone(result.audit_report)
            self.assertEqual(result.audit_report.findings, [])
            self.assertEqual(result.pocs, [])

    def test_to_dict_serializes_audit_and_pocs(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            apk = _make_apk_with_lib(tdp, {"arm64-v8a": ["libcore.so"]})
            apktool_stub = _executable(
                tdp / "stub-apktool.sh",
                textwrap.dedent("""\
                    #!/bin/sh
                    while [ $# -gt 0 ]; do
                        case "$1" in
                            -o) shift; OUT="$1"; shift; ;;
                            *) shift; ;;
                        esac
                    done
                    mkdir -p "$OUT"
                    cat > "$OUT/AndroidManifest.xml" <<'EOF'
                    <?xml version="1.0"?>
                    <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.demo">
                        <application android:debuggable="true"/>
                    </manifest>
                    EOF
                    exit 0
                """),
            )
            with mock.patch(
                "venomhook.android_pipeline.extract_binary_meta",
                return_value=_stub_binary_meta("/tmp/libcore.so", []),
            ):
                result = analyze_apk(
                    apk,
                    tdp / "work",
                    apktool_config=ApktoolConfig(apktool_path=str(apktool_stub)),
                    use_jadx=False,
                )
            d = result.to_dict()
            self.assertIsNotNone(d["audit_report"])
            self.assertEqual(d["audit_report"]["package_name"], "com.demo")
            self.assertGreater(len(d["pocs"]), 0)
            self.assertEqual(d["pocs"][0]["rule_id"], "MANIFEST-001")


class AndroidAnalysisRoundtripTests(unittest.TestCase):
    """AndroidAnalysis.to_dict -> from_dict roundtrip — Phase 4 cache foundation.

    Builds a real-ish AndroidAnalysis via the stubbed pipeline path used
    elsewhere in this file, serializes, and reconstructs. The reconstructed
    object must compare equal to the original on every nested field so the
    cache layer can replace a live run with a stored payload.
    """

    def _full_analysis(self, tdp: Path) -> AndroidAnalysis:
        apk = _make_apk_with_lib(tdp, {"arm64-v8a": ["libcore.so"]})
        apktool_stub = _executable(
            tdp / "stub-apktool.sh",
            textwrap.dedent("""\
                #!/bin/sh
                while [ $# -gt 0 ]; do
                    case "$1" in
                        -o) shift; OUT="$1"; shift; ;;
                        *) shift; ;;
                    esac
                done
                mkdir -p "$OUT"
                cat > "$OUT/AndroidManifest.xml" <<'EOF'
                <?xml version="1.0"?>
                <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.demo">
                    <application android:debuggable="true"/>
                </manifest>
                EOF
                exit 0
            """),
        )
        with mock.patch(
            "venomhook.android_pipeline.extract_binary_meta",
            return_value=_stub_binary_meta(
                "/tmp/libcore.so", ["Java_com_demo_X_native"]
            ),
        ):
            return analyze_apk(
                apk, tdp / "work",
                apktool_config=ApktoolConfig(apktool_path=str(apktool_stub)),
                use_jadx=False,
            )

    def test_round_trip_equals_original(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            original = self._full_analysis(tdp)
            restored = AndroidAnalysis.from_dict(original.to_dict())
            self.assertEqual(restored, original)

    def test_round_trip_preserves_pocs_and_audit(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            original = self._full_analysis(tdp)
            self.assertGreater(len(original.pocs), 0)
            restored = AndroidAnalysis.from_dict(original.to_dict())
            self.assertEqual(
                [p.rule_id for p in restored.pocs],
                [p.rule_id for p in original.pocs],
            )
            self.assertEqual(
                restored.audit_report.package_name,
                original.audit_report.package_name,
            )

    def test_legacy_payload_without_audit_or_pocs_loads(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            original = self._full_analysis(tdp)
            d = original.to_dict()
            d.pop("audit_report")
            d.pop("pocs")
            restored = AndroidAnalysis.from_dict(d)
            self.assertIsNone(restored.audit_report)
            self.assertEqual(restored.pocs, [])

    def test_round_trip_preserves_additional_so_metas(self):
        """Phase 9-1: --apk-lib all payload with additional_so_metas survives round-trip."""
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            apk = _make_apk_with_lib(
                tdp,
                {"arm64-v8a": ["libcrypto.so", "libssl.so"]},
            )

            def _meta_per_path(path):
                name = Path(path).name
                if name == "libcrypto.so":
                    return _stub_binary_meta(str(path), ["Java_com_app_C_e"])
                if name == "libssl.so":
                    return _stub_binary_meta(str(path), ["Java_com_app_S_h"])
                raise AssertionError(path)

            with mock.patch(
                "venomhook.android_pipeline.extract_binary_meta",
                side_effect=_meta_per_path,
            ):
                original = analyze_apk(
                    apk, tdp / "work",
                    use_apktool=False, use_jadx=False,
                    analyze_all_libs=True,
                )
            self.assertEqual(len(original.additional_so_metas), 1)
            restored = AndroidAnalysis.from_dict(original.to_dict())
            self.assertEqual(len(restored.additional_so_metas), 1)
            self.assertEqual(
                [m.name for m in restored.additional_so_metas],
                ["libssl.so"],
            )
            self.assertEqual(
                restored.additional_so_paths, original.additional_so_paths
            )

    def test_round_trip_with_no_native_libs_branch(self):
        # Post-9d0dbca safety mode: selected_abi/extracted_so_path/so_meta
        # may all be None when require_native=False and the APK has no
        # native libs. The cache must still round-trip such records.
        d = {
            "apk_meta": {
                "path": "/x.apk", "name": "x.apk", "hash": "sha256:00",
                "abis": [], "native_libs": {},
            },
            "selected_abi": None,
            "extracted_so_path": None,
            "so_meta": None,
            "app_meta": None,
            "java_natives": [],
            "bridges": [],
            "audit_report": None,
            "pocs": [],
            "warnings": ["no native libs"],
        }
        restored = AndroidAnalysis.from_dict(d)
        self.assertIsNone(restored.so_meta)
        self.assertIsNone(restored.app_meta)
        self.assertEqual(restored.warnings, ["no native libs"])


if __name__ == "__main__":
    unittest.main()

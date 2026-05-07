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
            self.assertIn("no native libraries", str(ctx.exception))

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
                self.assertIn("binary_meta failed", str(ctx.exception))


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


if __name__ == "__main__":
    unittest.main()

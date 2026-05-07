"""Tests for the `venomhook android-audit` CLI subcommand.

Exercises the full argparse -> analyze_apk -> stdout/JSON path with
stubbed apktool / binary_meta so no real APK or external tool is
required. Covers exit code semantics (success, missing-tool failure,
severity gate) which are the contract for CI integration.
"""

from __future__ import annotations

import io
import json
import stat
import sys
import tempfile
import textwrap
import unittest
import zipfile
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from venomhook.binary_meta import BinaryMeta
from venomhook.cli import main


def _make_apk_with_lib(tmp: Path, abi: str = "arm64-v8a", lib: str = "libfoo.so") -> Path:
    apk = tmp / "synth.apk"
    with zipfile.ZipFile(apk, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", b"\x00\x00\x00\x00")
        zf.writestr(f"lib/{abi}/{lib}", b"\x7fELF" + b"\x00" * 60)
    return apk


def _executable(path: Path, body: str) -> Path:
    path.write_text(body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


def _stub_binary_meta(path: str) -> BinaryMeta:
    return BinaryMeta(
        name=Path(path).name, path=path, hash="sha256:stub",
        format="ELF", arch="arm64", os_hint="android",
        image_base=0, aslr=True, exports=[],
    )


def _apktool_stub(tmp: Path, manifest_xml: str) -> Path:
    """Stub apktool that drops a fixed AndroidManifest.xml into -o <out>.

    Built as a flat string (no textwrap.dedent) because the embedded
    manifest_xml has col-0 lines that defeat dedent's common-prefix logic
    and would leave the shebang indented.
    """
    body = (
        "#!/bin/sh\n"
        "while [ $# -gt 0 ]; do\n"
        "    case \"$1\" in\n"
        "        -o) shift; OUT=\"$1\"; shift; ;;\n"
        "        *) shift; ;;\n"
        "    esac\n"
        "done\n"
        "mkdir -p \"$OUT\"\n"
        "cat > \"$OUT/AndroidManifest.xml\" <<'EOF'\n"
        f"{manifest_xml}"
        "EOF\n"
        "exit 0\n"
    )
    return _executable(tmp / "stub-apktool.sh", body)


# Minimal manifest variants used across tests.
_MANIFEST_DEBUGGABLE = textwrap.dedent("""\
    <?xml version="1.0"?>
    <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.demo">
        <application android:debuggable="true"/>
    </manifest>
""")
_MANIFEST_CLEAN = textwrap.dedent("""\
    <?xml version="1.0"?>
    <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.clean">
        <uses-sdk android:minSdkVersion="26" android:targetSdkVersion="33"/>
        <application android:allowBackup="false" android:usesCleartextTraffic="false"/>
    </manifest>
""")


class AndroidAuditCliTests(unittest.TestCase):
    def _run(self, argv: list[str]) -> str:
        """Run CLI capturing stdout. Re-raises SystemExit so tests can
        observe exit codes.
        """
        buf = io.StringIO()
        with redirect_stdout(buf):
            main(argv)
        return buf.getvalue()

    def test_summary_and_pocs_printed_for_findings(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            apk = _make_apk_with_lib(tdp)
            apktool = _apktool_stub(tdp, _MANIFEST_DEBUGGABLE)

            with mock.patch(
                "venomhook.android_pipeline.extract_binary_meta",
                return_value=_stub_binary_meta("/tmp/libfoo.so"),
            ):
                out = self._run([
                    "android-audit",
                    "--apk", str(apk),
                    "--out-dir", str(tdp / "work"),
                    "--apktool-path", str(apktool),
                    "--no-jadx",
                ])

        self.assertIn("AndroidManifest audit", out)
        self.assertIn("MANIFEST-001", out)
        self.assertIn("PoC bundle", out)
        # PoC commands include the jdb attach line
        self.assertIn("adb forward", out)

    def test_quiet_suppresses_stdout(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            apk = _make_apk_with_lib(tdp)
            apktool = _apktool_stub(tdp, _MANIFEST_DEBUGGABLE)

            with mock.patch(
                "venomhook.android_pipeline.extract_binary_meta",
                return_value=_stub_binary_meta("/tmp/libfoo.so"),
            ):
                out = self._run([
                    "android-audit",
                    "--apk", str(apk),
                    "--out-dir", str(tdp / "work"),
                    "--apktool-path", str(apktool),
                    "--no-jadx",
                    "--quiet",
                ])

        self.assertEqual(out, "")

    def test_writes_all_three_json_outputs(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            apk = _make_apk_with_lib(tdp)
            apktool = _apktool_stub(tdp, _MANIFEST_DEBUGGABLE)
            report_path = tdp / "report.json"
            audit_path = tdp / "audit.json"
            poc_path = tdp / "poc.json"

            with mock.patch(
                "venomhook.android_pipeline.extract_binary_meta",
                return_value=_stub_binary_meta("/tmp/libfoo.so"),
            ):
                self._run([
                    "android-audit",
                    "--apk", str(apk),
                    "--out-dir", str(tdp / "work"),
                    "--apktool-path", str(apktool),
                    "--no-jadx",
                    "--quiet",
                    "--report-json", str(report_path),
                    "--audit-json", str(audit_path),
                    "--poc-json", str(poc_path),
                ])

            report = json.loads(report_path.read_text())
            audit = json.loads(audit_path.read_text())
            pocs = json.loads(poc_path.read_text())

        self.assertEqual(report["app_meta"]["package_name"], "com.demo")
        self.assertEqual(audit["package_name"], "com.demo")
        self.assertGreaterEqual(len(pocs), 1)
        self.assertEqual(pocs[0]["rule_id"], "MANIFEST-001")

    def test_severity_gate_triggers_exit_2(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            apk = _make_apk_with_lib(tdp)
            apktool = _apktool_stub(tdp, _MANIFEST_DEBUGGABLE)

            with mock.patch(
                "venomhook.android_pipeline.extract_binary_meta",
                return_value=_stub_binary_meta("/tmp/libfoo.so"),
            ), self.assertRaises(SystemExit) as ctx:
                self._run([
                    "android-audit",
                    "--apk", str(apk),
                    "--out-dir", str(tdp / "work"),
                    "--apktool-path", str(apktool),
                    "--no-jadx",
                    "--quiet",
                    "--severity-threshold", "high",
                ])
        self.assertEqual(ctx.exception.code, 2)

    def test_severity_gate_passes_on_clean_manifest(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            apk = _make_apk_with_lib(tdp)
            apktool = _apktool_stub(tdp, _MANIFEST_CLEAN)

            with mock.patch(
                "venomhook.android_pipeline.extract_binary_meta",
                return_value=_stub_binary_meta("/tmp/libfoo.so"),
            ):
                # Should not raise SystemExit
                self._run([
                    "android-audit",
                    "--apk", str(apk),
                    "--out-dir", str(tdp / "work"),
                    "--apktool-path", str(apktool),
                    "--no-jadx",
                    "--quiet",
                    "--severity-threshold", "high",
                ])

    def test_missing_apktool_exits_1_when_no_app_meta(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            apk = _make_apk_with_lib(tdp)

            # Simulate apktool not on PATH: ApktoolNotFoundError surfaces as
            # warning, app_meta stays None, audit cannot run.
            with mock.patch(
                "venomhook.android_pipeline.extract_binary_meta",
                return_value=_stub_binary_meta("/tmp/libfoo.so"),
            ), mock.patch(
                "venomhook.android_pipeline.decode_apk",
                side_effect=__import__(
                    "venomhook.apk_decoder", fromlist=["ApktoolNotFoundError"]
                ).ApktoolNotFoundError("not on PATH"),
            ), self.assertRaises(SystemExit) as ctx:
                self._run([
                    "android-audit",
                    "--apk", str(apk),
                    "--out-dir", str(tdp / "work"),
                    "--no-jadx",
                    "--quiet",
                ])
        self.assertEqual(ctx.exception.code, 1)

    def test_pipeline_error_exits_1(self):
        # Empty APK (no native libs) -> AndroidPipelineError -> exit 1
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            apk = tdp / "empty.apk"
            with zipfile.ZipFile(apk, "w") as zf:
                zf.writestr("AndroidManifest.xml", b"\x00\x00\x00\x00")
            with self.assertRaises(SystemExit) as ctx:
                self._run([
                    "android-audit",
                    "--apk", str(apk),
                    "--out-dir", str(tdp / "work"),
                    "--no-jadx",
                    "--quiet",
                ])
        self.assertEqual(ctx.exception.code, 1)


if __name__ == "__main__":
    unittest.main()

"""Tests for analysis_diff — compare two AndroidAnalysis snapshots."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from venomhook.analysis_diff import (
    AnalysisDiff,
    diff_analyses,
    format_diff_text,
)
from venomhook.android_pipeline import AndroidAnalysis
from venomhook.apk_extractor import ApkMeta
from venomhook.binary_meta import BinaryMeta
from venomhook.models import (
    AndroidAppMeta,
    AndroidAuditReport,
    JavaNativeMethod,
    JniBridge,
    ManifestFinding,
    PoCArtifact,
)


def _bm(exports: list[str]) -> BinaryMeta:
    return BinaryMeta(
        name="libfoo.so", path="/abs/libfoo.so", hash="sha256:lh",
        format="ELF", arch="arm64", os_hint="android",
        image_base=0, aslr=True, exports=exports,
    )


def _bridge(class_fqn: str, method_name: str, matched: bool = True) -> JniBridge:
    jm = JavaNativeMethod(
        class_fqn=class_fqn, method_name=method_name, return_type="void",
    )
    short = f"Java_{class_fqn.replace('.', '_')}_{method_name}"
    return JniBridge(
        java_method=jm, predicted_short=short,
        matched_symbol=short if matched else None,
    )


def _finding(rule_id: str, component: str | None = None,
             severity: str = "high", title: str = "t") -> ManifestFinding:
    return ManifestFinding(
        rule_id=rule_id, title=title, severity=severity,
        detail="d", remediation="r", component=component,
        references=["CWE-1"],
    )


def _poc(rule_id: str, kind: str = "adb", title: str = "t",
         component: str | None = None) -> PoCArtifact:
    return PoCArtifact(
        rule_id=rule_id, title=title, severity="high", kind=kind,
        package_name="com.demo", component=component,
        commands=["echo hi"], references=[],
    )


def _analysis(
    apk_hash: str = "sha256:a",
    package: str = "com.demo",
    findings: list[ManifestFinding] | None = None,
    pocs: list[PoCArtifact] | None = None,
    exports: list[str] | None = None,
    bridges: list[JniBridge] | None = None,
) -> AndroidAnalysis:
    return AndroidAnalysis(
        apk_meta=ApkMeta(path=f"/{apk_hash}.apk", name="x.apk", hash=apk_hash),
        selected_abi="arm64-v8a",
        extracted_so_path="/tmp/lib.so",
        so_meta=_bm(list(exports or [])),
        app_meta=AndroidAppMeta(package_name=package),
        bridges=list(bridges or []),
        audit_report=AndroidAuditReport(
            package_name=package, findings=list(findings or []),
        ),
        pocs=list(pocs or []),
    )


class FindingDiffTests(unittest.TestCase):
    def test_no_changes_when_identical(self):
        a = _analysis(findings=[_finding("MANIFEST-001", component="A")])
        b = _analysis(findings=[_finding("MANIFEST-001", component="A")])
        diff = diff_analyses(a, b)
        self.assertEqual(diff.added_findings, [])
        self.assertEqual(diff.removed_findings, [])
        self.assertEqual(len(diff.unchanged_findings), 1)
        self.assertFalse(diff.has_changes)

    def test_addition_detected(self):
        a = _analysis(findings=[_finding("MANIFEST-001", component="A")])
        b = _analysis(findings=[
            _finding("MANIFEST-001", component="A"),
            _finding("MANIFEST-004", component="com.x.Y"),
        ])
        diff = diff_analyses(a, b)
        self.assertEqual(len(diff.added_findings), 1)
        self.assertEqual(diff.added_findings[0].rule_id, "MANIFEST-004")
        self.assertEqual(diff.removed_findings, [])
        self.assertTrue(diff.has_changes)

    def test_removal_detected(self):
        a = _analysis(findings=[
            _finding("MANIFEST-001", component="A"),
            _finding("MANIFEST-004", component="com.x.Y"),
        ])
        b = _analysis(findings=[_finding("MANIFEST-001", component="A")])
        diff = diff_analyses(a, b)
        self.assertEqual(len(diff.removed_findings), 1)
        self.assertEqual(diff.removed_findings[0].rule_id, "MANIFEST-004")

    def test_finding_identity_uses_rule_id_and_component(self):
        # Same rule_id, different component -> different identity.
        a = _analysis(findings=[_finding("MANIFEST-004", component="com.x.A")])
        b = _analysis(findings=[_finding("MANIFEST-004", component="com.x.B")])
        diff = diff_analyses(a, b)
        self.assertEqual(len(diff.added_findings), 1)
        self.assertEqual(len(diff.removed_findings), 1)


class PocDiffTests(unittest.TestCase):
    def test_pocs_diff_by_full_identity(self):
        a = _analysis(pocs=[
            _poc("MANIFEST-001", kind="adb", title="jdb"),
            _poc("MANIFEST-001", kind="adb", title="run-as"),
        ])
        b = _analysis(pocs=[
            _poc("MANIFEST-001", kind="adb", title="jdb"),
            _poc("MANIFEST-004", kind="frida", title="observer",
                 component="com.x.Y"),
        ])
        diff = diff_analyses(a, b)
        self.assertEqual(len(diff.added_pocs), 1)
        self.assertEqual(diff.added_pocs[0].kind, "frida")
        self.assertEqual(len(diff.removed_pocs), 1)
        self.assertEqual(diff.removed_pocs[0].title, "run-as")


class ExportDiffTests(unittest.TestCase):
    def test_exports_added_and_removed(self):
        a = _analysis(exports=["sym_a", "sym_b"])
        b = _analysis(exports=["sym_b", "sym_c"])
        diff = diff_analyses(a, b)
        self.assertEqual(diff.added_exports, ["sym_c"])
        self.assertEqual(diff.removed_exports, ["sym_a"])

    def test_handles_none_so_meta_on_either_side(self):
        a = _analysis(exports=["x"])
        a.so_meta = None
        b = _analysis(exports=["y"])
        diff = diff_analyses(a, b)
        self.assertEqual(diff.added_exports, ["y"])
        self.assertEqual(diff.removed_exports, [])


class BridgeDiffTests(unittest.TestCase):
    def test_bridge_identity_via_class_and_method(self):
        a = _analysis(bridges=[_bridge("com.x.A", "init")])
        b = _analysis(bridges=[
            _bridge("com.x.A", "init"),
            _bridge("com.x.A", "shutdown"),
        ])
        diff = diff_analyses(a, b)
        self.assertEqual(diff.added_bridges, ["com.x.A.shutdown"])
        self.assertEqual(diff.removed_bridges, [])


class PackageDiffTests(unittest.TestCase):
    def test_package_change_marks_has_changes_true(self):
        a = _analysis(package="com.x")
        b = _analysis(package="com.y")
        diff = diff_analyses(a, b)
        self.assertEqual(diff.old_package, "com.x")
        self.assertEqual(diff.new_package, "com.y")
        self.assertTrue(diff.has_changes)

    def test_apk_hash_difference_alone_is_not_a_content_change(self):
        # Two builds of the same source with different zip-metadata
        # timestamps yield distinct hashes but identical content. The
        # diff layer reports "no changes" so CI gates don't false-fire
        # on repackaging.
        a = _analysis(apk_hash="sha256:old")
        b = _analysis(apk_hash="sha256:new")
        diff = diff_analyses(a, b)
        self.assertFalse(diff.has_changes)


class FormatDiffTextTests(unittest.TestCase):
    def test_no_changes_message(self):
        a = _analysis()
        b = _analysis()
        out = format_diff_text(diff_analyses(a, b))
        self.assertIn("(no changes)", out)

    def test_renders_added_and_removed_findings(self):
        a = _analysis(findings=[_finding("MANIFEST-001", component="A")])
        b = _analysis(findings=[
            _finding("MANIFEST-002", component="cleartext-app"),
        ])
        out = format_diff_text(diff_analyses(a, b))
        self.assertIn("Findings added", out)
        self.assertIn("MANIFEST-002", out)
        self.assertIn("Findings removed", out)
        self.assertIn("MANIFEST-001", out)


class ToDictTests(unittest.TestCase):
    def test_to_dict_serializes_all_sections(self):
        a = _analysis(findings=[_finding("MANIFEST-001")])
        b = _analysis(findings=[
            _finding("MANIFEST-001"),
            _finding("MANIFEST-004", component="com.x.Y"),
        ])
        d = diff_analyses(a, b).to_dict()
        for k in ("added_findings", "removed_findings", "unchanged_findings",
                   "added_pocs", "removed_pocs", "added_exports",
                   "removed_exports", "added_bridges", "removed_bridges",
                   "old_apk_hash", "new_apk_hash"):
            self.assertIn(k, d)


if __name__ == "__main__":
    unittest.main()

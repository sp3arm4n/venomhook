"""Tests for code_audit — text-pattern rule engine over jadx output.

Synthetic ``sources/`` trees keep the suite hermetic; jadx itself is
never invoked. Each rule has positive and negative cases plus a
package-filter test verifying third-party SDKs don't trigger.
"""

from __future__ import annotations

import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from venomhook.code_audit import (
    DEFAULT_THIRD_PARTY_PREFIXES,
    audit_code,
    iter_app_java_files,
)
from venomhook.models import AndroidAppMeta, CodeAuditReport, CodeFinding


def _meta(package_name: str = "com.example.app") -> AndroidAppMeta:
    return AndroidAppMeta(package_name=package_name)


def _write_java(root: Path, rel_path: str, body: str) -> Path:
    p = root / rel_path
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(textwrap.dedent(body), encoding="utf-8")
    return p


# ---------- file walking / package filter ----------


class IterAppJavaFilesTests(unittest.TestCase):
    def test_returns_empty_when_sources_dir_missing(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(
                iter_app_java_files(Path(td) / "nope"), []
            )

    def test_picks_up_java_files_recursively(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_java(root, "com/example/app/A.java", "class A {}")
            _write_java(root, "com/example/app/sub/B.java", "class B {}")
            files = iter_app_java_files(root, app_package="com.example.app")
            rels = [p.relative_to(root).as_posix() for p in files]
            self.assertIn("com/example/app/A.java", rels)
            self.assertIn("com/example/app/sub/B.java", rels)

    def test_skips_third_party_prefixes(self) -> None:
        # The default skip list should drop SDK code that pollutes findings.
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_java(root, "com/example/app/A.java", "class A {}")
            _write_java(root, "androidx/core/X.java", "class X {}")
            _write_java(root, "com/google/gson/Y.java", "class Y {}")
            _write_java(root, "kotlin/Z.java", "class Z {}")
            files = iter_app_java_files(root, app_package="com.example.app")
            rels = [p.relative_to(root).as_posix() for p in files]
            self.assertEqual(rels, ["com/example/app/A.java"])

    def test_app_package_overrides_skip_prefix(self) -> None:
        # An app whose own package starts with a prefix in the skip list
        # (e.g. ``com.google.foo``) must NOT have its own code skipped.
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_java(root, "com/google/myapp/A.java", "class A {}")
            _write_java(root, "com/google/gson/Y.java", "class Y {}")
            files = iter_app_java_files(
                root, app_package="com.google.myapp"
            )
            rels = [p.relative_to(root).as_posix() for p in files]
            self.assertEqual(rels, ["com/google/myapp/A.java"])

    def test_extra_skip_honored(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_java(root, "com/example/app/A.java", "class A {}")
            _write_java(root, "vendor/libfoo/B.java", "class B {}")
            files = iter_app_java_files(
                root,
                app_package="com.example.app",
                extra_skip=("vendor",),
            )
            rels = [p.relative_to(root).as_posix() for p in files]
            self.assertEqual(rels, ["com/example/app/A.java"])


# ---------- CODE-001 hardcoded HTTP ----------


class HardcodedHttpRuleTests(unittest.TestCase):
    def test_emits_finding_for_http_url_in_app_code(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_java(root, "com/example/app/Net.java", '''
                package com.example.app;
                public class Net {
                    String url = "http://api.example.com/login";
                }
            ''')
            report = audit_code(root, _meta())
            f = next(x for x in report.findings if x.rule_id == "CODE-001")
            self.assertEqual(f.severity, "high")
            self.assertEqual(f.file, "com/example/app/Net.java")
            self.assertEqual(f.class_fqn, "com.example.app.Net")
            self.assertGreater(f.line_no, 0)
            self.assertIn("http://api.example.com", f.line_text)

    def test_https_does_not_trigger(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_java(root, "com/example/app/Net.java",
                'String url = "https://api.example.com/x";\n'
            )
            report = audit_code(root, _meta())
            self.assertEqual(
                [f for f in report.findings if f.rule_id == "CODE-001"], []
            )

    def test_http_inside_line_comment_is_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_java(root, "com/example/app/Net.java", '''
                package com.example.app;
                public class Net {
                    // legacy: http://old.example.com
                    String url = "https://api.example.com";
                }
            ''')
            report = audit_code(root, _meta())
            self.assertEqual(
                [f for f in report.findings if f.rule_id == "CODE-001"], []
            )

    def test_http_inside_block_comment_is_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_java(root, "com/example/app/Net.java", '''
                package com.example.app;
                public class Net {
                    /*
                     * Old endpoint: http://old.example.com/foo
                     */
                    String url = "https://api.example.com";
                }
            ''')
            report = audit_code(root, _meta())
            self.assertEqual(
                [f for f in report.findings if f.rule_id == "CODE-001"], []
            )

    def test_third_party_http_does_not_trigger(self) -> None:
        # Vendored library has http:// — out of scope. Should not fire.
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_java(root, "com/google/gson/X.java",
                'String url = "http://schemas.example.org/x";\n'
            )
            report = audit_code(root, _meta())
            self.assertEqual(report.findings, [])
            self.assertEqual(report.files_scanned, 0)


# ---------- CODE-002 WebView JavaScript ----------


class WebViewJavaScriptRuleTests(unittest.TestCase):
    def test_set_javascript_enabled_true(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_java(root, "com/example/app/W.java", '''
                package com.example.app;
                public class W {
                    void setup(WebView w) {
                        w.getSettings().setJavaScriptEnabled(true);
                    }
                }
            ''')
            report = audit_code(root, _meta())
            findings = [f for f in report.findings if f.rule_id == "CODE-002"]
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].severity, "medium")
            self.assertIn("setJavaScriptEnabled", findings[0].line_text)

    def test_set_javascript_enabled_false_does_not_trigger(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_java(root, "com/example/app/W.java",
                "w.getSettings().setJavaScriptEnabled(false);\n"
            )
            report = audit_code(root, _meta())
            self.assertEqual(
                [f for f in report.findings if f.rule_id == "CODE-002"], []
            )

    def test_add_javascript_interface_emits_high(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_java(root, "com/example/app/W.java",
                'w.addJavascriptInterface(new Bridge(), "android");\n'
            )
            report = audit_code(root, _meta())
            findings = [f for f in report.findings if f.rule_id == "CODE-002"]
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].severity, "high")
            self.assertIn("addJavascriptInterface", findings[0].title)

    def test_both_patterns_in_one_class_emit_two_findings(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_java(root, "com/example/app/W.java", '''
                w.getSettings().setJavaScriptEnabled(true);
                w.addJavascriptInterface(new Bridge(), "android");
            ''')
            report = audit_code(root, _meta())
            findings = [f for f in report.findings if f.rule_id == "CODE-002"]
            self.assertEqual(len(findings), 2)

    def test_javascript_in_third_party_does_not_trigger(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_java(root, "com/google/ads/X.java",
                'w.getSettings().setJavaScriptEnabled(true);\n'
            )
            report = audit_code(root, _meta())
            self.assertEqual(report.findings, [])


# ---------- audit_code aggregate ----------


class AuditCodeTests(unittest.TestCase):
    def test_files_scanned_counts_only_kept_files(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_java(root, "com/example/app/A.java", "class A {}")
            _write_java(root, "com/example/app/B.java", "class B {}")
            _write_java(root, "androidx/core/X.java", "class X {}")
            report = audit_code(root, _meta())
            self.assertEqual(report.files_scanned, 2)

    def test_returns_empty_report_when_sources_missing(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            report = audit_code(Path(td) / "nope", _meta())
            self.assertEqual(report.findings, [])
            self.assertEqual(report.files_scanned, 0)

    def test_report_has_severity_counts(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_java(root, "com/example/app/W.java",
                'String url = "http://x";\n'
                'w.getSettings().setJavaScriptEnabled(true);\n'
                'w.addJavascriptInterface(new Bridge(), "x");\n'
            )
            report = audit_code(root, _meta())
            counts = report.severity_counts
            self.assertEqual(counts.get("high"), 2)   # CODE-001 + addJavascriptInterface
            self.assertEqual(counts.get("medium"), 1) # setJavaScriptEnabled

    def test_severity_threshold_gate(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_java(root, "com/example/app/Net.java",
                'String url = "http://api.example.com";\n'
            )
            report = audit_code(root, _meta())
            self.assertTrue(report.has_severity_at_least("high"))
            self.assertFalse(report.has_severity_at_least("critical"))


# ---------- model serialization ----------


class CodeFindingRoundTripTests(unittest.TestCase):
    def test_to_from_dict_roundtrip(self) -> None:
        f = CodeFinding(
            rule_id="CODE-001",
            title="t",
            severity="high",
            file="com/x/A.java",
            line_no=12,
            line_text='String u = "http://x";',
            class_fqn="com.x.A",
            detail="d",
            remediation="r",
            references=["CWE-319"],
        )
        roundtripped = CodeFinding.from_dict(f.to_dict())
        self.assertEqual(roundtripped, f)

    def test_to_dict_omits_optional_when_empty(self) -> None:
        f = CodeFinding(
            rule_id="CODE-001",
            title="t",
            severity="info",
            file="A.java",
        )
        d = f.to_dict()
        for key in ("line_no", "line_text", "class_fqn",
                    "detail", "remediation", "references"):
            self.assertNotIn(key, d)


class CodeAuditReportRoundTripTests(unittest.TestCase):
    def test_roundtrip_preserves_findings_and_count(self) -> None:
        report = CodeAuditReport(
            package_name="com.x",
            findings=[CodeFinding(
                rule_id="CODE-001", title="t", severity="high",
                file="A.java", line_no=1, line_text="x",
            )],
            files_scanned=42,
        )
        roundtripped = CodeAuditReport.from_dict(report.to_dict())
        self.assertEqual(roundtripped.package_name, "com.x")
        self.assertEqual(len(roundtripped.findings), 1)
        self.assertEqual(roundtripped.files_scanned, 42)


if __name__ == "__main__":
    unittest.main()

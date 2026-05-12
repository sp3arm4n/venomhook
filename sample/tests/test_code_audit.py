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
    dedup_findings_by_class,  # noqa: F401  re-exported for tests below
)
from venomhook.code_audit import (
    DEFAULT_THIRD_PARTY_PREFIXES,
    audit_code,
    iter_app_java_files,
)
from venomhook.models import (
    AndroidAppMeta,
    CodeAuditReport,
    CodeFinding,
    CodeOccurrence,
)


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


# ---------- CODE-003 weak crypto / hash ----------


class WeakCryptoRuleTests(unittest.TestCase):
    def test_des_cipher(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_java(root, "com/example/app/C.java",
                'Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding");\n'
            )
            report = audit_code(root, _meta())
            findings = [f for f in report.findings if f.rule_id == "CODE-003"]
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].severity, "high")
            self.assertIn("DES", findings[0].detail)

    def test_rc4_cipher(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_java(root, "com/example/app/C.java",
                'Cipher c = Cipher.getInstance("RC4");\n'
            )
            report = audit_code(root, _meta())
            self.assertEqual(
                len([f for f in report.findings if f.rule_id == "CODE-003"]), 1
            )

    def test_aes_ecb_cipher(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_java(root, "com/example/app/C.java",
                'Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");\n'
            )
            report = audit_code(root, _meta())
            findings = [f for f in report.findings if f.rule_id == "CODE-003"]
            self.assertEqual(len(findings), 1)
            self.assertIn("AES/ECB", findings[0].detail)

    def test_aes_cbc_nopadding_cipher(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_java(root, "com/example/app/C.java",
                'Cipher c = Cipher.getInstance("AES/CBC/NoPadding");\n'
            )
            report = audit_code(root, _meta())
            self.assertEqual(
                len([f for f in report.findings if f.rule_id == "CODE-003"]), 1
            )

    def test_aes_gcm_does_not_trigger(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_java(root, "com/example/app/C.java",
                'Cipher c = Cipher.getInstance("AES/GCM/NoPadding");\n'
            )
            report = audit_code(root, _meta())
            self.assertEqual(
                [f for f in report.findings if f.rule_id == "CODE-003"], []
            )

    def test_md5_hash(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_java(root, "com/example/app/H.java",
                'MessageDigest m = MessageDigest.getInstance("MD5");\n'
            )
            report = audit_code(root, _meta())
            findings = [f for f in report.findings if f.rule_id == "CODE-003"]
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].severity, "medium")

    def test_sha1_hash(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_java(root, "com/example/app/H.java",
                'MessageDigest m = MessageDigest.getInstance("SHA-1");\n'
            )
            report = audit_code(root, _meta())
            self.assertEqual(
                len([f for f in report.findings if f.rule_id == "CODE-003"]), 1
            )

    def test_sha256_does_not_trigger(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_java(root, "com/example/app/H.java",
                'MessageDigest m = MessageDigest.getInstance("SHA-256");\n'
            )
            report = audit_code(root, _meta())
            self.assertEqual(
                [f for f in report.findings if f.rule_id == "CODE-003"], []
            )


# ---------- CODE-004 plaintext credential logs ----------


class PlaintextLogRuleTests(unittest.TestCase):
    def test_logd_with_password(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_java(root, "com/example/app/L.java",
                'Log.d("Login:", "user=" + u + ", password=" + p);\n'
            )
            report = audit_code(root, _meta())
            findings = [f for f in report.findings if f.rule_id == "CODE-004"]
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].severity, "high")

    def test_loge_with_token(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_java(root, "com/example/app/L.java",
                'Log.e(TAG, "auth_token=" + token);\n'
            )
            report = audit_code(root, _meta())
            self.assertEqual(
                len([f for f in report.findings if f.rule_id == "CODE-004"]), 1
            )

    def test_logw_with_apikey(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_java(root, "com/example/app/L.java",
                'Log.w(TAG, "fail with api_key=" + key);\n'
            )
            report = audit_code(root, _meta())
            self.assertEqual(
                len([f for f in report.findings if f.rule_id == "CODE-004"]), 1
            )

    def test_log_without_credential_keyword_does_not_trigger(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_java(root, "com/example/app/L.java",
                'Log.d(TAG, "user logged in");\n'
            )
            report = audit_code(root, _meta())
            self.assertEqual(
                [f for f in report.findings if f.rule_id == "CODE-004"], []
            )

    def test_credential_keyword_outside_log_does_not_trigger(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_java(root, "com/example/app/L.java",
                'String password = preferences.getString("password", null);\n'
            )
            report = audit_code(root, _meta())
            self.assertEqual(
                [f for f in report.findings if f.rule_id == "CODE-004"], []
            )

    def test_fully_qualified_log_call(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_java(root, "com/example/app/L.java",
                'android.util.Log.d(TAG, "secret=" + s);\n'
            )
            report = audit_code(root, _meta())
            self.assertEqual(
                len([f for f in report.findings if f.rule_id == "CODE-004"]), 1
            )


# ---------- CODE-005 external storage ----------


class ExternalStorageRuleTests(unittest.TestCase):
    def test_get_external_storage_directory(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_java(root, "com/example/app/S.java",
                "File f = Environment.getExternalStorageDirectory();\n"
            )
            report = audit_code(root, _meta())
            findings = [f for f in report.findings if f.rule_id == "CODE-005"]
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].severity, "medium")

    def test_get_external_files_dir(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_java(root, "com/example/app/S.java",
                'File f = ctx.getExternalFilesDir(null);\n'
            )
            report = audit_code(root, _meta())
            self.assertEqual(
                len([f for f in report.findings if f.rule_id == "CODE-005"]), 1
            )

    def test_internal_storage_does_not_trigger(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_java(root, "com/example/app/S.java",
                "File f = ctx.getFilesDir();\n"
            )
            report = audit_code(root, _meta())
            self.assertEqual(
                [f for f in report.findings if f.rule_id == "CODE-005"], []
            )


# ---------- CODE-006 MODE_WORLD ----------


class ModeWorldRuleTests(unittest.TestCase):
    def test_mode_world_readable(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_java(root, "com/example/app/M.java",
                'openFileOutput("creds.txt", Context.MODE_WORLD_READABLE);\n'
            )
            report = audit_code(root, _meta())
            findings = [f for f in report.findings if f.rule_id == "CODE-006"]
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].severity, "high")
            self.assertIn("MODE_WORLD_READABLE", findings[0].title)

    def test_mode_world_writeable(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_java(root, "com/example/app/M.java",
                'openFileOutput("creds.txt", Context.MODE_WORLD_WRITEABLE);\n'
            )
            report = audit_code(root, _meta())
            self.assertEqual(
                len([f for f in report.findings if f.rule_id == "CODE-006"]), 1
            )

    def test_mode_private_does_not_trigger(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_java(root, "com/example/app/M.java",
                'openFileOutput("safe.txt", Context.MODE_PRIVATE);\n'
            )
            report = audit_code(root, _meta())
            self.assertEqual(
                [f for f in report.findings if f.rule_id == "CODE-006"], []
            )


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


class DedupFindingsByClassTests(unittest.TestCase):
    """Phase 11-1: collapse same (rule_id, class_fqn) into representative+occurrences."""

    def _f(self, rule_id="CODE-001", cls="com.x.A", line=1, file="x.java",
           text="t", tier="java") -> CodeFinding:
        return CodeFinding(
            rule_id=rule_id, title="t", severity="medium",
            file=file, line_no=line, line_text=text,
            class_fqn=cls, evidence_tier=tier,
        )

    def test_empty_input(self):
        self.assertEqual(dedup_findings_by_class([]), [])

    def test_distinct_classes_kept_separate(self):
        f1 = self._f(cls="com.x.A")
        f2 = self._f(cls="com.x.B")
        out = dedup_findings_by_class([f1, f2])
        self.assertEqual(len(out), 2)
        self.assertEqual(out[0].occurrences, [])
        self.assertEqual(out[1].occurrences, [])

    def test_distinct_rules_kept_separate(self):
        f1 = self._f(rule_id="CODE-001", cls="com.x.A")
        f2 = self._f(rule_id="CODE-003", cls="com.x.A")
        out = dedup_findings_by_class([f1, f2])
        self.assertEqual(len(out), 2)

    def test_same_class_same_rule_collapses(self):
        f1 = self._f(line=10, text="http://a.test")
        f2 = self._f(line=20, text="http://b.test")
        f3 = self._f(line=30, text="http://c.test")
        out = dedup_findings_by_class([f1, f2, f3])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].line_no, 10)  # representative is first
        self.assertEqual(len(out[0].occurrences), 2)
        self.assertEqual([o.line_no for o in out[0].occurrences], [20, 30])
        self.assertEqual(out[0].occurrences[0].line_text, "http://b.test")
        # occurrence_count = primary + extras
        self.assertEqual(out[0].occurrence_count, 3)

    def test_dedup_does_not_mutate_inputs(self):
        f1 = self._f(line=10, text="http://a.test")
        f2 = self._f(line=20, text="http://b.test")
        out1 = dedup_findings_by_class([f1, f2])
        out2 = dedup_findings_by_class([f1, f2])

        self.assertIsNot(out1[0], f1)
        self.assertEqual(f1.occurrences, [])
        self.assertEqual(f2.occurrences, [])
        self.assertEqual(out1[0].occurrence_count, 2)
        self.assertEqual(out2[0].occurrence_count, 2)

    def test_same_class_same_line_not_duplicated(self):
        """Two rules firing on the same line still create one occurrence,
        and a single rule firing twice on the same line (defensive case)
        is folded down to the primary only.
        """
        f1 = self._f(line=10, text="x")
        f2 = self._f(line=10, text="x")  # exact duplicate
        out = dedup_findings_by_class([f1, f2])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].occurrences, [])

    def test_empty_class_fqn_falls_back_to_file(self):
        f1 = self._f(cls="", file="A.java", line=10)
        f2 = self._f(cls="", file="A.java", line=20)
        f3 = self._f(cls="", file="B.java", line=10)
        out = dedup_findings_by_class([f1, f2, f3])
        # A.java group + B.java group
        self.assertEqual(len(out), 2)
        a_group = next(f for f in out if f.file == "A.java")
        self.assertEqual(len(a_group.occurrences), 1)

    def test_evidence_tier_preserved_in_occurrence(self):
        f1 = self._f(line=10, tier="java")
        f2 = self._f(line=20, tier="smali")
        out = dedup_findings_by_class([f1, f2])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].evidence_tier, "java")
        self.assertEqual(out[0].occurrences[0].evidence_tier, "smali")

    def test_codefinding_to_from_dict_round_trips_occurrences(self):
        f = self._f(line=10)
        f.occurrences.append(CodeOccurrence(line_no=20, line_text="more"))
        f.occurrences.append(CodeOccurrence(line_no=30, line_text="more2",
                                            evidence_tier="smali"))
        rt = CodeFinding.from_dict(f.to_dict())
        self.assertEqual(len(rt.occurrences), 2)
        self.assertEqual(rt.occurrences[0].line_no, 20)
        self.assertEqual(rt.occurrences[1].evidence_tier, "smali")

    def test_audit_code_dedups_in_real_pipeline(self):
        """audit_code() at module level returns the deduped report."""
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            src = Path(td)
            # Two http URLs in one class → after audit_code, 1 finding +
            # 1 occurrence rather than 2 separate findings.
            (src / "com" / "demo" / "app").mkdir(parents=True)
            (src / "com" / "demo" / "app" / "Net.java").write_text(
                "package com.demo.app;\n"
                "class Net {\n"
                "  String a = \"http://a.test/\";\n"
                "  String b = \"http://b.test/\";\n"
                "}\n"
            )
            report = audit_code(
                src, AndroidAppMeta(
                    package_name="com.demo.app",
                    application_class=None, permissions=[], components=[],
                ),
            )
            http_findings = [f for f in report.findings if f.rule_id == "CODE-001"]
            self.assertEqual(len(http_findings), 1)
            self.assertEqual(http_findings[0].occurrence_count, 2)


if __name__ == "__main__":
    unittest.main()

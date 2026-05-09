"""Tests for venomhook.audit_html_report — self-contained HTML report.

Covers:
    * render_audit_html produces valid (well-formed enough) HTML with
      every key section.
    * Severity classes appear on finding cards.
    * Findings are ordered critical -> info.
    * PoCs are embedded inside their parent finding's card via the
      (rule_id, component) join — not in a separate orphan list.
    * write_audit_html writes a UTF-8 file and links PoCs relative to
      its parent directory when ``poc_bundle_dir`` is provided.
    * HTML escape protects against component-name / string-derived
      injection.

All synthetic data — no apktool, no jadx, no lief, no network.
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from venomhook.android_pipeline import AndroidAnalysis
from venomhook.apk_extractor import ApkMeta
from venomhook.audit_html_report import render_audit_html, write_audit_html
from venomhook.models import (
    AndroidAppMeta,
    AndroidAuditReport,
    AndroidComponent,
    CodeAuditReport,
    CodeFinding,
    JavaNativeMethod,
    JniBridge,
    ManifestFinding,
    PoCArtifact,
)
from venomhook.native_strings import NativeStringHints


def _stub_apk(hash_: str = "sha256:deadbeefcafef00d") -> ApkMeta:
    return ApkMeta(
        path=f"/sample/{hash_[-8:]}.apk",
        name=f"{hash_[-8:]}.apk",
        hash=hash_,
        abis=["arm64-v8a"],
        native_libs={"arm64-v8a": ["libfoo.so"]},
    )


def _stub_app() -> AndroidAppMeta:
    return AndroidAppMeta(
        package_name="com.demo.bank",
        debuggable=True,
        allow_backup=True,
        permissions=["android.permission.INTERNET"],
        components=[
            AndroidComponent(
                type="activity",
                name="com.demo.bank.LoginActivity",
                exported=True,
                permission=None,
                intent_actions=["android.intent.action.MAIN"],
            ),
            AndroidComponent(
                type="provider",
                name="com.demo.bank.TrackUserProvider",
                exported=True,
                grant_uri_permissions=True,
            ),
        ],
    )


def _stub_findings() -> list[ManifestFinding]:
    return [
        ManifestFinding(
            rule_id="MANIFEST-001", title="Debuggable Application",
            severity="high",
            detail="The application is debuggable in production.",
            remediation="Set android:debuggable=\"false\" before release.",
            component=None,
            references=["OWASP MASVS-RESILIENCE-1", "CWE-489"],
        ),
        ManifestFinding(
            rule_id="MANIFEST-004", title="Exported activity",
            severity="high",
            detail="exported component without permission attribute",
            component="com.demo.bank.LoginActivity",
            references=["OWASP MASVS-PLATFORM-1"],
        ),
        ManifestFinding(
            rule_id="MANIFEST-007", title="Dangerous permission surface",
            severity="info",
            detail="0 dangerous permissions",
        ),
    ]


def _stub_pocs() -> list[PoCArtifact]:
    return [
        PoCArtifact(
            rule_id="MANIFEST-001", title="Attach jdb",
            severity="high", kind="adb",
            package_name="com.demo.bank",
            description="Attach jdb to a debuggable process.",
            commands=["adb shell setprop ...", "jdb -attach localhost:8700"],
            references=["OWASP MASVS-RESILIENCE-1"],
        ),
        PoCArtifact(
            rule_id="MANIFEST-001", title="Read app data via run-as",
            severity="high", kind="adb",
            package_name="com.demo.bank",
            commands=["adb shell run-as com.demo.bank ls /data/data/..."],
        ),
        PoCArtifact(
            rule_id="MANIFEST-004", title="Invoke exported activity",
            severity="high", kind="adb",
            package_name="com.demo.bank",
            component="com.demo.bank.LoginActivity",
            commands=["adb shell am start -n com.demo.bank/.LoginActivity"],
        ),
        PoCArtifact(
            rule_id="MANIFEST-004", title="Observe intents via Frida",
            severity="high", kind="frida",
            package_name="com.demo.bank",
            component="com.demo.bank.LoginActivity",
            commands=["Java.perform(() => { /* hook */ });"],
        ),
    ]


def _stub_analysis(*, with_pocs: bool = True) -> AndroidAnalysis:
    return AndroidAnalysis(
        apk_meta=_stub_apk(),
        selected_abi="arm64-v8a",
        extracted_so_path=None,
        so_meta=None,
        app_meta=_stub_app(),
        java_natives=[],
        bridges=[],
        audit_report=AndroidAuditReport(
            package_name="com.demo.bank",
            findings=_stub_findings(),
        ),
        pocs=_stub_pocs() if with_pocs else [],
        warnings=["sample warning emitted by stub"],
    )


# ---------- structural ----------


class RenderStructureTest(unittest.TestCase):
    def test_html_doctype_and_charset(self) -> None:
        html = render_audit_html(_stub_analysis())
        self.assertIn("<!doctype html>", html)
        self.assertIn('<meta charset="utf-8">', html)
        self.assertIn("</html>", html)

    def test_inlined_style_no_external_assets(self) -> None:
        html = render_audit_html(_stub_analysis())
        # CSS is in a <style> block; no <link rel=stylesheet>, no <script>
        self.assertIn("<style>", html)
        self.assertNotIn("<link rel", html)
        self.assertNotIn("<script", html)

    def test_summary_section_includes_apk_metadata(self) -> None:
        html = render_audit_html(_stub_analysis())
        self.assertIn("com.demo.bank", html)
        self.assertIn("sha256:deadbeefcafef00d", html)
        self.assertIn("arm64-v8a", html)

    def test_warnings_block_present(self) -> None:
        html = render_audit_html(_stub_analysis())
        self.assertIn("sample warning emitted by stub", html)

    def test_components_section_renders_table(self) -> None:
        html = render_audit_html(_stub_analysis())
        self.assertIn("컴포넌트 (2개)", html)
        self.assertIn("com.demo.bank.LoginActivity", html)
        self.assertIn("com.demo.bank.TrackUserProvider", html)


# ---------- findings ----------


class FindingCardsTest(unittest.TestCase):
    def test_each_finding_has_severity_class(self) -> None:
        html = render_audit_html(_stub_analysis())
        # Two HIGH cards + one INFO card
        self.assertGreaterEqual(html.count('class="finding sev-high"'), 2)
        self.assertGreaterEqual(html.count('class="finding sev-info"'), 1)

    def test_findings_ordered_critical_to_info(self) -> None:
        html = render_audit_html(_stub_analysis())
        i_high = html.find("MANIFEST-001")
        i_info = html.find("MANIFEST-007")
        self.assertGreater(i_info, i_high,
                           "INFO finding should appear after HIGH findings")

    def test_finding_includes_detail_and_remediation(self) -> None:
        html = render_audit_html(_stub_analysis())
        self.assertIn("debuggable in production", html)
        self.assertIn("android:debuggable", html)

    def test_finding_includes_references(self) -> None:
        html = render_audit_html(_stub_analysis())
        self.assertIn("OWASP MASVS-RESILIENCE-1", html)
        self.assertIn("CWE-489", html)


# ---------- PoC linkage ----------


class PoCEmbeddingTest(unittest.TestCase):
    def test_pocs_grouped_under_their_finding(self) -> None:
        html = render_audit_html(_stub_analysis())
        # Locate the MANIFEST-004 LoginActivity card and check that its
        # two PoCs (Invoke + Frida) appear *within* it (i.e., before
        # the next finding card starts).
        marker = "com.demo.bank.LoginActivity"
        i_card = html.find(marker)
        self.assertNotEqual(i_card, -1)
        # The card extends until the next <article tag opening.
        next_card = html.find("<article", i_card + 1)
        card_html = html[i_card:next_card] if next_card != -1 else html[i_card:]
        self.assertIn("Invoke exported activity", card_html)
        self.assertIn("Observe intents via Frida", card_html)
        # 개념 증명 카운트 헤더
        self.assertIn("개념 증명(PoC) 2건", card_html)

    def test_finding_with_no_poc_renders_zero_poc_section(self) -> None:
        # MANIFEST-007 has no matching PoC in our stub
        html = render_audit_html(_stub_analysis())
        i007 = html.find("MANIFEST-007")
        self.assertNotEqual(i007, -1)
        next_section = html.find("</section>", i007)
        card_tail = html[i007:next_section]
        self.assertIn("개념 증명(PoC) 0건", card_tail)
        self.assertIn("수동 검토가 필요합니다", card_tail)

    def test_poc_command_text_embedded(self) -> None:
        html = render_audit_html(_stub_analysis())
        self.assertIn("am start -n com.demo.bank", html)
        self.assertIn("Java.perform", html)

    def test_poc_links_relative_to_html_directory(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            out_html = Path(td) / "report" / "audit.html"
            bundle = Path(td) / "report" / "pocs"
            html = render_audit_html(
                _stub_analysis(),
                poc_bundle_dir=bundle,
                out_path=out_html,
            )
            # PoCs in the same directory; href is the bare filename.
            self.assertIn('href="pocs/MANIFEST-001-1', html)

    def test_poc_links_omitted_when_no_bundle_dir(self) -> None:
        html = render_audit_html(_stub_analysis())
        # No bundle dir -> no file links rendered (the class is "file-link")
        self.assertNotIn('class="file-link"', html)


# ---------- escape ----------


class EscapeTest(unittest.TestCase):
    def test_component_name_with_brackets_escaped(self) -> None:
        # Synthesize a finding whose component string contains markup.
        analysis = _stub_analysis()
        analysis.audit_report.findings.append(
            ManifestFinding(
                rule_id="X",
                title="<script>alert(1)</script>",
                severity="high",
                detail="<img onerror=alert(1)>",
                component="<b>BAD</b>",
            )
        )
        html = render_audit_html(analysis)
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertNotIn("<img onerror", html)
        self.assertIn("&lt;script&gt;", html)


# ---------- write ----------


class WriteAuditHtmlTest(unittest.TestCase):
    def test_writes_file_and_returns_path(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "x" / "audit.html"
            result = write_audit_html(_stub_analysis(), out)
            self.assertEqual(result, out)
            self.assertTrue(out.exists())
            text = out.read_text(encoding="utf-8")
            self.assertIn("VenomHook 감사 보고서", text)
            self.assertIn("MANIFEST-001", text)


# ---------- bridges ----------


class BridgesSectionTest(unittest.TestCase):
    def test_bridges_section_appears_when_any(self) -> None:
        analysis = _stub_analysis()
        analysis.bridges.append(
            JniBridge(
                java_method=JavaNativeMethod(
                    class_fqn="com.demo.bank.Crypto",
                    method_name="encrypt",
                    return_type="byte[]",
                    arg_types=["byte[]", "byte[]"],
                ),
                predicted_short="Java_com_demo_bank_Crypto_encrypt",
                matched_symbol="Java_com_demo_bank_Crypto_encrypt",
            )
        )
        html = render_audit_html(analysis)
        self.assertIn("JNI 브리지", html)
        self.assertIn("com.demo.bank.Crypto.encrypt", html)
        self.assertIn("Java_com_demo_bank_Crypto_encrypt", html)

    def test_bridges_section_omitted_when_empty(self) -> None:
        html = render_audit_html(_stub_analysis())
        self.assertNotIn("JNI 브리지", html)


# ---------- Phase 7-5 — code findings + native strings ----------


def _analysis_with_code_findings(
    *, code_findings: list[CodeFinding] | None = None,
    code_pocs: list[PoCArtifact] | None = None,
    hints: NativeStringHints | None = None,
) -> AndroidAnalysis:
    base = _stub_analysis(with_pocs=False)
    base.code_audit_report = CodeAuditReport(
        package_name="com.demo.bank",
        findings=list(code_findings or []),
        files_scanned=12,
    )
    base.native_string_hints = hints
    if code_pocs:
        base.pocs = list(base.pocs) + list(code_pocs)
    return base


class CodeFindingsSectionTest(unittest.TestCase):
    def test_section_omitted_when_no_code_findings(self) -> None:
        html = render_audit_html(_stub_analysis())
        self.assertNotIn("코드 감사", html)

    def test_section_renders_with_files_scanned_count(self) -> None:
        analysis = _analysis_with_code_findings(code_findings=[
            CodeFinding(
                rule_id="CODE-001", title="평문 HTTP",
                severity="high", file="com/x/A.java", line_no=12,
                line_text='String url = "http://api/x";',
                class_fqn="com.x.A",
                detail="d", remediation="r",
                references=["CWE-319"],
            ),
        ])
        html = render_audit_html(analysis)
        self.assertIn("코드 감사", html)
        self.assertIn("스캔 12개 파일", html)
        self.assertIn("com/x/A.java:12", html)
        self.assertIn("CWE-319", html)
        # The literal evidence line is rendered inside a <code> block
        self.assertIn("<code>", html)

    def test_code_findings_ordered_critical_to_info(self) -> None:
        analysis = _analysis_with_code_findings(code_findings=[
            CodeFinding(rule_id="CODE-005", title="ext storage",
                        severity="medium", file="a.java"),
            CodeFinding(rule_id="CODE-003", title="weak crypto",
                        severity="high", file="b.java"),
            CodeFinding(rule_id="CODE-007", title="info",
                        severity="info", file="c.java"),
        ])
        html = render_audit_html(analysis)
        i_high = html.find("weak crypto")
        i_medium = html.find("ext storage")
        i_info = html.find("CODE-007")
        self.assertGreater(i_medium, i_high)
        self.assertGreater(i_info, i_medium)

    def test_code_pocs_embedded_via_class_fqn(self) -> None:
        finding = CodeFinding(
            rule_id="CODE-002", title="WebView JS",
            severity="medium", file="com/x/W.java", line_no=25,
            class_fqn="com.x.W",
        )
        # PoC for the same (rule_id, class_fqn) — should embed inside the card
        poc = PoCArtifact(
            rule_id="CODE-002", title="Frida WebView observer",
            severity="medium", kind="frida",
            package_name="com.demo.bank",
            component="com.x.W",
            commands=["Java.perform(() => { /* hook */ });"],
        )
        analysis = _analysis_with_code_findings(
            code_findings=[finding],
            code_pocs=[poc],
        )
        html = render_audit_html(analysis)
        self.assertIn("Frida WebView observer", html)
        # The PoC count badge appears inside the card
        self.assertIn("개념 증명(PoC) 1건", html)


class NativeStringsSectionTest(unittest.TestCase):
    def test_section_omitted_when_hints_none(self) -> None:
        analysis = _stub_analysis()
        analysis.native_string_hints = None
        html = render_audit_html(analysis)
        self.assertNotIn("네이티브 라이브러리 문자열 단서", html)

    def test_section_omitted_when_hints_empty(self) -> None:
        analysis = _analysis_with_code_findings(hints=NativeStringHints())
        html = render_audit_html(analysis)
        self.assertNotIn("네이티브 라이브러리 문자열 단서", html)

    def test_section_renders_buckets_with_counts(self) -> None:
        analysis = _analysis_with_code_findings(hints=NativeStringHints(
            urls=["https://api.example.com/x", "http://10.1.2.3/cb"],
            crypto=["AES/CBC", "MD5"],
            paths=["/system/bin/sh"],
        ))
        html = render_audit_html(analysis)
        self.assertIn("네이티브 라이브러리 문자열 단서", html)
        self.assertIn("URL 임베디드 (2건)", html)
        self.assertIn("Crypto 알고리즘 단서 (2건)", html)
        self.assertIn("민감 경로 (1건)", html)
        self.assertIn("https://api.example.com/x", html)

    def test_long_bucket_truncates_with_more_indicator(self) -> None:
        # 25 items -> 20 visible + "외 5개 더" indicator
        analysis = _analysis_with_code_findings(hints=NativeStringHints(
            urls=[f"https://h{i}.example/" for i in range(25)],
        ))
        html = render_audit_html(analysis)
        self.assertIn("URL 임베디드 (25건)", html)
        self.assertIn("외 5개 더", html)


if __name__ == "__main__":
    unittest.main()

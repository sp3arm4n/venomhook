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
    JavaNativeMethod,
    JniBridge,
    ManifestFinding,
    PoCArtifact,
)


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
        self.assertIn("Components (2)", html)
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
        # Proof-of-Concept (2) header
        self.assertIn("Proof-of-Concept (2)", card_html)

    def test_finding_with_no_poc_renders_zero_poc_section(self) -> None:
        # MANIFEST-007 has no matching PoC in our stub
        html = render_audit_html(_stub_analysis())
        i007 = html.find("MANIFEST-007")
        self.assertNotEqual(i007, -1)
        next_section = html.find("</section>", i007)
        card_tail = html[i007:next_section]
        self.assertIn("Proof-of-Concept (0)", card_tail)
        self.assertIn("Manual review required", card_tail)

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
            self.assertIn("VenomHook Audit Report", text)
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
        self.assertIn("JNI Bridges", html)
        self.assertIn("com.demo.bank.Crypto.encrypt", html)
        self.assertIn("Java_com_demo_bank_Crypto_encrypt", html)

    def test_bridges_section_omitted_when_empty(self) -> None:
        html = render_audit_html(_stub_analysis())
        self.assertNotIn("JNI Bridges", html)


if __name__ == "__main__":
    unittest.main()

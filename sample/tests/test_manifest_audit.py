"""Tests for manifest_audit — rule engine over AndroidAppMeta.

Each rule has positive (triggers), negative (does not trigger), and edge
cases. Synthetic AndroidAppMeta objects keep tests pure-Python with no
external tool dependency.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from venomhook.manifest_audit import (
    DANGEROUS_PERMISSIONS,
    MIN_RECOMMENDED_MIN_SDK,
    MIN_RECOMMENDED_TARGET_SDK,
    RULES,
    SEV_HIGH,
    SEV_INFO,
    SEV_MEDIUM,
    audit_manifest,
    format_audit_summary,
)
from venomhook.models import (
    AndroidAppMeta,
    AndroidAuditReport,
    AndroidComponent,
    ManifestFinding,
    NetworkSecurityConfigMeta,
)


def _meta(**overrides) -> AndroidAppMeta:
    base = dict(
        package_name="com.x",
        application_class=None,
        permissions=[],
        components=[],
        min_sdk=30,
        target_sdk=33,
        debuggable=False,
        extract_native_libs=None,
        uses_cleartext_traffic=False,
        allow_backup=False,
        network_security_config=None,
    )
    base.update(overrides)
    return AndroidAppMeta(**base)


def _comp(**overrides) -> AndroidComponent:
    base = dict(type="activity", name="com.x.A", exported=False)
    base.update(overrides)
    return AndroidComponent(**base)


def _ids(report: AndroidAuditReport) -> list[str]:
    return [f.rule_id for f in report.findings]


# ---------- MANIFEST-001 Debuggable ----------


class TestDebuggable(unittest.TestCase):
    def test_triggers_when_debuggable_true(self):
        report = audit_manifest(_meta(debuggable=True))
        self.assertIn("MANIFEST-001", _ids(report))

    def test_severity_is_high(self):
        report = audit_manifest(_meta(debuggable=True))
        finding = next(f for f in report.findings if f.rule_id == "MANIFEST-001")
        self.assertEqual(finding.severity, SEV_HIGH)

    def test_does_not_trigger_when_false(self):
        report = audit_manifest(_meta(debuggable=False))
        self.assertNotIn("MANIFEST-001", _ids(report))


# ---------- MANIFEST-002 Cleartext Traffic ----------


class TestCleartextTraffic(unittest.TestCase):
    def test_explicit_true_triggers(self):
        report = audit_manifest(_meta(uses_cleartext_traffic=True))
        self.assertIn("MANIFEST-002", _ids(report))

    def test_explicit_false_does_not_trigger(self):
        report = audit_manifest(_meta(uses_cleartext_traffic=False, target_sdk=21))
        # Even with old targetSdk, explicit false wins
        self.assertNotIn("MANIFEST-002", _ids(report))

    def test_unset_with_target_sdk_below_28_triggers(self):
        report = audit_manifest(_meta(uses_cleartext_traffic=None, target_sdk=27))
        self.assertIn("MANIFEST-002", _ids(report))

    def test_unset_with_target_sdk_28_does_not_trigger(self):
        report = audit_manifest(_meta(uses_cleartext_traffic=None, target_sdk=28))
        self.assertNotIn("MANIFEST-002", _ids(report))

    def test_unset_with_network_security_config_does_not_trigger(self):
        # NSC takes responsibility for cleartext policy — don't double-flag
        report = audit_manifest(_meta(
            uses_cleartext_traffic=None,
            target_sdk=21,
            network_security_config="@xml/nsc",
        ))
        self.assertNotIn("MANIFEST-002", _ids(report))


# ---------- MANIFEST-002 NSC-aware variants (Phase 6-2) ----------


class TestCleartextTrafficNSC(unittest.TestCase):
    def test_nsc_base_cleartext_true_triggers_high(self):
        report = audit_manifest(_meta(
            uses_cleartext_traffic=None,
            target_sdk=33,                       # modern SDK; safe by default
            network_security_config="@xml/nsc",
            nsc=NetworkSecurityConfigMeta(base_cleartext_permitted=True),
        ))
        m002 = [f for f in report.findings if f.rule_id == "MANIFEST-002"]
        self.assertEqual(len(m002), 1)
        self.assertEqual(m002[0].severity, SEV_HIGH)
        self.assertIn("base-config", m002[0].title)

    def test_nsc_base_cleartext_false_does_not_trigger(self):
        report = audit_manifest(_meta(
            uses_cleartext_traffic=None,
            target_sdk=21,                       # old, but NSC explicitly says no
            network_security_config="@xml/nsc",
            nsc=NetworkSecurityConfigMeta(base_cleartext_permitted=False),
        ))
        self.assertNotIn("MANIFEST-002", _ids(report))

    def test_nsc_cleartext_domains_trigger_medium(self):
        report = audit_manifest(_meta(
            uses_cleartext_traffic=None,
            target_sdk=33,
            network_security_config="@xml/nsc",
            nsc=NetworkSecurityConfigMeta(
                base_cleartext_permitted=False,
                cleartext_domains=["legacy.example.com", "ocsp.example.org"],
            ),
        ))
        m002 = [f for f in report.findings if f.rule_id == "MANIFEST-002"]
        self.assertEqual(len(m002), 1)
        self.assertEqual(m002[0].severity, SEV_MEDIUM)
        self.assertIn("legacy.example.com", m002[0].detail)

    def test_nsc_base_cleartext_and_domains_emit_two_findings(self):
        # Pentest perspective: an APK can have both — base-config opens
        # everything AND domain-config redundantly lists hosts. Both should
        # surface so the report shows the full attack surface.
        report = audit_manifest(_meta(
            uses_cleartext_traffic=None,
            target_sdk=33,
            network_security_config="@xml/nsc",
            nsc=NetworkSecurityConfigMeta(
                base_cleartext_permitted=True,
                cleartext_domains=["a.test"],
            ),
        ))
        m002 = [f for f in report.findings if f.rule_id == "MANIFEST-002"]
        self.assertEqual(len(m002), 2)
        sevs = sorted(f.severity for f in m002)
        self.assertEqual(sevs, [SEV_HIGH, SEV_MEDIUM])

    def test_explicit_uses_cleartext_and_nsc_both_emit(self):
        # Belt and suspenders — old usesCleartextTraffic AND a permissive NSC.
        # Both findings stay so the developer sees both hooks they'd need to
        # close.
        report = audit_manifest(_meta(
            uses_cleartext_traffic=True,
            target_sdk=33,
            network_security_config="@xml/nsc",
            nsc=NetworkSecurityConfigMeta(base_cleartext_permitted=True),
        ))
        m002 = [f for f in report.findings if f.rule_id == "MANIFEST-002"]
        self.assertEqual(len(m002), 2)
        titles = {f.title for f in m002}
        self.assertTrue(any("명시적" in t for t in titles))
        self.assertTrue(any("base-config" in t for t in titles))

    def test_long_domain_list_truncates_in_detail(self):
        domains = [f"d{i}.example" for i in range(8)]
        report = audit_manifest(_meta(
            uses_cleartext_traffic=None,
            target_sdk=33,
            network_security_config="@xml/nsc",
            nsc=NetworkSecurityConfigMeta(
                base_cleartext_permitted=False,
                cleartext_domains=domains,
            ),
        ))
        m002 = [f for f in report.findings if f.rule_id == "MANIFEST-002"]
        self.assertEqual(len(m002), 1)
        # Title carries total count; detail truncates after first 5
        self.assertIn("(8개)", m002[0].title)
        self.assertIn("외 3개 더", m002[0].detail)


# ---------- MANIFEST-003 Allow Backup ----------


class TestAllowBackup(unittest.TestCase):
    def test_explicit_true_triggers(self):
        report = audit_manifest(_meta(allow_backup=True, target_sdk=33))
        self.assertIn("MANIFEST-003", _ids(report))

    def test_explicit_false_does_not_trigger(self):
        report = audit_manifest(_meta(allow_backup=False, target_sdk=21))
        self.assertNotIn("MANIFEST-003", _ids(report))

    def test_unset_with_target_sdk_below_31_triggers(self):
        report = audit_manifest(_meta(allow_backup=None, target_sdk=30))
        self.assertIn("MANIFEST-003", _ids(report))

    def test_unset_with_target_sdk_31_does_not_trigger(self):
        report = audit_manifest(_meta(allow_backup=None, target_sdk=31))
        self.assertNotIn("MANIFEST-003", _ids(report))

    def test_unset_with_no_target_sdk_triggers(self):
        # Without target_sdk we err on the side of warning
        report = audit_manifest(_meta(allow_backup=None, target_sdk=None))
        self.assertIn("MANIFEST-003", _ids(report))


# ---------- MANIFEST-004 Exported without Permission ----------


class TestExportedNoPermission(unittest.TestCase):
    def test_exported_activity_with_intent_no_permission_triggers(self):
        report = audit_manifest(_meta(components=[
            _comp(exported=True, intent_actions=["android.intent.action.MAIN"]),
        ]))
        self.assertIn("MANIFEST-004", _ids(report))

    def test_exported_with_permission_does_not_trigger(self):
        report = audit_manifest(_meta(components=[
            _comp(exported=True, intent_actions=["x"], permission="com.x.PERM"),
        ]))
        self.assertNotIn("MANIFEST-004", _ids(report))

    def test_exported_without_intent_actions_does_not_trigger(self):
        report = audit_manifest(_meta(components=[
            _comp(exported=True, intent_actions=[]),
        ]))
        # Activities without intent-filter aren't externally addressable
        # by intent matching; fewer auto-attack vectors → don't flag here.
        self.assertNotIn("MANIFEST-004", _ids(report))

    def test_absent_exported_with_intent_filter_triggers(self):
        report = audit_manifest(_meta(components=[
            _comp(exported=False, exported_declared=False, intent_actions=["x"]),
        ]))
        self.assertIn("MANIFEST-004", _ids(report))

    def test_provider_skipped_here(self):
        # Providers covered by MANIFEST-005, not double-counted
        report = audit_manifest(_meta(components=[
            _comp(type="provider", name="com.x.P", exported=True, intent_actions=[]),
        ]))
        self.assertNotIn("MANIFEST-004", _ids(report))

    def test_finding_carries_component_name(self):
        report = audit_manifest(_meta(components=[
            _comp(name="com.x.MainActivity", exported=True, intent_actions=["x"]),
        ]))
        finding = next(f for f in report.findings if f.rule_id == "MANIFEST-004")
        self.assertEqual(finding.component, "com.x.MainActivity")

    def test_multiple_offenders_yield_multiple_findings(self):
        report = audit_manifest(_meta(components=[
            _comp(name="A", exported=True, intent_actions=["a"]),
            _comp(name="B", exported=True, intent_actions=["b"]),
        ]))
        ids = _ids(report)
        self.assertEqual(ids.count("MANIFEST-004"), 2)


# ---------- MANIFEST-005 Exported Provider ----------


class TestExportedProvider(unittest.TestCase):
    def test_exported_provider_triggers(self):
        report = audit_manifest(_meta(components=[
            _comp(type="provider", name="com.x.P", exported=True),
        ]))
        self.assertIn("MANIFEST-005", _ids(report))

    def test_non_exported_provider_does_not_trigger(self):
        report = audit_manifest(_meta(components=[
            _comp(type="provider", name="com.x.P", exported=False),
        ]))
        self.assertNotIn("MANIFEST-005", _ids(report))

    def test_provider_with_permission_still_flagged(self):
        # Permissions can be obtained by malicious apps with the right
        # protectionLevel; flag stays high but detail mentions guard
        report = audit_manifest(_meta(components=[
            _comp(type="provider", name="com.x.P", exported=True, permission="com.x.PERM"),
        ]))
        finding = next(f for f in report.findings if f.rule_id == "MANIFEST-005")
        self.assertIn("권한", finding.detail)

    def test_absent_exported_provider_legacy_target_triggers(self):
        report = audit_manifest(_meta(target_sdk=16, components=[
            _comp(type="provider", name="com.x.P", exported=False, exported_declared=False),
        ]))
        self.assertIn("MANIFEST-005", _ids(report))

    def test_absent_exported_provider_modern_target_does_not_trigger(self):
        report = audit_manifest(_meta(target_sdk=17, components=[
            _comp(type="provider", name="com.x.P", exported=False, exported_declared=False),
        ]))
        self.assertNotIn("MANIFEST-005", _ids(report))


# ---------- MANIFEST-006 grantUriPermissions ----------


class TestGrantUriPermissions(unittest.TestCase):
    def test_provider_with_grant_uri_triggers(self):
        report = audit_manifest(_meta(components=[
            _comp(type="provider", name="com.x.P", grant_uri_permissions=True),
        ]))
        self.assertIn("MANIFEST-006", _ids(report))

    def test_non_provider_does_not_trigger(self):
        # Activities can't actually grant URI permissions; rule is provider-only
        report = audit_manifest(_meta(components=[
            _comp(type="activity", name="com.x.A", grant_uri_permissions=True),
        ]))
        self.assertNotIn("MANIFEST-006", _ids(report))


# ---------- MANIFEST-007 Dangerous Permissions ----------


class TestDangerousPermissions(unittest.TestCase):
    def test_dangerous_permission_triggers_info(self):
        report = audit_manifest(_meta(permissions=[
            "android.permission.READ_SMS",
        ]))
        finding = next(f for f in report.findings if f.rule_id == "MANIFEST-007")
        self.assertEqual(finding.severity, SEV_INFO)

    def test_no_dangerous_permission_does_not_trigger(self):
        report = audit_manifest(_meta(permissions=[
            "android.permission.INTERNET",  # normal protectionLevel
        ]))
        self.assertNotIn("MANIFEST-007", _ids(report))

    def test_multiple_dangerous_permissions_one_finding(self):
        # One aggregate finding listing all risky perms; not one finding per perm
        report = audit_manifest(_meta(permissions=[
            "android.permission.READ_SMS",
            "android.permission.RECORD_AUDIO",
            "android.permission.CAMERA",
        ]))
        ids = _ids(report)
        self.assertEqual(ids.count("MANIFEST-007"), 1)
        finding = next(f for f in report.findings if f.rule_id == "MANIFEST-007")
        self.assertIn("READ_SMS", finding.detail)
        self.assertIn("CAMERA", finding.detail)

    def test_dangerous_set_includes_known_perms(self):
        for p in [
            "android.permission.READ_SMS",
            "android.permission.RECORD_AUDIO",
            "android.permission.CAMERA",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.READ_CONTACTS",
        ]:
            self.assertIn(p, DANGEROUS_PERMISSIONS, p)


# ---------- MANIFEST-008 minSdk ----------


class TestMinSdk(unittest.TestCase):
    def test_below_threshold_triggers(self):
        report = audit_manifest(_meta(min_sdk=21))
        self.assertIn("MANIFEST-008", _ids(report))

    def test_at_threshold_does_not_trigger(self):
        report = audit_manifest(_meta(min_sdk=MIN_RECOMMENDED_MIN_SDK))
        self.assertNotIn("MANIFEST-008", _ids(report))

    def test_unset_does_not_trigger(self):
        report = audit_manifest(_meta(min_sdk=None))
        self.assertNotIn("MANIFEST-008", _ids(report))


# ---------- MANIFEST-009 targetSdk ----------


class TestTargetSdk(unittest.TestCase):
    def test_below_threshold_triggers(self):
        report = audit_manifest(_meta(target_sdk=29))
        self.assertIn("MANIFEST-009", _ids(report))

    def test_at_threshold_does_not_trigger(self):
        report = audit_manifest(_meta(target_sdk=MIN_RECOMMENDED_TARGET_SDK))
        self.assertNotIn("MANIFEST-009", _ids(report))

    def test_unset_does_not_trigger(self):
        report = audit_manifest(_meta(target_sdk=None))
        self.assertNotIn("MANIFEST-009", _ids(report))


# ---------- AndroidAuditReport ----------


class TestReportShape(unittest.TestCase):
    def test_empty_report_when_clean(self):
        # Modern, clean app: no findings
        report = audit_manifest(_meta(
            min_sdk=30,
            target_sdk=33,
            debuggable=False,
            allow_backup=False,
            uses_cleartext_traffic=False,
        ))
        self.assertEqual(report.findings, [])
        self.assertEqual(report.severity_counts, {})

    def test_severity_counts_grouping(self):
        report = audit_manifest(_meta(
            debuggable=True,
            allow_backup=True,
            target_sdk=33,
            permissions=["android.permission.READ_SMS"],
        ))
        counts = report.severity_counts
        self.assertEqual(counts.get(SEV_HIGH), 1)     # debuggable
        self.assertEqual(counts.get(SEV_MEDIUM), 1)   # allow_backup
        self.assertEqual(counts.get(SEV_INFO), 1)     # dangerous perm

    def test_has_severity_at_least_high(self):
        report = audit_manifest(_meta(debuggable=True))
        self.assertTrue(report.has_severity_at_least("high"))
        self.assertFalse(report.has_severity_at_least("critical"))

    def test_has_severity_threshold_inclusive(self):
        # MEDIUM finding present; threshold "medium" should match
        report = audit_manifest(_meta(allow_backup=True))
        self.assertTrue(report.has_severity_at_least("medium"))
        self.assertFalse(report.has_severity_at_least("high"))

    def test_report_round_trip(self):
        report = audit_manifest(_meta(debuggable=True, allow_backup=True))
        d = report.to_dict()
        rt = AndroidAuditReport.from_dict(d)
        self.assertEqual(len(rt.findings), len(report.findings))
        self.assertEqual(rt.findings[0].rule_id, report.findings[0].rule_id)


class TestRulesContract(unittest.TestCase):
    def test_each_rule_returns_list(self):
        meta = _meta()
        for rule in RULES:
            self.assertIsInstance(rule(meta), list, rule.__name__)

    def test_each_finding_has_required_fields(self):
        report = audit_manifest(_meta(
            debuggable=True,
            allow_backup=True,
            target_sdk=29,
            min_sdk=21,
            permissions=["android.permission.READ_SMS"],
            components=[
                _comp(name="A", exported=True, intent_actions=["x"]),
                _comp(type="provider", name="P", exported=True, grant_uri_permissions=True),
            ],
            uses_cleartext_traffic=True,
        ))
        for f in report.findings:
            self.assertTrue(f.rule_id.startswith("MANIFEST-"), f.rule_id)
            self.assertTrue(f.title)
            self.assertIn(f.severity, ("critical", "high", "medium", "low", "info"))
            self.assertTrue(f.detail)
            self.assertTrue(f.remediation)


# ---------- format_audit_summary ----------


class TestFormatAuditSummary(unittest.TestCase):
    def test_summary_includes_package_and_total(self):
        report = audit_manifest(_meta(debuggable=True))
        s = format_audit_summary(report)
        self.assertIn("com.x", s)
        self.assertIn("취약점 1건", s)

    def test_summary_clean_app(self):
        report = audit_manifest(_meta())
        s = format_audit_summary(report)
        self.assertIn("(탐지된 취약점 없음)", s)

    def test_summary_lists_each_finding(self):
        report = audit_manifest(_meta(
            debuggable=True,
            allow_backup=True,
            target_sdk=29,
        ))
        s = format_audit_summary(report)
        self.assertIn("MANIFEST-001", s)
        self.assertIn("MANIFEST-003", s)
        self.assertIn("MANIFEST-009", s)
        self.assertIn("[HIGH]", s)
        self.assertIn("[MEDIUM]", s)


# ---------- end-to-end realistic ----------


class TestEndToEndScenarios(unittest.TestCase):
    def test_legacy_app_many_findings(self):
        # Pre-Android-6 baseline: many issues
        meta = AndroidAppMeta(
            package_name="com.legacy",
            min_sdk=19,
            target_sdk=22,
            debuggable=True,
            permissions=[
                "android.permission.INTERNET",
                "android.permission.READ_SMS",
                "android.permission.READ_CONTACTS",
                "android.permission.RECORD_AUDIO",
            ],
            components=[
                AndroidComponent(
                    type="activity", name="com.legacy.Main",
                    exported=True, intent_actions=["android.intent.action.MAIN"],
                ),
                AndroidComponent(
                    type="provider", name="com.legacy.DataProvider",
                    exported=True, grant_uri_permissions=True,
                ),
            ],
            uses_cleartext_traffic=None,  # default true on this targetSdk
            allow_backup=None,             # default true
        )
        report = audit_manifest(meta)
        ids = set(_ids(report))
        # Expect: debuggable, cleartext (default), allow_backup (default),
        # exported activity no perm, exported provider, grant uri,
        # dangerous perms, min_sdk, target_sdk
        self.assertEqual(
            ids,
            {
                "MANIFEST-001", "MANIFEST-002", "MANIFEST-003",
                "MANIFEST-004", "MANIFEST-005", "MANIFEST-006",
                "MANIFEST-007", "MANIFEST-008", "MANIFEST-009",
            },
        )

    def test_modern_clean_app_no_findings(self):
        meta = AndroidAppMeta(
            package_name="com.modern",
            min_sdk=26,
            target_sdk=34,
            debuggable=False,
            permissions=["android.permission.INTERNET"],  # normal only
            components=[
                AndroidComponent(
                    type="activity", name="com.modern.Main",
                    exported=True, intent_actions=["android.intent.action.MAIN"],
                    permission="com.modern.SIGNATURE_PERM",
                ),
            ],
            uses_cleartext_traffic=False,
            allow_backup=False,
            network_security_config="@xml/nsc",
        )
        report = audit_manifest(meta)
        self.assertEqual(report.findings, [])


if __name__ == "__main__":
    unittest.main()

"""Tests for poc_generator — turn manifest_audit findings into PoCArtifact.

Synthetic AndroidAppMeta + AndroidAuditReport keep tests pure-Python.
Each rule covered by PER_RULE_BUILDERS gets a positive case verifying
artifact shape and the presence of the operator-visible markers
(kind, package_name, command keywords). Informational rules
(MANIFEST-007..009) are exercised in a negative test that confirms they
emit nothing.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from venomhook.manifest_audit import audit_manifest
from venomhook.models import (
    AndroidAppMeta,
    AndroidAuditReport,
    AndroidComponent,
    ManifestFinding,
    PoCArtifact,
)
from venomhook.poc_generator import (
    PER_RULE_BUILDERS,
    format_pocs_text,
    generate_pocs,
)


# ---------- helpers ----------


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


def _finding(rule_id: str, **overrides) -> ManifestFinding:
    base = dict(
        rule_id=rule_id,
        title="t",
        severity="high",
        detail="",
        remediation="",
        component=None,
        references=["OWASP MASVS-PLATFORM-1"],
    )
    base.update(overrides)
    return ManifestFinding(**base)


def _report(*findings: ManifestFinding, package_name: str = "com.x") -> AndroidAuditReport:
    return AndroidAuditReport(package_name=package_name, findings=list(findings))


# ---------- model roundtrip ----------


class PoCArtifactModelTests(unittest.TestCase):
    def test_default_minimal(self) -> None:
        a = PoCArtifact(
            rule_id="MANIFEST-001", title="t", severity="high",
            kind="adb", package_name="com.x",
        )
        self.assertEqual(a.commands, [])
        self.assertEqual(a.references, [])
        self.assertIsNone(a.component)

    def test_to_dict_omits_optional_when_empty(self) -> None:
        a = PoCArtifact(
            rule_id="MANIFEST-001", title="t", severity="high",
            kind="adb", package_name="com.x",
        )
        d = a.to_dict()
        self.assertNotIn("commands", d)
        self.assertNotIn("component", d)
        self.assertNotIn("references", d)
        self.assertEqual(d["rule_id"], "MANIFEST-001")

    def test_to_dict_includes_optional_when_set(self) -> None:
        a = PoCArtifact(
            rule_id="MANIFEST-004", title="t", severity="high",
            kind="adb", package_name="com.x",
            component="com.x.A",
            commands=["adb shell am start"],
            references=["CWE-926"],
            description="d", expected_evidence="e", notes="n",
        )
        d = a.to_dict()
        self.assertEqual(d["component"], "com.x.A")
        self.assertEqual(d["commands"], ["adb shell am start"])
        self.assertEqual(d["references"], ["CWE-926"])
        self.assertEqual(d["description"], "d")
        self.assertEqual(d["expected_evidence"], "e")
        self.assertEqual(d["notes"], "n")

    def test_round_trip(self) -> None:
        original = PoCArtifact(
            rule_id="MANIFEST-004", title="t", severity="high",
            kind="adb", package_name="com.x",
            component="com.x.A", commands=["c1", "c2"],
            references=["R1"], notes="n",
        )
        restored = PoCArtifact.from_dict(original.to_dict())
        self.assertEqual(restored, original)


# ---------- per-rule builder smoke tests ----------


class DebuggableBuilderTests(unittest.TestCase):
    def test_emits_jdb_and_runas_artifacts(self) -> None:
        launcher = _comp(name="com.x.Launcher",
                         intent_actions=["android.intent.action.MAIN"])
        meta = _meta(debuggable=True, components=[launcher])
        arts = generate_pocs(meta, audit_manifest(meta))
        self.assertEqual(len(arts), 2)
        self.assertTrue(any("jdb" in a.title.lower() for a in arts))
        self.assertTrue(any("run-as" in a.title.lower() for a in arts))
        self.assertTrue(any(
            any("com.x.Launcher" in c for c in a.commands) for a in arts
        ))

    def test_falls_back_with_note_when_no_launcher(self) -> None:
        meta = _meta(debuggable=True, components=[])
        arts = generate_pocs(meta, audit_manifest(meta))
        jdb = next(a for a in arts if "jdb" in a.title.lower())
        self.assertIn("MainActivity", " ".join(jdb.commands))
        self.assertIn("Launcher activity not detected", jdb.notes)


class CleartextBuilderTests(unittest.TestCase):
    def test_mitmproxy_recipe_emitted(self) -> None:
        meta = _meta(uses_cleartext_traffic=True)
        arts = generate_pocs(meta, audit_manifest(meta))
        self.assertEqual(len(arts), 1)
        a = arts[0]
        self.assertEqual(a.kind, "shell")
        self.assertTrue(any("mitmproxy" in c for c in a.commands))


class AllowBackupBuilderTests(unittest.TestCase):
    def test_adb_backup_recipe_emitted(self) -> None:
        # target_sdk<31 default → allowBackup defaults true
        meta = _meta(target_sdk=29, allow_backup=None)
        arts = generate_pocs(meta, audit_manifest(meta))
        self.assertEqual(len(arts), 1)
        a = arts[0]
        self.assertTrue(any("adb backup" in c for c in a.commands))
        self.assertTrue(any(c.endswith(meta.package_name) for c in a.commands))


class ExportedNoPermissionBuilderTests(unittest.TestCase):
    def test_per_action_artifact_for_activity(self) -> None:
        comp = _comp(
            type="activity", name="com.x.PublicAct",
            exported=True, exported_declared=True,
            intent_actions=["android.intent.action.VIEW",
                            "android.intent.action.SEND"],
        )
        meta = _meta(components=[comp])
        arts = generate_pocs(meta, audit_manifest(meta))
        # one ADB artifact per action + one Frida observer for the component
        self.assertEqual(len(arts), 3)
        adb_arts = [a for a in arts if a.kind == "adb"]
        frida_arts = [a for a in arts if a.kind == "frida"]
        self.assertEqual(len(adb_arts), 2)
        self.assertEqual(len(frida_arts), 1)
        for a in adb_arts:
            self.assertEqual(a.component, "com.x.PublicAct")
            self.assertTrue(any("am start" in c for c in a.commands))

    def test_frida_observer_for_activity_hooks_oncreate(self) -> None:
        comp = _comp(
            type="activity", name="com.x.A",
            exported=True, exported_declared=True,
            intent_actions=["android.intent.action.VIEW"],
        )
        meta = _meta(components=[comp])
        arts = generate_pocs(meta, audit_manifest(meta))
        frida = next(a for a in arts if a.kind == "frida")
        body = "\n".join(frida.commands)
        self.assertIn('Java.use("com.x.A")', body)
        self.assertIn("onCreate.overload", body)
        self.assertIn("getIntent()", body)
        self.assertIn("frida -U", frida.notes)

    def test_service_uses_startservice(self) -> None:
        comp = _comp(
            type="service", name="com.x.Svc",
            exported=True, exported_declared=True,
            intent_actions=["x.act.PING"],
        )
        meta = _meta(components=[comp])
        arts = generate_pocs(meta, audit_manifest(meta))
        adb = next(a for a in arts if a.kind == "adb")
        self.assertTrue(any("am startservice" in c for c in adb.commands))
        frida = next(a for a in arts if a.kind == "frida")
        self.assertIn("onStartCommand", "\n".join(frida.commands))

    def test_receiver_uses_broadcast(self) -> None:
        comp = _comp(
            type="receiver", name="com.x.Recv",
            exported=True, exported_declared=True,
            intent_actions=["x.act.SIG"],
        )
        meta = _meta(components=[comp])
        arts = generate_pocs(meta, audit_manifest(meta))
        adb = next(a for a in arts if a.kind == "adb")
        self.assertTrue(any("am broadcast" in c for c in adb.commands))
        frida = next(a for a in arts if a.kind == "frida")
        self.assertIn("onReceive", "\n".join(frida.commands))

    def test_degraded_when_component_missing_from_meta(self) -> None:
        # Hand-build a finding whose component isn't present in meta —
        # simulates loading a stored report against a different meta.
        meta = _meta(components=[])
        report = _report(_finding(
            "MANIFEST-004", component="com.x.Ghost",
            title="ghost", severity="high",
        ))
        arts = generate_pocs(meta, report)
        self.assertEqual(len(arts), 1)
        self.assertIn("com.x.Ghost", arts[0].commands[0])


class ExportedProviderBuilderTests(unittest.TestCase):
    def test_query_recipe_emitted_with_placeholder_when_authority_absent(self) -> None:
        comp = _comp(
            type="provider", name="com.x.Prov",
            exported=True, exported_declared=True,
            intent_actions=[],
        )
        meta = _meta(components=[comp], target_sdk=33)
        arts = generate_pocs(meta, audit_manifest(meta))
        self.assertGreaterEqual(len(arts), 1)
        a = next(x for x in arts if x.rule_id == "MANIFEST-005")
        self.assertTrue(any("content query" in c for c in a.commands))
        # No authorities on the component -> placeholder + guidance note.
        self.assertTrue(any("<AUTHORITY>" in c for c in a.commands))
        self.assertIn("android:authorities was not present", a.notes)

    def test_query_recipe_uses_real_authority_when_present(self) -> None:
        comp = _comp(
            type="provider", name="com.x.Prov",
            exported=True, exported_declared=True,
            authorities=["com.x.fileprovider"],
        )
        meta = _meta(components=[comp], target_sdk=33)
        arts = generate_pocs(meta, audit_manifest(meta))
        a = next(x for x in arts if x.rule_id == "MANIFEST-005")
        self.assertTrue(any("content://com.x.fileprovider/" in c for c in a.commands))
        # No fallback notes when real authority is in hand.
        self.assertNotIn("substitute the actual authority", a.notes)

    def test_multiple_authorities_recorded_in_notes(self) -> None:
        comp = _comp(
            type="provider", name="com.x.Prov",
            exported=True, exported_declared=True,
            authorities=["com.x.primary", "com.x.secondary", "com.x.legacy"],
        )
        meta = _meta(components=[comp], target_sdk=33)
        arts = generate_pocs(meta, audit_manifest(meta))
        a = next(x for x in arts if x.rule_id == "MANIFEST-005")
        # First authority used in URI; the rest surfaced as a note.
        self.assertTrue(any("content://com.x.primary/" in c for c in a.commands))
        self.assertIn("com.x.secondary", a.notes)
        self.assertIn("com.x.legacy", a.notes)


class GrantUriBuilderTests(unittest.TestCase):
    def test_traversal_probes_emitted(self) -> None:
        comp = _comp(
            type="provider", name="com.x.Prov",
            exported=True, exported_declared=True,
            grant_uri_permissions=True,
        )
        meta = _meta(components=[comp])
        arts = generate_pocs(meta, audit_manifest(meta))
        a = next(x for x in arts if x.rule_id == "MANIFEST-006")
        joined = " ".join(a.commands)
        self.assertIn("../", joined)
        self.assertIn(meta.package_name, joined)

    def test_traversal_uses_real_authority_when_present(self) -> None:
        comp = _comp(
            type="provider", name="com.x.Prov",
            exported=True, exported_declared=True,
            grant_uri_permissions=True,
            authorities=["com.x.fileprovider"],
        )
        meta = _meta(components=[comp])
        arts = generate_pocs(meta, audit_manifest(meta))
        a = next(x for x in arts if x.rule_id == "MANIFEST-006")
        self.assertTrue(any("content://com.x.fileprovider/" in c for c in a.commands))


# ---------- registry & informational rules ----------


class CoverageMatrixTests(unittest.TestCase):
    def test_builders_cover_001_through_006(self) -> None:
        self.assertEqual(
            set(PER_RULE_BUILDERS),
            {f"MANIFEST-00{i}" for i in range(1, 7)},
        )

    def test_informational_rules_emit_nothing(self) -> None:
        # MANIFEST-007 (dangerous perms), 008 (minSdk), 009 (targetSdk)
        meta = _meta(
            permissions=["android.permission.READ_SMS",
                         "android.permission.CAMERA"],
            min_sdk=14, target_sdk=22,
        )
        report = audit_manifest(meta)
        info_ids = {f.rule_id for f in report.findings}
        self.assertIn("MANIFEST-007", info_ids)
        self.assertIn("MANIFEST-008", info_ids)
        self.assertIn("MANIFEST-009", info_ids)
        arts = generate_pocs(meta, report)
        # No artifact should have one of those rule_ids
        self.assertFalse(
            any(a.rule_id in {"MANIFEST-007", "MANIFEST-008", "MANIFEST-009"} for a in arts)
        )


class FormatPocsTextTests(unittest.TestCase):
    def test_empty_bundle(self) -> None:
        out = format_pocs_text([])
        self.assertIn("no actionable findings", out)

    def test_render_includes_severity_rule_and_commands(self) -> None:
        meta = _meta(debuggable=True)
        arts = generate_pocs(meta, audit_manifest(meta))
        out = format_pocs_text(arts)
        self.assertIn("[HIGH]", out)
        self.assertIn("MANIFEST-001", out)
        self.assertIn("kind: adb", out)
        self.assertIn("adb forward", out)


if __name__ == "__main__":
    unittest.main()

"""Tests for poc_generator — turn manifest_audit findings into PoCArtifact.

Synthetic AndroidAppMeta + AndroidAuditReport keep tests pure-Python.
Each rule covered by PER_RULE_BUILDERS gets a positive case verifying
artifact shape and the presence of the operator-visible markers
(kind, package_name, command keywords). Informational rules
(MANIFEST-007..009) are exercised in a negative test that confirms they
emit nothing.
"""

from __future__ import annotations

import json
import shlex
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
    CodeAuditReport,
    CodeFinding,
    IntentDataSpec,
    IntentFilter,
    ManifestFinding,
    NetworkSecurityConfigMeta,
    PoCArtifact,
)
from venomhook.poc_generator import (
    PER_CODE_RULE_BUILDERS,
    PER_RULE_BUILDERS,
    format_pocs_text,
    generate_code_pocs,
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
        self.assertIn("런처 액티비티를 찾을 수 없습니다", jdb.notes)


class CleartextBuilderTests(unittest.TestCase):
    def test_mitmproxy_recipe_emitted(self) -> None:
        meta = _meta(uses_cleartext_traffic=True)
        arts = generate_pocs(meta, audit_manifest(meta))
        self.assertEqual(len(arts), 1)
        a = arts[0]
        self.assertEqual(a.kind, "shell")
        self.assertTrue(any("mitmproxy" in c for c in a.commands))


class UserCertTrustBuilderTests(unittest.TestCase):
    def test_mitmproxy_user_cert_recipe_emitted(self) -> None:
        meta = _meta(
            network_security_config="@xml/nsc",
            nsc=NetworkSecurityConfigMeta(base_trusts_user_certs=True),
        )
        arts = generate_pocs(meta, audit_manifest(meta))
        m010_arts = [a for a in arts if a.rule_id == "MANIFEST-010"]
        self.assertEqual(len(m010_arts), 1)
        a = m010_arts[0]
        self.assertEqual(a.kind, "shell")
        self.assertEqual(a.severity, "high")
        commands = " ".join(a.commands)
        self.assertIn("mitmproxy", commands)
        self.assertIn("mitmproxy.cer", commands)
        self.assertIn("am start", commands)


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

    def test_adb_action_is_quoted_for_host_and_remote_shells(self) -> None:
        action = "x.ACTION; touch /tmp/venomhook_pwned"
        comp = _comp(
            type="activity", name="com.x.PublicAct",
            exported=True, exported_declared=True,
            intent_actions=[action],
        )
        meta = _meta(components=[comp])
        arts = generate_pocs(meta, audit_manifest(meta))
        adb = next(a for a in arts if a.kind == "adb")
        argv = shlex.split(adb.commands[0])
        self.assertEqual(argv[:2], ["adb", "shell"])
        remote_argv = shlex.split(argv[2])
        self.assertEqual(
            remote_argv,
            ["am", "start", "-a", action, "-n", "com.x/com.x.PublicAct"],
        )

    def test_frida_class_name_is_js_string_encoded(self) -> None:
        klass = 'com.x.A"; console.log("pwned"); //'
        comp = _comp(
            type="activity", name=klass,
            exported=True, exported_declared=True,
            intent_actions=["android.intent.action.VIEW"],
        )
        meta = _meta(components=[comp])
        arts = generate_pocs(meta, audit_manifest(meta))
        frida = next(a for a in arts if a.kind == "frida")
        line = next(c for c in frida.commands if "Java.use(" in c)
        literal = line.strip().removeprefix("const Klass = Java.use(").removesuffix(");")
        self.assertEqual(json.loads(literal), klass)

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


# ---------- Phase 6-4 — deeplink PoCs for BROWSABLE activities ----------


def _browsable_activity(
    name: str = "com.x.Deep",
    *,
    schemes: tuple[tuple[str, str | None, dict | None], ...] = (),
) -> AndroidComponent:
    """Build an exported activity with one BROWSABLE filter per (scheme,host,extras).

    Each tuple is ``(scheme, host, extras_dict)`` where extras_dict can carry
    path / path_prefix / path_pattern / path_suffix / mime_type. Helps tests
    declare deeplink shapes concisely without the manifest XML round-trip.
    """
    filters: list[IntentFilter] = []
    for scheme, host, extras in schemes:
        kwargs = {"scheme": scheme, "host": host}
        kwargs.update(extras or {})
        filters.append(IntentFilter(
            actions=["android.intent.action.VIEW"],
            categories=[
                "android.intent.category.DEFAULT",
                "android.intent.category.BROWSABLE",
            ],
            data=[IntentDataSpec(**kwargs)],
        ))
    return _comp(
        type="activity", name=name,
        exported=True, exported_declared=True,
        intent_actions=["android.intent.action.VIEW"],
        intent_filters=filters,
    )


class DeeplinkBuilderTests(unittest.TestCase):
    def test_no_deeplink_when_filter_lacks_browsable(self) -> None:
        # LAUNCHER filter with scheme but no BROWSABLE — internal entry,
        # not externally addressable. Don't emit deeplink PoCs.
        comp = _comp(
            type="activity", name="com.x.A",
            exported=True, exported_declared=True,
            intent_actions=["android.intent.action.MAIN"],
            intent_filters=[IntentFilter(
                actions=["android.intent.action.MAIN"],
                categories=["android.intent.category.LAUNCHER"],
                data=[IntentDataSpec(scheme="custom")],
            )],
        )
        meta = _meta(components=[comp], target_sdk=33)
        arts = generate_pocs(meta, audit_manifest(meta))
        deeplink = [a for a in arts if a.title.startswith("Deeplink")]
        self.assertEqual(deeplink, [])

    def test_emits_one_deeplink_poc_per_unique_scheme(self) -> None:
        comp = _browsable_activity(schemes=(
            ("myapp", "auth", {"path_prefix": "/oauth"}),
            ("https", "example.com", {"path_prefix": "/cb"}),
        ))
        meta = _meta(components=[comp], target_sdk=33)
        arts = generate_pocs(meta, audit_manifest(meta))
        deeplinks = [a for a in arts if a.title.startswith("Deeplink")]
        self.assertEqual(len(deeplinks), 2)
        # URI is in commands; verify both are addressable
        all_cmds = "\n".join(c for a in deeplinks for c in a.commands)
        self.assertIn("myapp://auth/oauth", all_cmds)
        self.assertIn("https://example.com/cb", all_cmds)

    def test_deeplink_uses_implicit_intent_no_n_flag(self) -> None:
        # Pentest model: BROWSABLE = OS resolves the URI. Implicit intent
        # is the actual attack path, not `am start -n com.x/.A`.
        comp = _browsable_activity(schemes=(("myapp", "auth", None),))
        meta = _meta(components=[comp], target_sdk=33)
        arts = generate_pocs(meta, audit_manifest(meta))
        deeplinks = [a for a in arts if a.title.startswith("Deeplink")]
        self.assertEqual(len(deeplinks), 1)
        primary = deeplinks[0].commands
        # The first non-comment command should not have -n
        first_cmd = next(c for c in primary if not c.lstrip().startswith("#"))
        self.assertNotIn("-n ", first_cmd)
        self.assertIn("-a android.intent.action.VIEW", first_cmd)
        self.assertIn("myapp://auth", first_cmd)
        # Explicit fallback recorded in notes for verification
        self.assertIn("-n com.x/com.x.Deep", deeplinks[0].notes)

    def test_dedupe_across_filters_with_same_uri_triple(self) -> None:
        # Real F-Droid manifest declares the same scheme on multiple filters
        # (case variants, mimetype variants). The dedupe should collapse
        # identical (scheme,host,path) triples.
        comp = _comp(
            type="activity", name="com.x.A",
            exported=True, exported_declared=True,
            intent_actions=["android.intent.action.VIEW"],
            intent_filters=[
                IntentFilter(
                    actions=["android.intent.action.VIEW"],
                    categories=["android.intent.category.BROWSABLE"],
                    data=[IntentDataSpec(scheme="myapp", host="auth",
                                         path_prefix="/oauth")],
                ),
                IntentFilter(
                    actions=["android.intent.action.VIEW"],
                    categories=["android.intent.category.BROWSABLE"],
                    data=[IntentDataSpec(scheme="myapp", host="auth",
                                         path_prefix="/oauth")],
                ),
            ],
        )
        meta = _meta(components=[comp], target_sdk=33)
        arts = generate_pocs(meta, audit_manifest(meta))
        deeplinks = [a for a in arts if a.title.startswith("Deeplink")]
        self.assertEqual(len(deeplinks), 1)

    def test_caps_at_five_specs_per_component(self) -> None:
        comp = _browsable_activity(schemes=tuple(
            (f"app{i}", "h", None) for i in range(8)
        ))
        meta = _meta(components=[comp], target_sdk=33)
        arts = generate_pocs(meta, audit_manifest(meta))
        deeplinks = [a for a in arts if a.title.startswith("Deeplink")]
        self.assertEqual(len(deeplinks), 5)

    def test_path_pattern_warning_in_notes(self) -> None:
        comp = _browsable_activity(schemes=(
            ("https", "example.com", {"path_pattern": "/api/.*"}),
        ))
        meta = _meta(components=[comp], target_sdk=33)
        arts = generate_pocs(meta, audit_manifest(meta))
        deeplinks = [a for a in arts if a.title.startswith("Deeplink")]
        self.assertEqual(len(deeplinks), 1)
        self.assertIn("pathPattern", deeplinks[0].notes)
        self.assertIn("정규식이 아니므로", deeplinks[0].notes)

    def test_http_scheme_without_host_falls_back_to_example_com(self) -> None:
        # A bare http:// scheme would yield an unrunnable URI; provide a
        # placeholder host so the operator gets something to substitute.
        comp = _browsable_activity(schemes=(("https", None, None),))
        meta = _meta(components=[comp], target_sdk=33)
        arts = generate_pocs(meta, audit_manifest(meta))
        deeplinks = [a for a in arts if a.title.startswith("Deeplink")]
        self.assertEqual(len(deeplinks), 1)
        cmds = "\n".join(deeplinks[0].commands)
        self.assertIn("https://example.com", cmds)

    def test_non_activity_browsable_skipped(self) -> None:
        # BROWSABLE is conventionally only on activities. If somehow a
        # service/receiver carried it, we still skip — `am start -a VIEW -d`
        # wouldn't reach it anyway.
        comp = _comp(
            type="service", name="com.x.S",
            exported=True, exported_declared=True,
            intent_actions=["android.intent.action.VIEW"],
            intent_filters=[IntentFilter(
                actions=["android.intent.action.VIEW"],
                categories=["android.intent.category.BROWSABLE"],
                data=[IntentDataSpec(scheme="myapp")],
            )],
        )
        meta = _meta(components=[comp], target_sdk=33)
        arts = generate_pocs(meta, audit_manifest(meta))
        deeplinks = [a for a in arts if a.title.startswith("Deeplink")]
        self.assertEqual(deeplinks, [])

    def test_deeplink_inherits_finding_severity_and_refs(self) -> None:
        comp = _browsable_activity(schemes=(("myapp", "auth", None),))
        meta = _meta(components=[comp], target_sdk=33)
        arts = generate_pocs(meta, audit_manifest(meta))
        deeplink = next(a for a in arts if a.title.startswith("Deeplink"))
        self.assertEqual(deeplink.severity, "high")
        self.assertEqual(deeplink.kind, "adb")
        self.assertIn("CWE-926", deeplink.references)


# ---------- Phase 7-4 — code-finding PoCs ----------


def _code_finding(rule_id: str, **overrides) -> CodeFinding:
    base = dict(
        rule_id=rule_id,
        title="t",
        severity="high",
        file="com/x/A.java",
        line_no=10,
        line_text="…",
        class_fqn="com.x.A",
        detail="d",
        remediation="r",
        references=["OWASP MASVS-CODE-2"],
    )
    base.update(overrides)
    return CodeFinding(**base)


class CodeWebViewBuilderTests(unittest.TestCase):
    def test_emits_frida_observer_with_class_and_evidence(self) -> None:
        f = _code_finding("CODE-002", class_fqn="com.x.WebActivity")
        report = CodeAuditReport(package_name="com.x", findings=[f])
        arts = generate_code_pocs(_meta(), report)
        self.assertEqual(len(arts), 1)
        a = arts[0]
        self.assertEqual(a.kind, "frida")
        self.assertEqual(a.rule_id, "CODE-002")
        self.assertEqual(a.component, "com.x.WebActivity")
        body = "\n".join(a.commands)
        self.assertIn("setJavaScriptEnabled", body)
        self.assertIn("addJavascriptInterface", body)
        self.assertIn("loadUrl", body)

    def test_class_fqn_falls_back_when_missing(self) -> None:
        f = _code_finding("CODE-002", class_fqn="")
        report = CodeAuditReport(package_name="com.x", findings=[f])
        arts = generate_code_pocs(_meta(), report)
        self.assertEqual(len(arts), 1)
        self.assertIn("<unknown class>", arts[0].title)


class CodeWeakCryptoBuilderTests(unittest.TestCase):
    def test_emits_cipher_observer(self) -> None:
        f = _code_finding("CODE-003", class_fqn="com.x.Crypto")
        report = CodeAuditReport(package_name="com.x", findings=[f])
        arts = generate_code_pocs(_meta(), report)
        self.assertEqual(len(arts), 1)
        a = arts[0]
        self.assertEqual(a.kind, "frida")
        body = "\n".join(a.commands)
        self.assertIn("javax.crypto.Cipher", body)
        self.assertIn("SecretKeySpec", body)
        self.assertIn("doFinal", body)
        self.assertIn("MessageDigest", body)


class CodeCredentialLogBuilderTests(unittest.TestCase):
    def test_emits_logcat_recipe(self) -> None:
        f = _code_finding("CODE-004",
                          class_fqn="com.x.Login",
                          line_text='Log.d(TAG, "password=" + p);')
        report = CodeAuditReport(package_name="com.x", findings=[f])
        arts = generate_code_pocs(_meta(), report)
        self.assertEqual(len(arts), 1)
        a = arts[0]
        self.assertEqual(a.kind, "adb")
        cmds = "\n".join(a.commands)
        self.assertIn("logcat -c", cmds)
        self.assertIn("logcat -v time", cmds)
        self.assertIn("password", cmds.lower())
        # The static evidence line is preserved in notes
        self.assertIn("password", a.notes)


class GenerateCodePocsAggregateTests(unittest.TestCase):
    def test_skips_rules_without_builder(self) -> None:
        # CODE-001 / 005 / 006 intentionally have no builder.
        report = CodeAuditReport(
            package_name="com.x",
            findings=[
                _code_finding("CODE-001"),
                _code_finding("CODE-005"),
                _code_finding("CODE-006"),
                _code_finding("CODE-002", class_fqn="com.x.W"),
            ],
        )
        arts = generate_code_pocs(_meta(), report)
        self.assertEqual([a.rule_id for a in arts], ["CODE-002"])

    def test_empty_report_emits_nothing(self) -> None:
        arts = generate_code_pocs(_meta(),
                                   CodeAuditReport(package_name="com.x"))
        self.assertEqual(arts, [])


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
        self.assertIn("android:authorities가 선언되어 있지 않습니다", a.notes)

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

    def test_authority_is_quoted_for_host_and_remote_shells(self) -> None:
        authority = "com.x.provider; touch /tmp/venomhook_pwned"
        comp = _comp(
            type="provider", name="com.x.Prov",
            exported=True, exported_declared=True,
            authorities=[authority],
        )
        meta = _meta(components=[comp], target_sdk=33)
        arts = generate_pocs(meta, audit_manifest(meta))
        a = next(x for x in arts if x.rule_id == "MANIFEST-005")
        argv = shlex.split(a.commands[0])
        self.assertEqual(argv[:2], ["adb", "shell"])
        remote_argv = shlex.split(argv[2])
        self.assertEqual(
            remote_argv,
            ["content", "query", "--uri", f"content://{authority}/"],
        )

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
    def test_builders_cover_001_through_006_and_010(self) -> None:
        # MANIFEST-007..009 are informational (no PoC); MANIFEST-010 is the
        # NSC user-cert trust rule added in Phase 9-2 with a mitmproxy CA
        # install recipe. Keep this matrix in sync as new rules land.
        self.assertEqual(
            set(PER_RULE_BUILDERS),
            {f"MANIFEST-00{i}" for i in range(1, 7)} | {"MANIFEST-010"},
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
        self.assertIn("실행 가능한 finding 없음", out)

    def test_render_includes_severity_rule_and_commands(self) -> None:
        meta = _meta(debuggable=True)
        arts = generate_pocs(meta, audit_manifest(meta))
        out = format_pocs_text(arts)
        self.assertIn("[HIGH]", out)
        self.assertIn("MANIFEST-001", out)
        self.assertIn("종류: adb", out)
        self.assertIn("adb forward", out)


if __name__ == "__main__":
    unittest.main()

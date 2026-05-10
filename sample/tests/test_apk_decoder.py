"""Tests for apk_decoder — apktool wrapper, manifest parser, name resolution.

Synthetic AndroidManifest.xml fixtures and a stub apktool binary keep this
test suite hermetic. apktool itself is never invoked in CI.
"""

from __future__ import annotations

import os
import stat
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from _subproc_stub import make_stub_executable

from venomhook.apk_decoder import (
    ANDROID_NS,
    APKTOOL_ENV_VAR,
    ApkDecoderError,
    ApktoolConfig,
    ApktoolNotFoundError,
    ApktoolResult,
    ApktoolRunError,
    ManifestParseError,
    _resolve_class_name,
    decode_apk,
    find_apktool,
    parse_android_manifest,
    run_apktool_decode,
)
from venomhook.models import (
    AndroidAppMeta,
    AndroidComponent,
    IntentDataSpec,
    IntentFilter,
)


def _write_executable(path: Path, body: str) -> Path:
    path.write_text(body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


def _manifest_xml(
    package: str = "com.example.app",
    permissions: tuple[str, ...] = (),
    activities: tuple[dict, ...] = (),
    services: tuple[dict, ...] = (),
    receivers: tuple[dict, ...] = (),
    application_name: str | None = None,
    debuggable: bool = False,
    extract_native_libs: str | None = None,
    min_sdk: int | None = None,
    target_sdk: int | None = None,
    network_security_config: str | None = None,
) -> str:
    """Build a synthetic AndroidManifest.xml for parser tests.

    Plain string assembly (no dedent) — the XML parser ignores whitespace
    so we don't bother indenting consistently.
    """
    lines = [
        '<?xml version="1.0" encoding="utf-8"?>',
        f'<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="{package}">',
    ]
    for p in permissions:
        lines.append(f'<uses-permission android:name="{p}"/>')

    sdk_attrs = []
    if min_sdk is not None:
        sdk_attrs.append(f'android:minSdkVersion="{min_sdk}"')
    if target_sdk is not None:
        sdk_attrs.append(f'android:targetSdkVersion="{target_sdk}"')
    if sdk_attrs:
        lines.append(f'<uses-sdk {" ".join(sdk_attrs)}/>')

    app_attrs = []
    if application_name is not None:
        app_attrs.append(f'android:name="{application_name}"')
    if debuggable:
        app_attrs.append('android:debuggable="true"')
    if extract_native_libs is not None:
        app_attrs.append(f'android:extractNativeLibs="{extract_native_libs}"')
    if 'network_security_config' in locals() and network_security_config is not None:
        app_attrs.append(f'android:networkSecurityConfig="{network_security_config}"')
    lines.append(f'<application {" ".join(app_attrs)}>')

    def _component_xml(tag: str, c: dict) -> str:
        attrs = [f'android:name="{c["name"]}"']
        if c.get("exported") is not None:
            attrs.append(f'android:exported="{"true" if c["exported"] else "false"}"')
        if c.get("permission"):
            attrs.append(f'android:permission="{c["permission"]}"')
        actions = c.get("actions", [])
        if not actions:
            return f'<{tag} {" ".join(attrs)}/>'
        action_lines = "".join(
            f'<action android:name="{a}"/>' for a in actions
        )
        return f'<{tag} {" ".join(attrs)}><intent-filter>{action_lines}</intent-filter></{tag}>'

    for a in activities:
        lines.append(_component_xml("activity", a))
    for s in services:
        lines.append(_component_xml("service", s))
    for r in receivers:
        lines.append(_component_xml("receiver", r))

    lines.append("</application>")
    lines.append("</manifest>")
    return "\n".join(lines)


# ---------- find_apktool ----------


class TestFindApktool(unittest.TestCase):
    def setUp(self):
        self.saved = os.environ.pop(APKTOOL_ENV_VAR, None)

    def tearDown(self):
        if self.saved is not None:
            os.environ[APKTOOL_ENV_VAR] = self.saved
        else:
            os.environ.pop(APKTOOL_ENV_VAR, None)

    def test_env_var_wins(self):
        with tempfile.TemporaryDirectory() as td:
            stub = _write_executable(Path(td) / "my-apktool", "#!/bin/sh\nexit 0\n")
            os.environ[APKTOOL_ENV_VAR] = str(stub)
            self.assertEqual(find_apktool(), str(stub))

    def test_env_var_nonexistent_raises(self):
        os.environ[APKTOOL_ENV_VAR] = "/nope/apktool"
        with self.assertRaises(ApktoolNotFoundError):
            find_apktool()

    def test_path_lookup(self):
        with mock.patch("venomhook.apk_decoder.shutil.which") as m:
            m.side_effect = lambda n: "/usr/local/bin/apktool" if n == "apktool" else None
            self.assertEqual(find_apktool(), "/usr/local/bin/apktool")

    def test_not_found_raises(self):
        with mock.patch("venomhook.apk_decoder.shutil.which", return_value=None):
            with self.assertRaises(ApktoolNotFoundError) as ctx:
                find_apktool()
            self.assertIn("VENOMHOOK_APKTOOL", str(ctx.exception))


# ---------- _resolve_class_name ----------


class TestResolveClassName(unittest.TestCase):
    def test_leading_dot(self):
        self.assertEqual(
            _resolve_class_name(".MainActivity", "com.app"),
            "com.app.MainActivity",
        )

    def test_bare_name(self):
        self.assertEqual(
            _resolve_class_name("MainActivity", "com.app"),
            "com.app.MainActivity",
        )

    def test_already_qualified(self):
        self.assertEqual(
            _resolve_class_name("com.foo.X", "com.app"),
            "com.foo.X",
        )

    def test_none_or_empty(self):
        self.assertIsNone(_resolve_class_name(None, "com.app"))
        self.assertIsNone(_resolve_class_name("", "com.app"))

    def test_empty_package_with_leading_dot(self):
        # No package context: drop the leading '.'
        self.assertEqual(_resolve_class_name(".A", ""), "A")

    def test_empty_package_with_bare_name(self):
        self.assertEqual(_resolve_class_name("A", ""), "A")


# ---------- parse_android_manifest ----------


class TestParseAndroidManifest(unittest.TestCase):
    def _write(self, td: Path, xml: str) -> Path:
        p = td / "AndroidManifest.xml"
        p.write_text(xml)
        return p

    def test_minimal_manifest(self):
        with tempfile.TemporaryDirectory() as td:
            m = self._write(
                Path(td),
                """<?xml version="1.0"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.x.y">
    <application/>
</manifest>""",
            )
            meta = parse_android_manifest(m)
            self.assertEqual(meta.package_name, "com.x.y")
            self.assertEqual(meta.permissions, [])
            self.assertEqual(meta.components, [])
            self.assertFalse(meta.debuggable)

    def test_permissions_collected(self):
        with tempfile.TemporaryDirectory() as td:
            xml = _manifest_xml(
                package="com.app",
                permissions=("android.permission.INTERNET", "android.permission.CAMERA"),
            )
            m = self._write(Path(td), xml)
            meta = parse_android_manifest(m)
            self.assertEqual(
                meta.permissions,
                ["android.permission.INTERNET", "android.permission.CAMERA"],
            )

    def test_activity_with_resolution(self):
        with tempfile.TemporaryDirectory() as td:
            xml = _manifest_xml(
                package="com.app",
                activities=(
                    {"name": ".MainActivity", "exported": True,
                     "actions": ["android.intent.action.MAIN"]},
                    {"name": "com.elsewhere.Other", "exported": False},
                ),
            )
            m = self._write(Path(td), xml)
            meta = parse_android_manifest(m)
            self.assertEqual(len(meta.activities), 2)
            self.assertEqual(meta.activities[0].name, "com.app.MainActivity")
            self.assertTrue(meta.activities[0].exported)
            self.assertEqual(
                meta.activities[0].intent_actions,
                ["android.intent.action.MAIN"],
            )
            self.assertEqual(meta.activities[1].name, "com.elsewhere.Other")
            self.assertFalse(meta.activities[1].exported)

    def test_absent_exported_is_preserved(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "AndroidManifest.xml"
            p.write_text(
                '<?xml version="1.0"?>\n'
                '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.app">\n'
                '  <uses-sdk android:targetSdkVersion="23"/>\n'
                '  <application>\n'
                '    <activity android:name=".MainActivity">\n'
                '      <intent-filter>\n'
                '        <action android:name="android.intent.action.MAIN"/>\n'
                '      </intent-filter>\n'
                '    </activity>\n'
                '  </application>\n'
                '</manifest>\n'
            )
            meta = parse_android_manifest(p)
            self.assertFalse(meta.activities[0].exported)
            self.assertFalse(meta.activities[0].exported_declared)

    def test_application_class(self):
        with tempfile.TemporaryDirectory() as td:
            xml = _manifest_xml(
                package="com.app",
                application_name=".MyApplication",
            )
            m = self._write(Path(td), xml)
            meta = parse_android_manifest(m)
            self.assertEqual(meta.application_class, "com.app.MyApplication")

    def test_debuggable_and_extract_native_libs(self):
        with tempfile.TemporaryDirectory() as td:
            xml = _manifest_xml(
                package="com.app",
                debuggable=True,
                extract_native_libs="false",
            )
            m = self._write(Path(td), xml)
            meta = parse_android_manifest(m)
            self.assertTrue(meta.debuggable)
            self.assertEqual(meta.extract_native_libs, False)

    def test_extract_native_libs_unset_is_none(self):
        with tempfile.TemporaryDirectory() as td:
            xml = _manifest_xml(package="com.app")
            m = self._write(Path(td), xml)
            meta = parse_android_manifest(m)
            self.assertIsNone(meta.extract_native_libs)

    def test_sdk_versions(self):
        with tempfile.TemporaryDirectory() as td:
            xml = _manifest_xml(package="com.app", min_sdk=23, target_sdk=33)
            m = self._write(Path(td), xml)
            meta = parse_android_manifest(m)
            self.assertEqual(meta.min_sdk, 23)
            self.assertEqual(meta.target_sdk, 33)

    def test_sdk_falls_back_to_apktool_yml_when_uses_sdk_absent(self):
        # apktool 2.x emits SDK info under sdkInfo: in apktool.yml instead of
        # leaving <uses-sdk> in the decoded manifest. Verify the fallback
        # picks up both values from the sibling YAML.
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            xml = _manifest_xml(package="com.app")  # no <uses-sdk>
            m = self._write(tdp, xml)
            (tdp / "apktool.yml").write_text(
                "!!brut.androlib.meta.MetaInfo\n"
                "sdkInfo:\n"
                "  minSdkVersion: 21\n"
                "  targetSdkVersion: 30\n"
                "packageInfo:\n"
                "  forcedPackageId: '127'\n"
            )
            meta = parse_android_manifest(m)
            self.assertEqual(meta.min_sdk, 21)
            self.assertEqual(meta.target_sdk, 30)

    def test_sdk_manifest_takes_priority_over_apktool_yml(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            xml = _manifest_xml(package="com.app", min_sdk=23, target_sdk=33)
            m = self._write(tdp, xml)
            (tdp / "apktool.yml").write_text(
                "sdkInfo:\n"
                "  minSdkVersion: 15\n"
                "  targetSdkVersion: 22\n"
            )
            meta = parse_android_manifest(m)
            self.assertEqual(meta.min_sdk, 23)
            self.assertEqual(meta.target_sdk, 33)

    def test_sdk_partial_fallback_when_only_one_field_in_manifest(self):
        # If the manifest declares min but not target, the missing field is
        # filled from apktool.yml; the present one stays as-is.
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            xml = _manifest_xml(package="com.app", min_sdk=24)  # target_sdk omitted
            m = self._write(tdp, xml)
            (tdp / "apktool.yml").write_text(
                "sdkInfo:\n"
                "  minSdkVersion: 15\n"
                "  targetSdkVersion: 31\n"
            )
            meta = parse_android_manifest(m)
            self.assertEqual(meta.min_sdk, 24)
            self.assertEqual(meta.target_sdk, 31)

    def test_sdk_codename_in_apktool_yml_falls_through_to_none(self):
        # Preview/codename strings (e.g. 'P', 'Tiramisu') aren't integer
        # API levels — _safe_int returns None and we keep "unspecified"
        # semantics rather than guessing.
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            xml = _manifest_xml(package="com.app")
            m = self._write(tdp, xml)
            (tdp / "apktool.yml").write_text(
                "sdkInfo:\n"
                "  minSdkVersion: 'P'\n"
                "  targetSdkVersion: 31\n"
            )
            meta = parse_android_manifest(m)
            self.assertIsNone(meta.min_sdk)
            self.assertEqual(meta.target_sdk, 31)

    def test_sdk_apktool_yml_missing_keeps_none(self):
        with tempfile.TemporaryDirectory() as td:
            xml = _manifest_xml(package="com.app")
            m = self._write(Path(td), xml)
            meta = parse_android_manifest(m)
            self.assertIsNone(meta.min_sdk)
            self.assertIsNone(meta.target_sdk)

    def test_sdk_only_picks_values_inside_sdkInfo_block(self):
        # A minSdkVersion: line under a *different* top-level section must
        # not leak into our SDK fields. Guards against the parser becoming
        # over-eager.
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            xml = _manifest_xml(package="com.app")
            m = self._write(tdp, xml)
            (tdp / "apktool.yml").write_text(
                "unknownSection:\n"
                "  minSdkVersion: 99\n"
                "  targetSdkVersion: 99\n"
                "sdkInfo:\n"
                "  minSdkVersion: 21\n"
                "  targetSdkVersion: 30\n"
            )
            meta = parse_android_manifest(m)
            self.assertEqual(meta.min_sdk, 21)
            self.assertEqual(meta.target_sdk, 30)

    def test_services_and_receivers(self):
        with tempfile.TemporaryDirectory() as td:
            xml = _manifest_xml(
                package="com.app",
                services=({"name": ".MyService", "exported": False},),
                receivers=(
                    {"name": ".BootReceiver", "exported": True,
                     "actions": ["android.intent.action.BOOT_COMPLETED"]},
                ),
            )
            m = self._write(Path(td), xml)
            meta = parse_android_manifest(m)
            self.assertEqual(len(meta.services), 1)
            self.assertEqual(meta.services[0].name, "com.app.MyService")
            self.assertEqual(len(meta.receivers), 1)
            self.assertEqual(meta.receivers[0].name, "com.app.BootReceiver")
            self.assertTrue(meta.receivers[0].exported)
            self.assertEqual(
                meta.receivers[0].intent_actions,
                ["android.intent.action.BOOT_COMPLETED"],
            )

    def test_exported_components_property(self):
        with tempfile.TemporaryDirectory() as td:
            xml = _manifest_xml(
                package="com.app",
                activities=(
                    {"name": ".A", "exported": True},
                    {"name": ".B", "exported": False},
                ),
                services=({"name": ".S", "exported": True},),
            )
            m = self._write(Path(td), xml)
            meta = parse_android_manifest(m)
            exported = meta.exported_components
            self.assertEqual(len(exported), 2)
            names = {c.name for c in exported}
            self.assertEqual(names, {"com.app.A", "com.app.S"})

    def test_missing_file_raises(self):
        with self.assertRaises(ManifestParseError):
            parse_android_manifest("/nonexistent/AndroidManifest.xml")

    def test_binary_axml_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "AndroidManifest.xml"
            # AXML magic header
            p.write_bytes(b"\x03\x00\x08\x00\x00\x00\x00\x00")
            with self.assertRaises(ManifestParseError) as ctx:
                parse_android_manifest(p)
            self.assertIn("binary AXML", str(ctx.exception))

    def test_malformed_xml_raises(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "AndroidManifest.xml"
            p.write_text("<not-closed-tag>")
            with self.assertRaises(ManifestParseError):
                parse_android_manifest(p)

    def test_wrong_root_element_raises(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "AndroidManifest.xml"
            p.write_text("<wrong/>")
            with self.assertRaises(ManifestParseError):
                parse_android_manifest(p)

    def test_no_application_section(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "AndroidManifest.xml"
            p.write_text(
                '<?xml version="1.0"?>\n'
                '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.x"/>\n'
            )
            meta = parse_android_manifest(p)
            self.assertEqual(meta.package_name, "com.x")
            self.assertEqual(meta.components, [])
            self.assertIsNone(meta.application_class)

    def test_activity_alias_mapped_to_activity_type(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "AndroidManifest.xml"
            p.write_text(
                '<?xml version="1.0"?>\n'
                '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="p">\n'
                '  <application>\n'
                '    <activity-alias android:name=".Alias" android:targetActivity=".Real" android:exported="true"/>\n'
                '  </application>\n'
                '</manifest>\n'
            )
            meta = parse_android_manifest(p)
            self.assertEqual(len(meta.activities), 1)
            self.assertEqual(meta.activities[0].type, "activity")
            self.assertEqual(meta.activities[0].name, "p.Alias")

    def test_provider_authorities_single(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "AndroidManifest.xml"
            p.write_text(
                '<?xml version="1.0"?>\n'
                '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.x">\n'
                '  <application>\n'
                '    <provider android:name=".FileProv"\n'
                '              android:authorities="com.x.fileprovider"\n'
                '              android:exported="true"\n'
                '              android:grantUriPermissions="true"/>\n'
                '  </application>\n'
                '</manifest>\n'
            )
            meta = parse_android_manifest(p)
            self.assertEqual(len(meta.providers), 1)
            prov = meta.providers[0]
            self.assertEqual(prov.authorities, ["com.x.fileprovider"])
            self.assertTrue(prov.grant_uri_permissions)

    def test_provider_authorities_semicolon_split(self):
        # Per Android spec android:authorities accepts a ';' separated list.
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "AndroidManifest.xml"
            p.write_text(
                '<?xml version="1.0"?>\n'
                '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.x">\n'
                '  <application>\n'
                '    <provider android:name=".P"\n'
                '              android:authorities="com.x.primary; com.x.legacy ;com.x.alt"\n'
                '              android:exported="true"/>\n'
                '  </application>\n'
                '</manifest>\n'
            )
            meta = parse_android_manifest(p)
            self.assertEqual(
                meta.providers[0].authorities,
                ["com.x.primary", "com.x.legacy", "com.x.alt"],
            )

    def test_non_provider_components_have_empty_authorities(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "AndroidManifest.xml"
            p.write_text(
                '<?xml version="1.0"?>\n'
                '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.x">\n'
                '  <application>\n'
                '    <activity android:name=".A"/>\n'
                '    <service android:name=".S"/>\n'
                '  </application>\n'
                '</manifest>\n'
            )
            meta = parse_android_manifest(p)
            self.assertEqual(meta.activities[0].authorities, [])
            self.assertEqual(meta.services[0].authorities, [])

    def test_provider_without_authorities_attribute(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "AndroidManifest.xml"
            p.write_text(
                '<?xml version="1.0"?>\n'
                '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.x">\n'
                '  <application>\n'
                '    <provider android:name=".P" android:exported="true"/>\n'
                '  </application>\n'
                '</manifest>\n'
            )
            meta = parse_android_manifest(p)
            self.assertEqual(meta.providers[0].authorities, [])


# ---------- intent-filter structured parsing (Phase 6-3) ----------


class TestIntentFilterParsing(unittest.TestCase):
    def _parse_first_activity(self, td: Path, manifest_body: str) -> AndroidComponent:
        m = td / "AndroidManifest.xml"
        m.write_text(manifest_body, encoding="utf-8")
        meta = parse_android_manifest(m)
        return meta.activities[0]

    def test_action_only_filter(self):
        with tempfile.TemporaryDirectory() as td:
            act = self._parse_first_activity(Path(td), (
                '<?xml version="1.0"?>\n'
                '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
                'package="com.app">\n'
                '  <application>\n'
                '    <activity android:name=".A">\n'
                '      <intent-filter>\n'
                '        <action android:name="android.intent.action.MAIN"/>\n'
                '        <category android:name="android.intent.category.LAUNCHER"/>\n'
                '      </intent-filter>\n'
                '    </activity>\n'
                '  </application>\n'
                '</manifest>\n'
            ))
            self.assertEqual(len(act.intent_filters), 1)
            f = act.intent_filters[0]
            self.assertEqual(f.actions, ["android.intent.action.MAIN"])
            self.assertEqual(f.categories, ["android.intent.category.LAUNCHER"])
            self.assertEqual(f.data, [])
            self.assertTrue(f.is_launcher)
            self.assertFalse(f.is_browsable)

    def test_browsable_deeplink_with_scheme_host_path(self):
        with tempfile.TemporaryDirectory() as td:
            act = self._parse_first_activity(Path(td), (
                '<?xml version="1.0"?>\n'
                '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
                'package="com.app">\n'
                '  <application>\n'
                '    <activity android:name=".Deep">\n'
                '      <intent-filter>\n'
                '        <action android:name="android.intent.action.VIEW"/>\n'
                '        <category android:name="android.intent.category.DEFAULT"/>\n'
                '        <category android:name="android.intent.category.BROWSABLE"/>\n'
                '        <data android:scheme="myapp" android:host="auth" '
                'android:pathPrefix="/oauth"/>\n'
                '      </intent-filter>\n'
                '    </activity>\n'
                '  </application>\n'
                '</manifest>\n'
            ))
            self.assertEqual(len(act.intent_filters), 1)
            f = act.intent_filters[0]
            self.assertTrue(f.is_browsable)
            self.assertEqual(len(f.data), 1)
            d = f.data[0]
            self.assertEqual(d.scheme, "myapp")
            self.assertEqual(d.host, "auth")
            self.assertEqual(d.path_prefix, "/oauth")
            self.assertIsNone(d.path)
            self.assertEqual(act.data_schemes, ["myapp"])
            self.assertTrue(act.is_browsable)

    def test_multiple_filters_preserved_separately(self):
        # Same activity often has LAUNCHER (no data) plus a separate
        # BROWSABLE filter — flattening loses that pairing.
        with tempfile.TemporaryDirectory() as td:
            act = self._parse_first_activity(Path(td), (
                '<?xml version="1.0"?>\n'
                '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
                'package="com.app">\n'
                '  <application>\n'
                '    <activity android:name=".A">\n'
                '      <intent-filter>\n'
                '        <action android:name="android.intent.action.MAIN"/>\n'
                '        <category android:name="android.intent.category.LAUNCHER"/>\n'
                '      </intent-filter>\n'
                '      <intent-filter>\n'
                '        <action android:name="android.intent.action.VIEW"/>\n'
                '        <category android:name="android.intent.category.BROWSABLE"/>\n'
                '        <data android:scheme="myapp"/>\n'
                '      </intent-filter>\n'
                '    </activity>\n'
                '  </application>\n'
                '</manifest>\n'
            ))
            self.assertEqual(len(act.intent_filters), 2)
            self.assertTrue(act.intent_filters[0].is_launcher)
            self.assertFalse(act.intent_filters[0].is_browsable)
            self.assertEqual(act.intent_filters[0].data, [])
            self.assertTrue(act.intent_filters[1].is_browsable)
            self.assertEqual(act.intent_filters[1].data[0].scheme, "myapp")

    def test_data_with_only_mime_type(self):
        with tempfile.TemporaryDirectory() as td:
            act = self._parse_first_activity(Path(td), (
                '<?xml version="1.0"?>\n'
                '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
                'package="com.app">\n'
                '  <application>\n'
                '    <activity android:name=".A">\n'
                '      <intent-filter>\n'
                '        <action android:name="android.intent.action.SEND"/>\n'
                '        <data android:mimeType="image/*"/>\n'
                '      </intent-filter>\n'
                '    </activity>\n'
                '  </application>\n'
                '</manifest>\n'
            ))
            d = act.intent_filters[0].data[0]
            self.assertEqual(d.mime_type, "image/*")
            self.assertIsNone(d.scheme)
            self.assertEqual(act.data_schemes, [])

    def test_empty_data_element_skipped(self):
        # Buggy/placeholder <data/> with no attributes is meaningless and
        # should not pollute the spec list.
        with tempfile.TemporaryDirectory() as td:
            act = self._parse_first_activity(Path(td), (
                '<?xml version="1.0"?>\n'
                '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
                'package="com.app">\n'
                '  <application>\n'
                '    <activity android:name=".A">\n'
                '      <intent-filter>\n'
                '        <action android:name="android.intent.action.SEND"/>\n'
                '        <data/>\n'
                '        <data android:scheme="https"/>\n'
                '      </intent-filter>\n'
                '    </activity>\n'
                '  </application>\n'
                '</manifest>\n'
            ))
            self.assertEqual(len(act.intent_filters[0].data), 1)
            self.assertEqual(act.intent_filters[0].data[0].scheme, "https")

    def test_path_pattern_and_suffix_captured(self):
        with tempfile.TemporaryDirectory() as td:
            act = self._parse_first_activity(Path(td), (
                '<?xml version="1.0"?>\n'
                '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
                'package="com.app">\n'
                '  <application>\n'
                '    <activity android:name=".A">\n'
                '      <intent-filter>\n'
                '        <action android:name="android.intent.action.VIEW"/>\n'
                '        <data android:scheme="https" android:host="example.com"\n'
                '              android:pathPattern="/api/.*"\n'
                '              android:pathSuffix=".html"\n'
                '              android:port="8443"/>\n'
                '      </intent-filter>\n'
                '    </activity>\n'
                '  </application>\n'
                '</manifest>\n'
            ))
            d = act.intent_filters[0].data[0]
            self.assertEqual(d.path_pattern, "/api/.*")
            self.assertEqual(d.path_suffix, ".html")
            self.assertEqual(d.port, "8443")

    def test_intent_actions_compat_remains_flat(self):
        # Existing consumers (manifest_audit MANIFEST-004 etc.) read the flat
        # intent_actions list. Phase 6-3 must not break that contract.
        with tempfile.TemporaryDirectory() as td:
            act = self._parse_first_activity(Path(td), (
                '<?xml version="1.0"?>\n'
                '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
                'package="com.app">\n'
                '  <application>\n'
                '    <activity android:name=".A">\n'
                '      <intent-filter>\n'
                '        <action android:name="android.intent.action.MAIN"/>\n'
                '      </intent-filter>\n'
                '      <intent-filter>\n'
                '        <action android:name="android.intent.action.VIEW"/>\n'
                '        <action android:name="android.intent.action.SEND"/>\n'
                '      </intent-filter>\n'
                '    </activity>\n'
                '  </application>\n'
                '</manifest>\n'
            ))
            self.assertEqual(act.intent_actions, [
                "android.intent.action.MAIN",
                "android.intent.action.VIEW",
                "android.intent.action.SEND",
            ])

    def test_to_from_dict_roundtrip(self):
        # Cache replay loads components via from_dict; structured filters
        # must survive serialization.
        c = AndroidComponent(
            type="activity", name="com.app.A",
            exported=True, exported_declared=True,
            intent_actions=["android.intent.action.VIEW"],
            intent_filters=[IntentFilter(
                actions=["android.intent.action.VIEW"],
                categories=["android.intent.category.BROWSABLE"],
                data=[IntentDataSpec(scheme="https", host="example.com",
                                     path_prefix="/x")],
            )],
        )
        roundtripped = AndroidComponent.from_dict(c.to_dict())
        self.assertEqual(len(roundtripped.intent_filters), 1)
        f = roundtripped.intent_filters[0]
        self.assertEqual(f.categories, ["android.intent.category.BROWSABLE"])
        self.assertEqual(f.data[0].scheme, "https")
        self.assertEqual(f.data[0].path_prefix, "/x")


# ---------- network_security_config XML resolution & parsing ----------


def _write_nsc(td: Path, body: str, name: str = "nsc") -> Path:
    res_xml = td / "res" / "xml"
    res_xml.mkdir(parents=True, exist_ok=True)
    nsc_path = res_xml / f"{name}.xml"
    nsc_path.write_text(body, encoding="utf-8")
    return nsc_path


class TestNetworkSecurityConfigParsing(unittest.TestCase):
    def _write_manifest(self, td: Path, ref: str | None) -> Path:
        xml = _manifest_xml(package="com.app", network_security_config=ref)
        m = td / "AndroidManifest.xml"
        m.write_text(xml)
        return m

    def test_no_nsc_attribute_yields_none(self):
        with tempfile.TemporaryDirectory() as td:
            m = self._write_manifest(Path(td), None)
            meta = parse_android_manifest(m)
            self.assertIsNone(meta.network_security_config)
            self.assertIsNone(meta.nsc)

    def test_nsc_referenced_but_file_missing_keeps_nsc_none(self):
        with tempfile.TemporaryDirectory() as td:
            m = self._write_manifest(Path(td), "@xml/nsc")
            meta = parse_android_manifest(m)
            self.assertEqual(meta.network_security_config, "@xml/nsc")
            self.assertIsNone(meta.nsc)

    def test_base_cleartext_true_is_captured(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            _write_nsc(tdp, (
                '<?xml version="1.0" encoding="utf-8"?>\n'
                '<network-security-config>\n'
                '  <base-config cleartextTrafficPermitted="true"/>\n'
                '</network-security-config>\n'
            ))
            m = self._write_manifest(tdp, "@xml/nsc")
            meta = parse_android_manifest(m)
            self.assertIsNotNone(meta.nsc)
            self.assertTrue(meta.nsc.base_cleartext_permitted)
            self.assertEqual(meta.nsc.cleartext_domains, [])
            self.assertFalse(meta.nsc.base_trusts_user_certs)

    def test_base_cleartext_false_is_captured(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            _write_nsc(tdp, (
                '<?xml version="1.0"?>\n'
                '<network-security-config>\n'
                '  <base-config cleartextTrafficPermitted="false"/>\n'
                '</network-security-config>\n'
            ))
            m = self._write_manifest(tdp, "@xml/nsc")
            meta = parse_android_manifest(m)
            self.assertIsNotNone(meta.nsc)
            self.assertFalse(meta.nsc.base_cleartext_permitted)

    def test_domain_cleartext_collected(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            _write_nsc(tdp, (
                '<?xml version="1.0"?>\n'
                '<network-security-config>\n'
                '  <domain-config cleartextTrafficPermitted="true">\n'
                '    <domain includeSubdomains="true">example.com</domain>\n'
                '    <domain>legacy.example.org</domain>\n'
                '  </domain-config>\n'
                '  <domain-config cleartextTrafficPermitted="false">\n'
                '    <domain>secure.example.net</domain>\n'
                '  </domain-config>\n'
                '</network-security-config>\n'
            ))
            m = self._write_manifest(tdp, "@xml/nsc")
            meta = parse_android_manifest(m)
            self.assertEqual(
                meta.nsc.cleartext_domains,
                ["example.com", "legacy.example.org"],
            )

    def test_user_cert_trust_in_base_config(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            _write_nsc(tdp, (
                '<?xml version="1.0"?>\n'
                '<network-security-config>\n'
                '  <base-config>\n'
                '    <trust-anchors>\n'
                '      <certificates src="system"/>\n'
                '      <certificates src="user"/>\n'
                '    </trust-anchors>\n'
                '  </base-config>\n'
                '</network-security-config>\n'
            ))
            m = self._write_manifest(tdp, "@xml/nsc")
            meta = parse_android_manifest(m)
            self.assertTrue(meta.nsc.base_trusts_user_certs)

    def test_empty_policy_returns_default_record(self):
        # NSC file present but only inert policy (e.g. pin-set without cleartext
        # or user-cert trust). Should still yield a record so callers know the
        # file was resolved — just one with all audit-relevant fields neutral.
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            _write_nsc(tdp, (
                '<?xml version="1.0"?>\n'
                '<network-security-config>\n'
                '  <domain-config>\n'
                '    <domain>example.com</domain>\n'
                '    <pin-set><pin digest="SHA-256">aaaa</pin></pin-set>\n'
                '  </domain-config>\n'
                '</network-security-config>\n'
            ))
            m = self._write_manifest(tdp, "@xml/nsc")
            meta = parse_android_manifest(m)
            self.assertIsNotNone(meta.nsc)
            self.assertIsNone(meta.nsc.base_cleartext_permitted)
            self.assertEqual(meta.nsc.cleartext_domains, [])
            self.assertFalse(meta.nsc.base_trusts_user_certs)

    def test_resource_ref_with_namespace_prefix_resolves(self):
        # apktool sometimes emits the package-qualified form. The resolver
        # should still find the same xml file.
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            _write_nsc(tdp, (
                '<?xml version="1.0"?>\n'
                '<network-security-config>\n'
                '  <base-config cleartextTrafficPermitted="true"/>\n'
                '</network-security-config>\n'
            ))
            m = self._write_manifest(tdp, "@com.app:xml/nsc")
            meta = parse_android_manifest(m)
            self.assertIsNotNone(meta.nsc)
            self.assertTrue(meta.nsc.base_cleartext_permitted)

    def test_non_xml_resource_ref_not_resolved(self):
        # @drawable/foo, @string/foo etc. must never be opened as NSC.
        with tempfile.TemporaryDirectory() as td:
            m = self._write_manifest(Path(td), "@drawable/foo")
            meta = parse_android_manifest(m)
            self.assertEqual(meta.network_security_config, "@drawable/foo")
            self.assertIsNone(meta.nsc)

    def test_malformed_nsc_xml_yields_none(self):
        # Defensive: a corrupt NSC must not crash the manifest parse — the
        # whole pipeline depends on it.
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            _write_nsc(tdp, "<<<not-xml>>>")
            m = self._write_manifest(tdp, "@xml/nsc")
            meta = parse_android_manifest(m)
            self.assertIsNone(meta.nsc)


# ---------- run_apktool_decode ----------


class TestRunApktoolDecode(unittest.TestCase):
    def test_missing_apk(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(ApktoolRunError):
                run_apktool_decode(
                    "/no/such/file.apk",
                    Path(td) / "out",
                    config=ApktoolConfig(apktool_path="/bin/true"),
                )

    def test_directory_apk(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(ApktoolRunError):
                run_apktool_decode(
                    td,
                    Path(td) / "out",
                    config=ApktoolConfig(apktool_path="/bin/true"),
                )

    def test_successful_invocation_with_stub(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            apk = tdp / "fake.apk"
            apk.write_bytes(b"PK\x03\x04stub")
            stub = make_stub_executable(
                tdp / "stub-apktool",
                out_flag="-o",
                files={"AndroidManifest.xml": '<manifest package="com.x"/>\n'},
                mkdirs=["smali/com/x"],
            )
            result = run_apktool_decode(apk, tdp / "out", ApktoolConfig(apktool_path=str(stub)))
            self.assertEqual(result.returncode, 0)
            self.assertTrue(result.manifest_path)
            self.assertTrue(result.smali_present)

    def test_no_manifest_produced_raises(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            apk = tdp / "fake.apk"
            apk.write_bytes(b"PK")
            stub = make_stub_executable(tdp / "fail-apktool", exit_code=5)
            with self.assertRaises(ApktoolRunError):
                run_apktool_decode(apk, tdp / "out", ApktoolConfig(apktool_path=str(stub)))

    def test_launch_os_error_is_wrapped(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            apk = tdp / "fake.apk"
            apk.write_bytes(b"PK")
            with mock.patch(
                "venomhook.apk_decoder.subprocess.run",
                side_effect=PermissionError("permission denied"),
            ):
                with self.assertRaises(ApktoolRunError) as ctx:
                    run_apktool_decode(
                        apk, tdp / "out", ApktoolConfig(apktool_path="/bad/apktool")
                    )
            self.assertIn("could not exec apktool binary", str(ctx.exception))

    def test_default_command_includes_force_and_o(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            apk = tdp / "x.apk"
            apk.write_bytes(b"PK")
            seen: dict[str, list[str]] = {}

            class FakeCompleted:
                returncode = 0
                stdout = ""
                stderr = ""

            def fake_run(cmd, **kw):
                seen["cmd"] = list(cmd)
                out_idx = cmd.index("-o") + 1
                Path(cmd[out_idx]).mkdir(parents=True, exist_ok=True)
                (Path(cmd[out_idx]) / "AndroidManifest.xml").write_text(
                    '<?xml version="1.0"?><manifest package="x"/>'
                )
                return FakeCompleted()

            with mock.patch("venomhook.apk_decoder.subprocess.run", side_effect=fake_run):
                run_apktool_decode(apk, tdp / "o", ApktoolConfig(apktool_path="/usr/bin/apktool"))
            cmd = seen["cmd"]
            self.assertEqual(cmd[0], "/usr/bin/apktool")
            self.assertEqual(cmd[1], "d")
            self.assertIn("--force", cmd)
            self.assertIn("-o", cmd)

    def test_no_src_no_res_flags(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            apk = tdp / "x.apk"
            apk.write_bytes(b"PK")
            seen: dict[str, list[str]] = {}

            class FakeCompleted:
                returncode = 0
                stdout = ""
                stderr = ""

            def fake_run(cmd, **kw):
                seen["cmd"] = list(cmd)
                out_idx = cmd.index("-o") + 1
                Path(cmd[out_idx]).mkdir(parents=True, exist_ok=True)
                (Path(cmd[out_idx]) / "AndroidManifest.xml").write_text(
                    '<?xml version="1.0"?><manifest package="x"/>'
                )
                return FakeCompleted()

            cfg = ApktoolConfig(
                apktool_path="/usr/bin/apktool", no_src=True, no_res=True, force=False
            )
            with mock.patch("venomhook.apk_decoder.subprocess.run", side_effect=fake_run):
                run_apktool_decode(apk, tdp / "o", cfg)
            cmd = seen["cmd"]
            self.assertIn("--no-src", cmd)
            self.assertIn("--no-res", cmd)
            self.assertNotIn("--force", cmd)


# ---------- decode_apk (end-to-end with stub) ----------


class TestDecodeApk(unittest.TestCase):
    def test_pipeline(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            apk = tdp / "fake.apk"
            apk.write_bytes(b"PK")
            stub = make_stub_executable(
                tdp / "stub-apktool",
                out_flag="-o",
                files={
                    "AndroidManifest.xml": (
                        '<?xml version="1.0"?>\n'
                        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.demo">\n'
                        '    <uses-permission android:name="android.permission.INTERNET"/>\n'
                        '    <application android:name=".App">\n'
                        '        <activity android:name=".MainActivity" android:exported="true">\n'
                        '            <intent-filter>\n'
                        '                <action android:name="android.intent.action.MAIN"/>\n'
                        '            </intent-filter>\n'
                        '        </activity>\n'
                        '    </application>\n'
                        '</manifest>\n'
                    )
                },
            )

            result, meta = decode_apk(apk, tdp / "o", ApktoolConfig(apktool_path=str(stub)))
            self.assertTrue(result.manifest_path)
            self.assertEqual(meta.package_name, "com.demo")
            self.assertEqual(meta.application_class, "com.demo.App")
            self.assertEqual(meta.permissions, ["android.permission.INTERNET"])
            self.assertEqual(len(meta.activities), 1)
            self.assertEqual(meta.activities[0].name, "com.demo.MainActivity")
            self.assertTrue(meta.activities[0].exported)


# ---------- model round-trip ----------


class TestAndroidModels(unittest.TestCase):
    def test_component_round_trip(self):
        c = AndroidComponent(
            type="activity",
            name="com.x.A",
            exported=True,
            permission="com.x.PERM",
            intent_actions=["android.intent.action.MAIN"],
        )
        round = AndroidComponent.from_dict(c.to_dict())
        self.assertEqual(round, c)

    def test_component_to_dict_omits_optional(self):
        c = AndroidComponent(type="service", name="com.x.S")
        d = c.to_dict()
        self.assertNotIn("permission", d)
        self.assertNotIn("intent_actions", d)

    def test_app_meta_round_trip(self):
        meta = AndroidAppMeta(
            package_name="com.x",
            application_class="com.x.App",
            permissions=["android.permission.INTERNET"],
            components=[
                AndroidComponent(type="activity", name="com.x.A", exported=True),
                AndroidComponent(type="service", name="com.x.S"),
            ],
            min_sdk=21,
            target_sdk=33,
            debuggable=True,
            extract_native_libs=False,
        )
        round = AndroidAppMeta.from_dict(meta.to_dict())
        self.assertEqual(round, meta)


if __name__ == "__main__":
    unittest.main()

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
from venomhook.models import AndroidAppMeta, AndroidComponent


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
            stub = tdp / "stub-apktool.sh"
            stub.write_text(textwrap.dedent("""\
                #!/bin/sh
                # apktool d --force ... -o OUT apk_path
                while [ $# -gt 0 ]; do
                    case "$1" in
                        -o) shift; OUT="$1"; shift; ;;
                        *) shift; ;;
                    esac
                done
                mkdir -p "$OUT/smali/com/x"
                echo "<manifest package=\\"com.x\\"/>" > "$OUT/AndroidManifest.xml"
                exit 0
            """))
            stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
            result = run_apktool_decode(apk, tdp / "out", ApktoolConfig(apktool_path=str(stub)))
            self.assertEqual(result.returncode, 0)
            self.assertTrue(result.manifest_path)
            self.assertTrue(result.smali_present)

    def test_no_manifest_produced_raises(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            apk = tdp / "fake.apk"
            apk.write_bytes(b"PK")
            stub = tdp / "fail-apktool.sh"
            stub.write_text("#!/bin/sh\nexit 5\n")
            stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
            with self.assertRaises(ApktoolRunError):
                run_apktool_decode(apk, tdp / "out", ApktoolConfig(apktool_path=str(stub)))

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
            stub = tdp / "stub-apktool.sh"
            stub.write_text(textwrap.dedent("""\
                #!/bin/sh
                while [ $# -gt 0 ]; do
                    case "$1" in
                        -o) shift; OUT="$1"; shift; ;;
                        *) shift; ;;
                    esac
                done
                mkdir -p "$OUT"
                cat > "$OUT/AndroidManifest.xml" <<'EOF'
                <?xml version="1.0"?>
                <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.demo">
                    <uses-permission android:name="android.permission.INTERNET"/>
                    <application android:name=".App">
                        <activity android:name=".MainActivity" android:exported="true">
                            <intent-filter>
                                <action android:name="android.intent.action.MAIN"/>
                            </intent-filter>
                        </activity>
                    </application>
                </manifest>
                EOF
                exit 0
            """))
            stub.chmod(stub.stat().st_mode | stat.S_IXUSR)

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

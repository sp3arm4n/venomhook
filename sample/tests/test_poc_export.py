"""Tests for poc_export — write PoCArtifacts to runnable on-disk scripts.

Covers filename construction, kind→extension dispatch, header comment
content, executable bit on shell scripts, README index shape, and the
full round-trip of a multi-artifact bundle.
"""

from __future__ import annotations

import stat
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from venomhook.models import PoCArtifact
from venomhook.poc_export import (
    export_pocs,
    render_index,
    render_sh,
    slugify,
)


def _adb_artifact(**overrides) -> PoCArtifact:
    base = dict(
        rule_id="MANIFEST-001",
        title="Attach jdb to debuggable process",
        severity="high",
        kind="adb",
        package_name="com.demo",
        component="com.demo.MainActivity",
        description="Attach jdb via adb forward.",
        commands=["adb shell am start -D -n com.demo/.MainActivity",
                  "adb forward tcp:8700 jdwp:1234"],
        expected_evidence="jdb prompt appears.",
        notes="",
        references=["CWE-489"],
    )
    base.update(overrides)
    return PoCArtifact(**base)


class SlugifyTests(unittest.TestCase):
    def test_lowercase_hyphenated(self):
        self.assertEqual(slugify("Attach jdb to Debuggable PROCESS"),
                         "attach-jdb-to-debuggable-process")

    def test_strips_special_chars(self):
        self.assertEqual(slugify("foo.bar/baz_qux!"), "foo-bar-baz-qux")

    def test_collapses_runs(self):
        self.assertEqual(slugify("a   b  c"), "a-b-c")

    def test_strips_outer_hyphens(self):
        self.assertEqual(slugify("---hi---"), "hi")

    def test_max_len(self):
        self.assertLessEqual(len(slugify("a" * 200)), 60)

    def test_empty_falls_back(self):
        self.assertEqual(slugify(""), "artifact")
        self.assertEqual(slugify("---"), "artifact")


class RenderShTests(unittest.TestCase):
    def test_shebang_first(self):
        out = render_sh(_adb_artifact())
        self.assertTrue(out.startswith("#!/bin/sh\n"))

    def test_header_includes_metadata(self):
        out = render_sh(_adb_artifact())
        self.assertIn("MANIFEST-001", out)
        self.assertIn("심각도:    high", out)
        self.assertIn("패키지:    com.demo", out)
        self.assertIn("컴포넌트:  com.demo.MainActivity", out)
        self.assertIn("CWE-489", out)
        self.assertIn("예상 결과:", out)

    def test_commands_appear_after_header(self):
        out = render_sh(_adb_artifact())
        # Both commands present and outside of comment lines (no leading '# ')
        for cmd in ("adb shell am start", "adb forward tcp:8700"):
            self.assertIn(cmd, out)
            for line in out.splitlines():
                if cmd in line:
                    self.assertFalse(line.lstrip().startswith("#"),
                                     f"{cmd} should not be commented out")

    def test_no_commands_falls_back_to_echo(self):
        out = render_sh(_adb_artifact(commands=[]))
        self.assertIn("기록된 명령이 없습니다", out)

    def test_multiline_header_fields_remain_comments(self):
        out = render_sh(_adb_artifact(
            title="safe title\nuname -a",
            component="com.demo.MainActivity\nid",
            description="description\nwhoami",
            expected_evidence="evidence\ncat /etc/passwd",
            notes="note\npwd",
            references=["CWE-489\nprintf pwned"],
        ))
        header = out.split("\nset -u", 1)[0]
        for line in header.splitlines():
            self.assertTrue(
                line.startswith("#"),
                f"header line is not commented: {line!r}",
            )
        self.assertNotIn("\nuname -a", out)
        self.assertNotIn("\nid", out)
        self.assertNotIn("\nwhoami", out)


class RenderIndexTests(unittest.TestCase):
    def test_groups_artifacts_under_finding_headings(self):
        # Two artifacts -> two findings (different rule_id)
        arts = [_adb_artifact(), _adb_artifact(rule_id="MANIFEST-003",
                                                title="adb backup",
                                                severity="medium")]
        names = ["MANIFEST-001-1_a.sh", "MANIFEST-003-2_b.sh"]
        out = render_index(arts, names)
        self.assertIn("# venomhook PoC 번들", out)
        # New per-recipe table header
        self.assertIn("| # | 종류 | 레시피 | 파일 |", out)
        # Finding headings include severity + rule id
        self.assertIn("### [HIGH] MANIFEST-001", out)
        self.assertIn("### [MEDIUM] MANIFEST-003", out)
        # File links survive
        self.assertIn("MANIFEST-001-1_a.sh", out)
        self.assertIn("MANIFEST-003-2_b.sh", out)

    def test_groups_pocs_for_same_finding_under_one_heading(self):
        # Same rule_id + same component -> single heading with two rows
        arts = [
            _adb_artifact(rule_id="MANIFEST-004", title="invoke",
                          component="com.x.A"),
            _adb_artifact(rule_id="MANIFEST-004", title="observe",
                          component="com.x.A"),
        ]
        names = ["MANIFEST-004-1_a.sh", "MANIFEST-004-2_b.sh"]
        out = render_index(arts, names)
        # Exactly one heading
        self.assertEqual(out.count("### [HIGH] MANIFEST-004"), 1)
        # Both recipes visible in the same group's table
        self.assertIn("invoke", out)
        self.assertIn("observe", out)

    def test_severity_ordering_critical_first(self):
        arts = [
            _adb_artifact(rule_id="A1", severity="info", title="t"),
            _adb_artifact(rule_id="A2", severity="critical", title="t"),
            _adb_artifact(rule_id="A3", severity="medium", title="t"),
        ]
        names = ["A1-1_t.sh", "A2-2_t.sh", "A3-3_t.sh"]
        out = render_index(arts, names)
        i_crit = out.find("[CRITICAL] A2")
        i_med = out.find("[MEDIUM] A3")
        i_info = out.find("[INFO] A1")
        self.assertTrue(0 <= i_crit < i_med < i_info,
                        f"expected critical < medium < info, got {i_crit}, {i_med}, {i_info}")

    def test_finding_count_in_subtitle(self):
        arts = [_adb_artifact(rule_id="A1"), _adb_artifact(rule_id="A2")]
        names = ["A1-1_t.sh", "A2-2_t.sh"]
        out = render_index(arts, names)
        self.assertIn("아티팩트 2개 (취약점 2건 기준)", out)

    def test_component_label_rendered_when_present(self):
        arts = [_adb_artifact(rule_id="MANIFEST-004",
                              component="com.x.LoginActivity")]
        names = ["MANIFEST-004-1_a.sh"]
        out = render_index(arts, names)
        self.assertIn("`com.x.LoginActivity`", out)

    def test_markdown_table_escapes_untrusted_text(self):
        arts = [_adb_artifact(
            rule_id="MANIFEST-004",
            title="bad | title\nsecond line",
            component="com.x.`A`|B\nC",
            kind="adb|shell",
        )]
        names = ["MANIFEST-004-1_bad.sh"]
        out = render_index(arts, names)
        self.assertIn("bad \\| title second line", out)
        self.assertIn("adb\\|shell", out)
        self.assertIn("com.x.`A`\\|B C", out)
        self.assertNotIn("\nsecond line", out)

    def test_empty_bundle_still_renders(self):
        out = render_index([], [])
        self.assertIn("아티팩트 0개", out)


class ExportPocsTests(unittest.TestCase):
    def test_writes_sh_for_adb_artifact_with_executable_bit(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td) / "pocs"
            paths = export_pocs([_adb_artifact()], tdp)
            self.assertTrue(tdp.exists())
            sh_files = [p for p in paths if p.suffix == ".sh"]
            self.assertEqual(len(sh_files), 1)
            sh = sh_files[0]
            self.assertEqual(sh.name,
                             "MANIFEST-001-1_attach-jdb-to-debuggable-process.sh")
            mode = sh.stat().st_mode
            self.assertTrue(mode & stat.S_IXUSR)
            self.assertTrue(mode & stat.S_IXGRP)

    def test_creates_readme_index(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td) / "pocs"
            export_pocs([_adb_artifact()], tdp)
            readme = tdp / "README.md"
            self.assertTrue(readme.exists())
            content = readme.read_text(encoding="utf-8")
            self.assertIn("MANIFEST-001", content)
            self.assertIn("attach-jdb-to-debuggable-process", content)

    def test_writes_localized_bundle_as_utf8(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td) / "pocs"
            paths = export_pocs([
                _adb_artifact(
                    title="디버깅 가능 프로세스",
                    description="한글 설명 — UTF-8로 기록되어야 합니다.",
                )
            ], tdp)
            for path in paths:
                text = path.read_text(encoding="utf-8")
                self.assertTrue(text)

    def test_creates_directory_when_missing(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "nested" / "pocs"
            self.assertFalse(target.exists())
            export_pocs([_adb_artifact()], target)
            self.assertTrue(target.is_dir())

    def test_kind_dispatch(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td) / "pocs"
            arts = [
                _adb_artifact(rule_id="R-1", kind="adb",  title="adb-thing"),
                _adb_artifact(rule_id="R-2", kind="shell", title="shell-thing"),
                _adb_artifact(rule_id="R-3", kind="frida", title="frida-thing",
                              commands=["console.log('hi');"]),
                _adb_artifact(rule_id="R-4", kind="info", title="info-thing"),
            ]
            paths = export_pocs(arts, tdp)
            ext_for_rule = {p.stem.split("_", 1)[0].split("-", 2)[0:2][0]:
                            p.suffix for p in paths if p.name != "README.md"}
            # Map by rule id
            by_rule = {p.name.split("-", 1)[0] + "-"
                       + p.name.split("-", 2)[1]: p
                       for p in paths if p.name != "README.md"}
            self.assertTrue(by_rule["R-1"].name.endswith(".sh"))
            self.assertTrue(by_rule["R-2"].name.endswith(".sh"))
            self.assertTrue(by_rule["R-3"].name.endswith(".frida.js"))
            self.assertTrue(by_rule["R-4"].name.endswith(".md"))

    def test_idempotent_overwrite(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td) / "pocs"
            export_pocs([_adb_artifact()], tdp)
            files_first = sorted(p.name for p in tdp.iterdir())
            export_pocs([_adb_artifact()], tdp)
            files_second = sorted(p.name for p in tdp.iterdir())
            self.assertEqual(files_first, files_second)

    def test_filename_indexed_to_avoid_collisions(self):
        # Two artifacts with the same rule_id and title get unique names
        # because the index suffix is part of the filename.
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td) / "pocs"
            arts = [_adb_artifact(), _adb_artifact()]
            paths = export_pocs(arts, tdp)
            sh_names = sorted(p.name for p in paths if p.suffix == ".sh")
            self.assertEqual(len(sh_names), 2)
            self.assertNotEqual(sh_names[0], sh_names[1])
            self.assertTrue(sh_names[0].startswith("MANIFEST-001-1_"))
            self.assertTrue(sh_names[1].startswith("MANIFEST-001-2_"))

    def test_empty_artifacts_writes_only_index(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td) / "pocs"
            paths = export_pocs([], tdp)
            self.assertEqual(len(paths), 1)
            self.assertEqual(paths[0].name, "README.md")


if __name__ == "__main__":
    unittest.main()

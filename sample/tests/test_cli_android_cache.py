"""Tests for `android-cache-list` and `android-cache-diff` CLI subcommands.

Pre-populates an AnalysisCache with hand-built AndroidAnalysis records,
then drives the CLI through each subcommand exit-code path.
"""

from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from venomhook.analysis_cache import AnalysisCache
from venomhook.android_pipeline import AndroidAnalysis
from venomhook.apk_extractor import ApkMeta
from venomhook.binary_meta import BinaryMeta
from venomhook.cli import main
from venomhook.models import (
    AndroidAppMeta,
    AndroidAuditReport,
    ManifestFinding,
)


def _bm() -> BinaryMeta:
    return BinaryMeta(
        name="libfoo.so", path="/abs/libfoo.so", hash="sha256:lh",
        format="ELF", arch="arm64", os_hint="android",
        image_base=0, aslr=True,
    )


def _analysis(apk_hash: str, package: str,
              findings: list[ManifestFinding] | None = None) -> AndroidAnalysis:
    return AndroidAnalysis(
        apk_meta=ApkMeta(path=f"/{apk_hash}.apk", name="x.apk", hash=apk_hash),
        selected_abi="arm64-v8a",
        extracted_so_path="/tmp/lib.so",
        so_meta=_bm(),
        app_meta=AndroidAppMeta(package_name=package),
        audit_report=AndroidAuditReport(
            package_name=package, findings=list(findings or []),
        ),
    )


def _finding(rule_id: str, **overrides) -> ManifestFinding:
    base = dict(rule_id=rule_id, title="t", severity="high",
                 detail="", remediation="", component=None,
                 references=[])
    base.update(overrides)
    return ManifestFinding(**base)


def _populate(cache_dir: Path, *records: AndroidAnalysis) -> None:
    cache_dir.mkdir(parents=True, exist_ok=True)
    with AnalysisCache(cache_dir / "cache.db") as cache:
        for r in records:
            cache.put(r)


def _run(argv: list[str]) -> str:
    buf = io.StringIO()
    with redirect_stdout(buf):
        main(argv)
    return buf.getvalue()


class CacheListTests(unittest.TestCase):
    def test_missing_cache_exits_1(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(SystemExit) as ctx:
                _run(["android-cache-list",
                      "--cache-dir", str(Path(td) / "nope")])
            self.assertEqual(ctx.exception.code, 1)

    def test_empty_cache_message(self):
        with tempfile.TemporaryDirectory() as td:
            cache_dir = Path(td) / "c"
            cache_dir.mkdir()
            # Touch DB by opening once.
            AnalysisCache(cache_dir / "cache.db").close()
            out = _run(["android-cache-list", "--cache-dir", str(cache_dir)])
            self.assertIn("(cache is empty)", out)

    def test_text_table_lists_entries(self):
        with tempfile.TemporaryDirectory() as td:
            cache_dir = Path(td) / "c"
            _populate(
                cache_dir,
                _analysis("sha256:aa", "com.a", [_finding("MANIFEST-001")]),
                _analysis("sha256:bb", "com.b"),
            )
            out = _run(["android-cache-list", "--cache-dir", str(cache_dir)])
            self.assertIn("apk_hash", out)
            self.assertIn("com.a", out)
            self.assertIn("com.b", out)

    def test_json_emits_machine_readable_list(self):
        with tempfile.TemporaryDirectory() as td:
            cache_dir = Path(td) / "c"
            _populate(
                cache_dir,
                _analysis("sha256:aa", "com.a"),
                _analysis("sha256:bb", "com.b"),
            )
            out = _run([
                "android-cache-list", "--cache-dir", str(cache_dir), "--json",
            ])
            data = json.loads(out)
            self.assertEqual(len(data), 2)
            packages = sorted(d["package_name"] for d in data)
            self.assertEqual(packages, ["com.a", "com.b"])
            for entry in data:
                self.assertIn("apk_hash", entry)
                self.assertIn("schema_version", entry)
                self.assertIn("created_at", entry)


class CacheDiffTests(unittest.TestCase):
    def test_missing_old_hash_exits_1(self):
        with tempfile.TemporaryDirectory() as td:
            cache_dir = Path(td) / "c"
            _populate(cache_dir, _analysis("sha256:bb", "com.b"))
            with self.assertRaises(SystemExit) as ctx:
                _run([
                    "android-cache-diff",
                    "--cache-dir", str(cache_dir),
                    "--old", "sha256:never",
                    "--new", "sha256:bb",
                ])
            self.assertEqual(ctx.exception.code, 1)

    def test_diff_renders_added_finding(self):
        with tempfile.TemporaryDirectory() as td:
            cache_dir = Path(td) / "c"
            _populate(
                cache_dir,
                _analysis("sha256:old", "com.x", []),
                _analysis("sha256:new", "com.x",
                          [_finding("MANIFEST-002")]),
            )
            out = _run([
                "android-cache-diff",
                "--cache-dir", str(cache_dir),
                "--old", "sha256:old",
                "--new", "sha256:new",
            ])
            self.assertIn("Findings added", out)
            self.assertIn("MANIFEST-002", out)

    def test_diff_no_changes_message(self):
        with tempfile.TemporaryDirectory() as td:
            cache_dir = Path(td) / "c"
            # Both analyses have the same shape — same hash so they're the
            # same row. Use distinct hashes pointing at equal content.
            _populate(
                cache_dir,
                _analysis("sha256:a", "com.x", [_finding("MANIFEST-001")]),
                _analysis("sha256:b", "com.x", [_finding("MANIFEST-001")]),
            )
            out = _run([
                "android-cache-diff",
                "--cache-dir", str(cache_dir),
                "--old", "sha256:a",
                "--new", "sha256:b",
            ])
            self.assertIn("(no changes)", out)

    def test_exit_on_changes_returns_2(self):
        with tempfile.TemporaryDirectory() as td:
            cache_dir = Path(td) / "c"
            _populate(
                cache_dir,
                _analysis("sha256:old", "com.x", []),
                _analysis("sha256:new", "com.x",
                          [_finding("MANIFEST-002")]),
            )
            with self.assertRaises(SystemExit) as ctx:
                _run([
                    "android-cache-diff",
                    "--cache-dir", str(cache_dir),
                    "--old", "sha256:old",
                    "--new", "sha256:new",
                    "--exit-on-changes",
                ])
            self.assertEqual(ctx.exception.code, 2)

    def test_exit_on_changes_zero_when_no_diff(self):
        with tempfile.TemporaryDirectory() as td:
            cache_dir = Path(td) / "c"
            _populate(
                cache_dir,
                _analysis("sha256:a", "com.x", [_finding("MANIFEST-001")]),
                _analysis("sha256:b", "com.x", [_finding("MANIFEST-001")]),
            )
            # Should not raise SystemExit.
            _run([
                "android-cache-diff",
                "--cache-dir", str(cache_dir),
                "--old", "sha256:a",
                "--new", "sha256:b",
                "--exit-on-changes",
            ])

    def test_json_output_path(self):
        with tempfile.TemporaryDirectory() as td:
            cache_dir = Path(td) / "c"
            _populate(
                cache_dir,
                _analysis("sha256:old", "com.x", []),
                _analysis("sha256:new", "com.x", [_finding("MANIFEST-002")]),
            )
            out_json = Path(td) / "diff.json"
            _run([
                "android-cache-diff",
                "--cache-dir", str(cache_dir),
                "--old", "sha256:old",
                "--new", "sha256:new",
                "--json", str(out_json),
            ])
            payload = json.loads(out_json.read_text())
            self.assertEqual(len(payload["added_findings"]), 1)
            self.assertEqual(payload["added_findings"][0]["rule_id"],
                              "MANIFEST-002")


if __name__ == "__main__":
    unittest.main()

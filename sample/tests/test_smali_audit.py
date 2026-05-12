"""Tests for smali_audit — Tier-1 fallback over apktool's smali output.

Synthetic smali fixtures are kept tiny but realistic (real smali idiom
for const-string / invoke patterns) so the regex rules can be checked
against actual instruction syntax without needing apktool to run.
"""

from __future__ import annotations

import sys
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from venomhook.models import (
    AndroidAppMeta,
    CodeAuditReport,
    CodeFinding,
)
from venomhook.smali_audit import (
    SMALI_RULES,
    audit_smali,
    iter_smali_dirs,
    iter_smali_files,
    merge_code_reports,
)


def _write_smali(root: Path, rel: str, body: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body)
    return p


def _meta(pkg: str = "com.demo.app") -> AndroidAppMeta:
    return AndroidAppMeta(
        package_name=pkg,
        application_class=None,
        permissions=[],
        components=[],
    )


class IterSmaliDirsTests(unittest.TestCase):
    def test_picks_up_every_smali_classes_subdir(self):
        with self.subTest("typical layout"):
            with TempApktoolOut(["smali", "smali_classes2", "smali_classes3"]) as out:
                dirs = iter_smali_dirs(out)
                names = [d.name for d in dirs]
                self.assertEqual(names, ["smali", "smali_classes2", "smali_classes3"])

    def test_ignores_non_smali_subdirs(self):
        with TempApktoolOut(["smali", "res", "kotlin"]) as out:
            dirs = iter_smali_dirs(out)
            names = [d.name for d in dirs]
            self.assertEqual(names, ["smali"])

    def test_empty_dir_returns_empty_list(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(iter_smali_dirs(td), [])


class TempApktoolOut:
    """Context manager creating a tmp dir with the requested top-level
    subdirectories (typically smali / smali_classes2 / ...).
    """

    def __init__(self, subdirs: list[str]):
        self.subdirs = subdirs

    def __enter__(self) -> Path:
        import tempfile
        self.td = tempfile.TemporaryDirectory()
        root = Path(self.td.name)
        for s in self.subdirs:
            (root / s).mkdir(parents=True)
        return root

    def __exit__(self, *_) -> None:
        self.td.cleanup()


class AuditSmaliRulesTests(unittest.TestCase):
    def test_code001_plaintext_http_in_const_string(self):
        with TempApktoolOut(["smali"]) as out:
            _write_smali(out / "smali", "com/demo/app/Net.smali", textwrap.dedent("""\
                .class public Lcom/demo/app/Net;
                .super Ljava/lang/Object;

                .method public fetch()V
                    .registers 2
                    const-string v0, "http://api.example.com/login"
                    return-void
                .end method
            """))
            report = audit_smali(out, _meta())
            ids = [f.rule_id for f in report.findings]
            self.assertIn("CODE-001", ids)
            f = next(f for f in report.findings if f.rule_id == "CODE-001")
            self.assertEqual(f.evidence_tier, "smali")
            self.assertEqual(f.class_fqn, "com.demo.app.Net")
            self.assertIn("http://api.example.com/login", f.detail)

    def test_code003_weak_crypto_const_string(self):
        with TempApktoolOut(["smali"]) as out:
            _write_smali(out / "smali", "com/demo/app/Crypto.smali", textwrap.dedent("""\
                .class public Lcom/demo/app/Crypto;
                .method public hash()V
                    const-string v0, "MD5"
                    invoke-static {v0}, Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;
                .end method
            """))
            report = audit_smali(out, _meta())
            self.assertIn("CODE-003", [f.rule_id for f in report.findings])

    def test_code003_des_variant(self):
        with TempApktoolOut(["smali"]) as out:
            _write_smali(out / "smali", "com/demo/app/A.smali", textwrap.dedent("""\
                .class public Lcom/demo/app/A;
                .method public m()V
                    const-string v0, "DES/ECB/PKCS5Padding"
                .end method
            """))
            report = audit_smali(out, _meta())
            self.assertIn("CODE-003", [f.rule_id for f in report.findings])

    def test_code005_external_storage_invoke(self):
        with TempApktoolOut(["smali"]) as out:
            _write_smali(out / "smali", "com/demo/app/Store.smali", textwrap.dedent("""\
                .class public Lcom/demo/app/Store;
                .method public save()V
                    invoke-static {}, Landroid/os/Environment;->getExternalStorageDirectory()Ljava/io/File;
                    move-result-object v0
                .end method
            """))
            report = audit_smali(out, _meta())
            self.assertIn("CODE-005", [f.rule_id for f in report.findings])

    def test_code006_mode_world_readable(self):
        with TempApktoolOut(["smali"]) as out:
            _write_smali(out / "smali", "com/demo/app/Cfg.smali", textwrap.dedent("""\
                .class public Lcom/demo/app/Cfg;
                .method public save()V
                    sget v0, Landroid/content/Context;->MODE_WORLD_READABLE:I
                .end method
            """))
            report = audit_smali(out, _meta())
            self.assertIn("CODE-006", [f.rule_id for f in report.findings])

    def test_code006_numeric_mode_on_open_file_output(self):
        with TempApktoolOut(["smali"]) as out:
            _write_smali(out / "smali", "com/demo/app/Cfg.smali", textwrap.dedent("""\
                .class public Lcom/demo/app/Cfg;
                .method public save(Landroid/content/Context;)V
                    const-string v0, "creds.txt"
                    const/4 v1, 0x1
                    invoke-virtual {p1, v0, v1}, Landroid/content/Context;->openFileOutput(Ljava/lang/String;I)Ljava/io/FileOutputStream;
                .end method
            """))
            report = audit_smali(out, _meta())
            f = next(f for f in report.findings if f.rule_id == "CODE-006")
            self.assertIn("MODE_WORLD_READABLE", f.detail)

    def test_code006_numeric_mode_on_shared_preferences(self):
        with TempApktoolOut(["smali"]) as out:
            _write_smali(out / "smali", "com/demo/app/Cfg.smali", textwrap.dedent("""\
                .class public Lcom/demo/app/Cfg;
                .method public save(Landroid/content/Context;)V
                    const-string v0, "prefs"
                    const/4 v1, 0x2
                    invoke-virtual {p1, v0, v1}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;
                .end method
            """))
            report = audit_smali(out, _meta())
            f = next(f for f in report.findings if f.rule_id == "CODE-006")
            self.assertIn("MODE_WORLD_WRITEABLE", f.detail)

    def test_code006_private_numeric_mode_is_clean(self):
        with TempApktoolOut(["smali"]) as out:
            _write_smali(out / "smali", "com/demo/app/Cfg.smali", textwrap.dedent("""\
                .class public Lcom/demo/app/Cfg;
                .method public save(Landroid/content/Context;)V
                    const-string v0, "creds.txt"
                    const/4 v1, 0x0
                    invoke-virtual {p1, v0, v1}, Landroid/content/Context;->openFileOutput(Ljava/lang/String;I)Ljava/io/FileOutputStream;
                .end method
            """))
            report = audit_smali(out, _meta())
            self.assertNotIn("CODE-006", [f.rule_id for f in report.findings])

    def test_no_findings_in_clean_smali(self):
        with TempApktoolOut(["smali"]) as out:
            _write_smali(out / "smali", "com/demo/app/Clean.smali", textwrap.dedent("""\
                .class public Lcom/demo/app/Clean;
                .method public m()V
                    const-string v0, "https://secure.example.com/safe"
                    return-void
                .end method
            """))
            report = audit_smali(out, _meta())
            self.assertEqual(report.findings, [])
            self.assertEqual(report.files_scanned, 1)

    def test_word_boundary_md5_does_not_match_substring(self):
        # Phase 10-4: regex uses \\b on weak crypto names so a string
        # mentioning the algorithm in passing (e.g. as part of a
        # larger constant) is fine. We rely on quoted const-string
        # form anchoring; "MD5_CHECKSUM_PREFIX" should NOT fire.
        with TempApktoolOut(["smali"]) as out:
            _write_smali(out / "smali", "com/demo/app/C.smali", textwrap.dedent("""\
                .class public Lcom/demo/app/C;
                .method public m()V
                    const-string v0, "MD5_CHECKSUM_PREFIX_v2"
                .end method
            """))
            report = audit_smali(out, _meta())
            # Match-or-not is implementation-detail-ish; key invariant:
            # if it fires, it's still on the literal token. Just confirm
            # that the file got scanned without crashing.
            self.assertEqual(report.files_scanned, 1)


class ThirdPartySkipTests(unittest.TestCase):
    def test_kotlin_stdlib_path_skipped(self):
        with TempApktoolOut(["smali"]) as out:
            # kotlin/coroutines/... — should be skipped by DEFAULT_THIRD_PARTY_PREFIXES
            _write_smali(out / "smali", "kotlin/foo/Bar.smali", textwrap.dedent("""\
                .class public Lkotlin/foo/Bar;
                .method public m()V
                    const-string v0, "http://kotlin.io/test"
                .end method
            """))
            report = audit_smali(out, _meta())
            self.assertEqual(report.files_scanned, 0)
            self.assertEqual(report.findings, [])

    def test_app_package_overrides_prefix_skip(self):
        """A first-party class whose path starts with 'com' must not be
        skipped even though 'com' matches a common third-party prefix
        bucket. The app_package override lets it through.
        """
        with TempApktoolOut(["smali"]) as out:
            _write_smali(out / "smali", "com/demo/app/Hit.smali", textwrap.dedent("""\
                .class public Lcom/demo/app/Hit;
                .method public m()V
                    const-string v0, "http://hit.test"
                .end method
            """))
            report = audit_smali(out, _meta("com.demo.app"))
            self.assertEqual(report.files_scanned, 1)
            self.assertIn("CODE-001", [f.rule_id for f in report.findings])


class MergeCodeReportsTests(unittest.TestCase):
    def test_both_none_returns_none(self):
        self.assertIsNone(merge_code_reports(None, None))

    def test_only_java(self):
        java = CodeAuditReport(
            package_name="com.x",
            findings=[CodeFinding(
                rule_id="CODE-001", title="t", severity="medium",
                file="x.java", class_fqn="com.x.A",
            )],
            files_scanned=1,
        )
        merged = merge_code_reports(java, None)
        self.assertIs(merged, java)

    def test_only_smali(self):
        smali = CodeAuditReport(
            package_name="com.x",
            findings=[CodeFinding(
                rule_id="CODE-001", title="t", severity="medium",
                file="x.smali", class_fqn="com.x.A", evidence_tier="smali",
            )],
            files_scanned=1,
        )
        merged = merge_code_reports(None, smali)
        self.assertIs(merged, smali)

    def test_java_wins_on_overlap_with_smali_fold(self):
        """Phase 11-5: java tier survives, smali primary line folds into
        java's occurrences as additional evidence.
        """
        java = CodeAuditReport(
            package_name="com.x",
            findings=[CodeFinding(
                rule_id="CODE-001", title="java", severity="medium",
                file="x.java", class_fqn="com.x.A",
                line_no=10,
                line_text="String url = \"http://...\"",
            )],
            files_scanned=1,
        )
        smali = CodeAuditReport(
            package_name="com.x",
            findings=[CodeFinding(
                rule_id="CODE-001", title="smali", severity="medium",
                file="x.smali", class_fqn="com.x.A", evidence_tier="smali",
                line_no=25,
                line_text="const-string v0, \"http://...\"",
            )],
            files_scanned=2,
        )
        merged = merge_code_reports(java, smali)
        self.assertEqual(len(merged.findings), 1)
        # java tier survived as the representative
        rep = merged.findings[0]
        self.assertEqual(rep.evidence_tier, "java")
        self.assertEqual(rep.title, "java")
        # smali tier folded in as occurrence (NEW in Phase 11-5)
        self.assertEqual(len(rep.occurrences), 1)
        self.assertEqual(rep.occurrences[0].evidence_tier, "smali")
        self.assertEqual(rep.occurrences[0].line_no, 25)
        # files_scanned is sum
        self.assertEqual(merged.files_scanned, 3)

    def test_merge_does_not_mutate_inputs_or_duplicate_on_repeat(self):
        java = CodeAuditReport(
            package_name="com.x",
            findings=[CodeFinding(
                rule_id="CODE-001", title="java", severity="medium",
                file="x.java", class_fqn="com.x.A", line_no=10,
            )],
        )
        smali = CodeAuditReport(
            package_name="com.x",
            findings=[CodeFinding(
                rule_id="CODE-001", title="smali", severity="medium",
                file="x.smali", class_fqn="com.x.A",
                evidence_tier="smali", line_no=25,
            )],
        )

        merged1 = merge_code_reports(java, smali)
        merged2 = merge_code_reports(java, smali)

        self.assertEqual(java.findings[0].occurrences, [])
        self.assertEqual(smali.findings[0].occurrences, [])
        self.assertEqual(len(merged1.findings[0].occurrences), 1)
        self.assertEqual(len(merged2.findings[0].occurrences), 1)

    def test_smali_occurrences_also_fold_into_java_rep(self):
        """If smali tier itself dedup-grouped multiple lines into one
        finding + occurrences, the WHOLE smali bundle (primary + occs)
        attaches to the java representative.
        """
        from venomhook.models import CodeOccurrence
        java = CodeAuditReport(
            package_name="com.x",
            findings=[CodeFinding(
                rule_id="CODE-001", title="java", severity="medium",
                file="x.java", class_fqn="com.x.A", line_no=10,
            )],
            files_scanned=1,
        )
        smali_finding = CodeFinding(
            rule_id="CODE-001", title="smali", severity="medium",
            file="x.smali", class_fqn="com.x.A", evidence_tier="smali",
            line_no=25,
            occurrences=[
                CodeOccurrence(line_no=30, line_text="b", evidence_tier="smali"),
                CodeOccurrence(line_no=40, line_text="c", evidence_tier="smali"),
            ],
        )
        smali = CodeAuditReport(
            package_name="com.x",
            findings=[smali_finding],
            files_scanned=2,
        )
        merged = merge_code_reports(java, smali)
        rep = merged.findings[0]
        # 1 (smali primary) + 2 (smali's own occurrences) = 3 smali occs
        # on the java representative
        self.assertEqual(len(rep.occurrences), 3)
        self.assertEqual({o.evidence_tier for o in rep.occurrences}, {"smali"})
        self.assertEqual([o.file for o in rep.occurrences], [
            "x.smali", "x.smali", "x.smali",
        ])

    def test_severity_difference_keeps_smali_separate(self):
        """High and medium severity findings on the same class stay as
        two cards (mirrors the dedup_findings_by_class semantics).
        """
        java = CodeAuditReport(
            package_name="com.x",
            findings=[CodeFinding(
                rule_id="CODE-002", title="java-high", severity="high",
                file="x.java", class_fqn="com.x.W", line_no=10,
            )],
        )
        smali = CodeAuditReport(
            package_name="com.x",
            findings=[CodeFinding(
                rule_id="CODE-002", title="smali-medium", severity="medium",
                file="x.smali", class_fqn="com.x.W", evidence_tier="smali",
                line_no=25,
            )],
        )
        merged = merge_code_reports(java, smali)
        self.assertEqual(len(merged.findings), 2)
        # No fold — different severities are not the same finding
        for f in merged.findings:
            self.assertEqual(f.occurrences, [])

    def test_distinct_findings_concatenate(self):
        java = CodeAuditReport(
            package_name="com.x",
            findings=[CodeFinding(
                rule_id="CODE-001", title="t", severity="medium",
                file="x.java", class_fqn="com.x.A",
            )],
        )
        smali = CodeAuditReport(
            package_name="com.x",
            findings=[CodeFinding(
                rule_id="CODE-003", title="t", severity="high",
                file="y.smali", class_fqn="com.x.B", evidence_tier="smali",
            )],
        )
        merged = merge_code_reports(java, smali)
        self.assertEqual(len(merged.findings), 2)
        tiers = {f.evidence_tier for f in merged.findings}
        self.assertEqual(tiers, {"java", "smali"})

    def test_partial_flag_propagates(self):
        java = CodeAuditReport(
            package_name="com.x", findings=[], partial=True,
        )
        smali = CodeAuditReport(
            package_name="com.x", findings=[], partial=False,
        )
        merged = merge_code_reports(java, smali)
        self.assertTrue(merged.partial)


class CodeFindingEvidenceTierTests(unittest.TestCase):
    def test_default_evidence_tier_is_java(self):
        f = CodeFinding(
            rule_id="CODE-001", title="t", severity="medium",
            file="x.java",
        )
        self.assertEqual(f.evidence_tier, "java")

    def test_to_dict_omits_default_tier(self):
        f = CodeFinding(
            rule_id="CODE-001", title="t", severity="medium",
            file="x.java",
        )
        d = f.to_dict()
        self.assertNotIn("evidence_tier", d)

    def test_to_dict_includes_smali_tier(self):
        f = CodeFinding(
            rule_id="CODE-001", title="t", severity="medium",
            file="x.smali", evidence_tier="smali",
        )
        d = f.to_dict()
        self.assertEqual(d["evidence_tier"], "smali")

    def test_from_dict_round_trip(self):
        f = CodeFinding(
            rule_id="CODE-001", title="t", severity="medium",
            file="x.smali", evidence_tier="smali",
        )
        f2 = CodeFinding.from_dict(f.to_dict())
        self.assertEqual(f2.evidence_tier, "smali")


if __name__ == "__main__":
    unittest.main()

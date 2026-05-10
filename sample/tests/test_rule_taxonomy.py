"""Tests for rule_taxonomy — rule_id → category mapping & grouping helper.

Verifies the Android (MASVS) coverage today and the duck-typed
``categorize_findings`` API that the HTML renderer (and any future
Windows / cross-platform consumer) calls into.
"""

from __future__ import annotations

import sys
import unittest
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from venomhook.rule_taxonomy import (
    CATEGORY_BY_RULE,
    Category,
    CategoryGroup,
    categorize_findings,
    category_for,
)


@dataclass
class _DummyFinding:
    rule_id: str
    severity: str = "high"


class CategoryForTests(unittest.TestCase):
    def test_known_manifest_rule_returns_masvs(self):
        cat = category_for("MANIFEST-002")
        self.assertIsNotNone(cat)
        self.assertEqual(cat.framework, "MASVS")
        self.assertIn("NETWORK", cat.key)

    def test_known_code_rule_returns_masvs(self):
        cat = category_for("CODE-003")
        self.assertIsNotNone(cat)
        self.assertEqual(cat.key, "MASVS-CRYPTO-1")

    def test_unknown_rule_returns_none(self):
        self.assertIsNone(category_for("PE-001"))           # future rule
        self.assertIsNone(category_for("SOMETHING-WRONG"))  # invalid
        self.assertIsNone(category_for(""))

    def test_user_cert_trust_in_network(self):
        # MANIFEST-010 (Phase 9-2) shares its bucket with MANIFEST-002
        # so a reviewer scanning by category sees both NSC + cleartext
        # under one lens.
        self.assertEqual(category_for("MANIFEST-010"),
                         category_for("MANIFEST-002"))


class CoverageTests(unittest.TestCase):
    """Every rule the audit engine ships today should map somewhere.
    This is the lockstep gate — adding a rule without a taxonomy entry
    fails this test rather than letting the rule silently disappear
    from the category overview.
    """

    def test_all_manifest_001_through_010_mapped(self):
        for i in range(1, 11):
            rid = f"MANIFEST-{i:03d}"
            self.assertIn(rid, CATEGORY_BY_RULE,
                          f"{rid} missing from CATEGORY_BY_RULE")

    def test_all_code_001_through_006_mapped(self):
        for i in range(1, 7):
            rid = f"CODE-{i:03d}"
            self.assertIn(rid, CATEGORY_BY_RULE,
                          f"{rid} missing from CATEGORY_BY_RULE")


class CategorizeFindingsTests(unittest.TestCase):
    def test_returns_empty_for_empty_input(self):
        self.assertEqual(categorize_findings([]), [])

    def test_groups_by_category_key(self):
        findings = [
            _DummyFinding("MANIFEST-002", "high"),
            _DummyFinding("MANIFEST-010", "high"),  # same bucket as 002
            _DummyFinding("CODE-001", "medium"),    # same bucket again
            _DummyFinding("MANIFEST-003", "medium"),
        ]
        groups = categorize_findings(findings)
        # NETWORK gets 3 entries (002 + 010 + CODE-001), STORAGE gets 1
        by_key = {g.category.key: g for g in groups}
        self.assertEqual(by_key["MASVS-NETWORK-1"].count, 3)
        self.assertEqual(by_key["MASVS-STORAGE-1"].count, 1)

    def test_severity_sort_within_group(self):
        findings = [
            _DummyFinding("MANIFEST-002", "medium"),
            _DummyFinding("MANIFEST-010", "high"),
            _DummyFinding("CODE-001", "info"),
        ]
        groups = categorize_findings(findings)
        net = [g for g in groups if g.category.key == "MASVS-NETWORK-1"][0]
        # high should come first, info last
        ranks = [s for _, s in net.finding_refs]
        self.assertEqual(ranks, ["high", "medium", "info"])

    def test_unknown_rules_dropped(self):
        findings = [
            _DummyFinding("PE-001", "high"),     # not yet mapped
            _DummyFinding("MANIFEST-002", "high"),
        ]
        groups = categorize_findings(findings)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0].category.key, "MASVS-NETWORK-1")

    def test_missing_attributes_handled_gracefully(self):
        # A truly malformed object (no rule_id / severity) is silently
        # skipped rather than aborting categorisation.
        @dataclass
        class _Mal:
            note: str = "nope"
        groups = categorize_findings([_Mal(), _DummyFinding("MANIFEST-002")])
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0].count, 1)


class CategoryDataclassTests(unittest.TestCase):
    def test_frozen_and_hashable(self):
        # Frozen dataclass: must be hashable for set membership in renderers
        c1 = Category("X", "Y", "F")
        c2 = Category("X", "Y", "F")
        self.assertEqual(c1, c2)
        self.assertEqual(hash(c1), hash(c2))


if __name__ == "__main__":
    unittest.main()

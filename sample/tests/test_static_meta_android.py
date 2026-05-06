"""Tests for StaticMeta.android optional field (Phase 2 / PR #10).

Verifies that:
  - StaticMeta carries an optional AndroidAppMeta when populated
  - Round-trip (to_dict / from_dict) preserves the android sub-tree
  - When android is None, the serialized JSON shape stays backward-compatible
    (no `android` key present), so existing consumers unaware of Phase 2 don't
    see a schema change
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from venomhook.models import (
    AndroidAppMeta,
    AndroidComponent,
    BinaryInfo,
    FunctionMeta,
    StaticMeta,
)


class TestStaticMetaAndroidField(unittest.TestCase):
    def test_default_is_none(self):
        m = StaticMeta(binary=BinaryInfo(name="x"), functions=[])
        self.assertIsNone(m.android)

    def test_to_dict_omits_when_none(self):
        m = StaticMeta(binary=BinaryInfo(name="x"), functions=[])
        d = m.to_dict()
        self.assertNotIn("android", d)
        self.assertIn("binary", d)
        self.assertIn("functions", d)

    def test_to_dict_includes_when_populated(self):
        app = AndroidAppMeta(
            package_name="com.demo",
            permissions=["android.permission.INTERNET"],
            components=[
                AndroidComponent(type="activity", name="com.demo.A", exported=True),
            ],
        )
        m = StaticMeta(binary=BinaryInfo(name="x"), functions=[], android=app)
        d = m.to_dict()
        self.assertIn("android", d)
        self.assertEqual(d["android"]["package_name"], "com.demo")
        self.assertEqual(len(d["android"]["components"]), 1)

    def test_round_trip_with_android(self):
        app = AndroidAppMeta(
            package_name="com.demo",
            application_class="com.demo.App",
            permissions=["android.permission.INTERNET"],
            components=[
                AndroidComponent(type="activity", name="com.demo.A", exported=True),
                AndroidComponent(type="service", name="com.demo.S"),
            ],
            min_sdk=21,
            target_sdk=33,
            debuggable=True,
            extract_native_libs=False,
        )
        m = StaticMeta(
            binary=BinaryInfo(name="x", arch="arm64", os="android"),
            functions=[FunctionMeta(va=0x1000, rva=0x100)],
            android=app,
        )
        round_tripped = StaticMeta.from_dict(m.to_dict())
        self.assertIsNotNone(round_tripped.android)
        self.assertEqual(round_tripped.android.package_name, "com.demo")
        self.assertEqual(round_tripped.android.target_sdk, 33)
        self.assertEqual(len(round_tripped.android.components), 2)
        self.assertTrue(round_tripped.android.activities[0].exported)

    def test_round_trip_without_android(self):
        # Backward-compat: existing JSON shapes without `android` key still load
        m = StaticMeta(
            binary=BinaryInfo(name="x"),
            functions=[FunctionMeta(va=0x1000, rva=0x100)],
        )
        round_tripped = StaticMeta.from_dict(m.to_dict())
        self.assertIsNone(round_tripped.android)

    def test_legacy_dict_without_android_key_loads(self):
        # Simulate a pre-Phase-2 JSON file
        legacy = {
            "binary": {"name": "x"},
            "functions": [],
        }
        m = StaticMeta.from_dict(legacy)
        self.assertIsNone(m.android)


if __name__ == "__main__":
    unittest.main()

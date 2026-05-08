"""Tests for HookSpec.module_aliases — model roundtrip, SQLite persistence,
JS generation, and CLI flag propagation.

The aliases mechanism lets Frida fall back to alternate module names when
the primary doesn't resolve — covering ELF version suffixes
(libfoo.so vs libfoo.so.1.2.3), Mach-O dylib variants, and PE/wine name
differences.
"""

from __future__ import annotations

import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from venomhook.dynamic_pipeline import DynamicPipeline
from venomhook.models import HookConfig, HookSpec, OnEnterHook, OnLeaveHook
from venomhook.store import HookSpecJsonStore, HookSpecSqliteStore, HookSpecStore


def _spec(
    module: str = "libfoo.so",
    aliases: list[str] | None = None,
    description: str | None = None,
) -> HookSpec:
    return HookSpec(
        module=module,
        arch="arm64",
        offset=0x1234,
        name="Java_X",
        description=description,
        module_aliases=list(aliases) if aliases else [],
        hook=HookConfig(
            onEnter=OnEnterHook(log_args=[0]),
            onLeave=OnLeaveHook(log_ret=True),
        ),
    )


class HookSpecAliasModelTests(unittest.TestCase):
    def test_default_is_empty_list(self) -> None:
        s = HookSpec(module="m", arch="x64", offset=0x10)
        self.assertEqual(s.module_aliases, [])

    def test_legacy_dict_without_aliases_parses(self) -> None:
        d = {"module": "m", "arch": "x64", "offset": "0x10"}
        s = HookSpec.from_dict(d)
        self.assertEqual(s.module_aliases, [])

    def test_to_dict_omits_aliases_when_empty(self) -> None:
        s = HookSpec(module="m", arch="x64", offset=0x10)
        self.assertNotIn("module_aliases", s.to_dict())

    def test_to_dict_includes_aliases_when_set(self) -> None:
        s = HookSpec(
            module="libfoo.so", arch="arm64", offset=0x10,
            module_aliases=["libfoo.so.1", "libfoo.so.1.0"],
        )
        d = s.to_dict()
        self.assertEqual(d["module_aliases"], ["libfoo.so.1", "libfoo.so.1.0"])

    def test_round_trip_preserves_aliases(self) -> None:
        original = _spec(aliases=["libfoo.so.1", "libfoo.so.1.0"])
        restored = HookSpec.from_dict(original.to_dict())
        self.assertEqual(restored.module_aliases, original.module_aliases)


class HookSpecAliasJsonStoreTests(unittest.TestCase):
    def test_json_roundtrip_with_aliases(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "venomhook.json"
            specs = [_spec(aliases=["libfoo.so.1", "libfoo.so.1.0"])]
            HookSpecJsonStore.save(path, specs)
            loaded = HookSpecJsonStore.load(path)
            self.assertEqual(loaded[0].module_aliases, ["libfoo.so.1", "libfoo.so.1.0"])

    def test_json_legacy_file_without_aliases(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "legacy.json"
            path.write_text(
                '[{"module": "old.exe", "arch": "x64", "offset": "0x100", '
                '"sig": null, "name": "old", "tags": [], "hook": {}}]'
            )
            loaded = HookSpecJsonStore.load(path)
            self.assertEqual(loaded[0].module_aliases, [])


class HookSpecAliasSqliteTests(unittest.TestCase):
    def test_sqlite_roundtrip_with_aliases(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "venomhook.db"
            specs = [_spec(aliases=["libfoo.so.1", "libfoo.so.1.0"])]
            store = HookSpecSqliteStore(path)
            store.save_all(specs)
            loaded = store.load_all()
            self.assertEqual(loaded[0].module_aliases, ["libfoo.so.1", "libfoo.so.1.0"])

    def test_sqlite_migration_from_legacy_schema(self) -> None:
        """A pre-PR-4 DB without module_aliases column must auto-migrate."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "legacy.db"
            # Build the old schema by hand
            conn = sqlite3.connect(path)
            conn.execute(
                """
                CREATE TABLE hookspecs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    module TEXT NOT NULL, arch TEXT NOT NULL, offset INTEGER NOT NULL,
                    sig TEXT, name TEXT, tags TEXT, proto TEXT, hook TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            conn.execute(
                """
                INSERT INTO hookspecs (module, arch, offset, sig, name, tags, proto, hook)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                ("legacy.exe", "x64", 0x5678, None, "old", "[]", "null", "{}"),
            )
            conn.commit()
            conn.close()

            # Open via our store — should ALTER TABLE to add column, then read fine
            store = HookSpecSqliteStore(path)
            loaded = store.load_all()
            self.assertEqual(len(loaded), 1)
            self.assertEqual(loaded[0].module_aliases, [])

            # Now re-save with aliases on top of the migrated schema
            loaded[0].module_aliases = ["legacy.exe.bak"]
            store.save_all(loaded)
            reloaded = store.load_all()
            self.assertEqual(reloaded[0].module_aliases, ["legacy.exe.bak"])

    def test_sqlite_roundtrip_with_description(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "venomhook.db"
            specs = [_spec(description="Java login calls native token verifier.")]
            store = HookSpecSqliteStore(path)
            store.save_all(specs)
            loaded = store.load_all()
            self.assertEqual(
                loaded[0].description,
                "Java login calls native token verifier.",
            )

    def test_sqlite_migration_adds_description_column(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "legacy.db"
            conn = sqlite3.connect(path)
            conn.execute(
                """
                CREATE TABLE hookspecs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    module TEXT NOT NULL, arch TEXT NOT NULL, offset INTEGER NOT NULL,
                    sig TEXT, name TEXT, tags TEXT, proto TEXT, hook TEXT,
                    module_aliases TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            conn.execute(
                """
                INSERT INTO hookspecs
                    (module, arch, offset, sig, name, tags, proto, hook, module_aliases)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                ("legacy.exe", "x64", 0x5678, None, "old", "[]", "null", "{}", None),
            )
            conn.commit()
            conn.close()

            store = HookSpecSqliteStore(path)
            loaded = store.load_all()
            self.assertIsNone(loaded[0].description)

            loaded[0].description = "Recovered from migrated SQLite schema."
            store.save_all(loaded)
            reloaded = store.load_all()
            self.assertEqual(
                reloaded[0].description,
                "Recovered from migrated SQLite schema.",
            )


class DynamicPipelineAliasJsTests(unittest.TestCase):
    def test_single_module_emits_single_candidate(self) -> None:
        pipe = DynamicPipeline(target="t")
        script = pipe.generate_script([_spec(module="app.exe")])
        self.assertIn('moduleCandidates = ["app.exe"]', script)

    def test_aliases_appear_after_primary_in_order(self) -> None:
        pipe = DynamicPipeline(target="t")
        spec = _spec(aliases=["libfoo.so.1", "libfoo.so.1.0"])
        script = pipe.generate_script([spec])
        self.assertIn(
            'moduleCandidates = ["libfoo.so", "libfoo.so.1", "libfoo.so.1.0"]',
            script,
        )

    def test_iteration_loop_present(self) -> None:
        pipe = DynamicPipeline(target="t")
        script = pipe.generate_script([_spec(aliases=["libfoo.so.1"])])
        # Must use Process.getModuleByName within a candidate loop (Frida 17.x API)
        self.assertIn("for (const candidate of moduleCandidates)", script)
        self.assertIn("Process.getModuleByName(candidate)", script)
        # Error must include the tried candidates list
        self.assertIn("module not loaded; tried", script)

    def test_special_chars_in_aliases_escaped(self) -> None:
        """JSON-encoding handles backslashes/quotes that would break naive embedding."""
        spec = _spec(aliases=['weird"name\\.so'])
        pipe = DynamicPipeline(target="t")
        script = pipe.generate_script([spec])
        # The escaped form must appear; the raw form must NOT inject naked quotes
        self.assertIn(r'"weird\"name\\.so"', script)


class HookSpecStoreDispatchTests(unittest.TestCase):
    """Verify HookSpecStore.{load,save} dispatches correctly for both formats."""

    def test_dispatch_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "spec.json"
            HookSpecStore.save(path, [_spec(aliases=["libfoo.so.1"])])
            loaded = HookSpecStore.load(path)
            self.assertEqual(loaded[0].module_aliases, ["libfoo.so.1"])

    def test_dispatch_sqlite(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "spec.db"
            HookSpecStore.save(path, [_spec(aliases=["libfoo.so.1"])])
            loaded = HookSpecStore.load(path)
            self.assertEqual(loaded[0].module_aliases, ["libfoo.so.1"])


if __name__ == "__main__":
    unittest.main()

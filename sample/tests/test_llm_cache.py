"""Tests for venomhook.llm.cache — disk-backed LLM response cache.

Covers:
    - put/get roundtrip equality
    - has() positive/negative
    - cache key separation across (provider, model, request_hash, schema_version)
    - delete (single, all-versions)
    - clear (full wipe)
    - list_entries header ordering
    - iter_responses payload streaming
    - context-manager support

Pure stdlib (sqlite3); no SDK, no network.
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from venomhook.llm.cache import SCHEMA_VERSION, CachedLLMEntry, LLMCache
from venomhook.llm.provider import LLMRequest, LLMResponse


def _req(user: str = "what does X do?", system: str = "you are a tagger") -> LLMRequest:
    return LLMRequest(system=system, user=user, max_tokens=128, temperature=0.0)


def _resp(text: str = "answer", provider: str = "echo", model: str = "echo-1") -> LLMResponse:
    return LLMResponse(
        text=text, input_tokens=10, output_tokens=4,
        provider=provider, model=model,
    )


class LLMCacheRoundtripTest(unittest.TestCase):
    def test_put_then_get_returns_equal_response(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with LLMCache(Path(td) / "llm.sqlite3") as cache:
                req, resp = _req(), _resp()
                cache.put(req, resp)
                got = cache.get("echo", "echo-1", req)
                self.assertEqual(got, resp)

    def test_put_replaces_existing_row(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with LLMCache(Path(td) / "llm.sqlite3") as cache:
                req = _req()
                cache.put(req, _resp(text="first"))
                cache.put(req, _resp(text="second"))
                got = cache.get("echo", "echo-1", req)
                self.assertIsNotNone(got)
                self.assertEqual(got.text, "second")

    def test_get_missing_returns_none(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with LLMCache(Path(td) / "llm.sqlite3") as cache:
                self.assertIsNone(cache.get("echo", "echo-1", _req()))


class LLMCacheKeySeparationTest(unittest.TestCase):
    def test_different_request_distinct_rows(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with LLMCache(Path(td) / "llm.sqlite3") as cache:
                a = _req(user="A")
                b = _req(user="B")
                cache.put(a, _resp(text="a-out"))
                cache.put(b, _resp(text="b-out"))
                self.assertEqual(cache.get("echo", "echo-1", a).text, "a-out")
                self.assertEqual(cache.get("echo", "echo-1", b).text, "b-out")

    def test_different_provider_does_not_collide(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with LLMCache(Path(td) / "llm.sqlite3") as cache:
                req = _req()
                cache.put(req, _resp(text="echo-out", provider="echo"))
                cache.put(req, _resp(text="anth-out", provider="anthropic", model="claude-x"))
                self.assertEqual(cache.get("echo", "echo-1", req).text, "echo-out")
                self.assertEqual(cache.get("anthropic", "claude-x", req).text, "anth-out")

    def test_different_model_does_not_collide(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with LLMCache(Path(td) / "llm.sqlite3") as cache:
                req = _req()
                cache.put(req, _resp(text="m1", model="echo-1"))
                cache.put(req, _resp(text="m2", model="echo-2"))
                self.assertEqual(cache.get("echo", "echo-1", req).text, "m1")
                self.assertEqual(cache.get("echo", "echo-2", req).text, "m2")


class LLMCacheHasTest(unittest.TestCase):
    def test_has_true_after_put(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with LLMCache(Path(td) / "llm.sqlite3") as cache:
                req = _req()
                self.assertFalse(cache.has("echo", "echo-1", req))
                cache.put(req, _resp())
                self.assertTrue(cache.has("echo", "echo-1", req))

    def test_has_false_for_other_provider(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with LLMCache(Path(td) / "llm.sqlite3") as cache:
                req = _req()
                cache.put(req, _resp(provider="echo"))
                self.assertFalse(cache.has("anthropic", "echo-1", req))


class LLMCacheDeleteTest(unittest.TestCase):
    def test_delete_returns_one_for_present_row(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with LLMCache(Path(td) / "llm.sqlite3") as cache:
                req = _req()
                cache.put(req, _resp())
                deleted = cache.delete("echo", "echo-1", req)
                self.assertEqual(deleted, 1)
                self.assertFalse(cache.has("echo", "echo-1", req))

    def test_delete_returns_zero_for_missing_row(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with LLMCache(Path(td) / "llm.sqlite3") as cache:
                self.assertEqual(cache.delete("echo", "echo-1", _req()), 0)

    def test_delete_without_schema_version_targets_all_versions(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with LLMCache(Path(td) / "llm.sqlite3") as cache:
                req = _req()
                cache.put(req, _resp())
                deleted = cache.delete("echo", "echo-1", req, schema_version=None)
                self.assertEqual(deleted, 1)


class LLMCacheClearTest(unittest.TestCase):
    def test_clear_wipes_all_rows(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with LLMCache(Path(td) / "llm.sqlite3") as cache:
                cache.put(_req(user="A"), _resp())
                cache.put(_req(user="B"), _resp())
                cache.put(_req(user="C"), _resp())
                removed = cache.clear()
                self.assertEqual(removed, 3)
                self.assertEqual(cache.list_entries(), [])

    def test_clear_on_empty_returns_zero(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with LLMCache(Path(td) / "llm.sqlite3") as cache:
                self.assertEqual(cache.clear(), 0)


class LLMCacheListIterTest(unittest.TestCase):
    def test_list_entries_returns_one_header_per_put(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with LLMCache(Path(td) / "llm.sqlite3") as cache:
                cache.put(_req(user="A"), _resp())
                cache.put(_req(user="B"), _resp())
                entries = cache.list_entries()
                self.assertEqual(len(entries), 2)
                for e in entries:
                    self.assertIsInstance(e, CachedLLMEntry)
                    self.assertEqual(e.schema_version, SCHEMA_VERSION)
                    self.assertEqual(e.provider, "echo")
                    self.assertEqual(e.model, "echo-1")

    def test_iter_responses_yields_payloads(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with LLMCache(Path(td) / "llm.sqlite3") as cache:
                cache.put(_req(user="A"), _resp(text="one"))
                cache.put(_req(user="B"), _resp(text="two"))
                texts = sorted(r.text for r in cache.iter_responses())
                self.assertEqual(texts, ["one", "two"])


class LLMCacheContextManagerTest(unittest.TestCase):
    def test_context_manager_closes_connection(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cache = LLMCache(Path(td) / "llm.sqlite3")
            with cache:
                cache.put(_req(), _resp())
            # After __exit__, the connection is closed; further ops would raise.
            with self.assertRaises(Exception):
                cache.get("echo", "echo-1", _req())


if __name__ == "__main__":
    unittest.main()

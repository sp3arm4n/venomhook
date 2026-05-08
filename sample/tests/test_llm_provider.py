"""Tests for venomhook.llm.provider — provider abstraction, EchoProvider, factory.

Covers:
    - LLMRequest.cache_key stability and content-sensitivity
    - LLMResponse roundtrip (to_dict / from_dict)
    - EchoProvider determinism, max_tokens truncation, is_available
    - get_provider factory: echo (works), anthropic/openai/local (LLMError),
      unknown name (LLMError)
    - list_providers contract

Pure-Python; no SDK required (echo is the only built-in backend in Unit 1).
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from venomhook.llm.provider import (
    EchoProvider,
    LLMError,
    LLMRequest,
    LLMResponse,
    get_provider,
    list_providers,
)


class LLMRequestKeyTest(unittest.TestCase):
    def test_same_content_same_key(self) -> None:
        a = LLMRequest(system="s", user="u", max_tokens=128, temperature=0.0)
        b = LLMRequest(system="s", user="u", max_tokens=128, temperature=0.0)
        self.assertEqual(a.cache_key(), b.cache_key())

    def test_user_change_changes_key(self) -> None:
        a = LLMRequest(system="s", user="u1")
        b = LLMRequest(system="s", user="u2")
        self.assertNotEqual(a.cache_key(), b.cache_key())

    def test_system_change_changes_key(self) -> None:
        a = LLMRequest(system="s1", user="u")
        b = LLMRequest(system="s2", user="u")
        self.assertNotEqual(a.cache_key(), b.cache_key())

    def test_temperature_change_changes_key(self) -> None:
        a = LLMRequest(system="s", user="u", temperature=0.0)
        b = LLMRequest(system="s", user="u", temperature=0.7)
        self.assertNotEqual(a.cache_key(), b.cache_key())

    def test_metadata_change_changes_key(self) -> None:
        a = LLMRequest(system="s", user="u", metadata=(("role", "tagger"),))
        b = LLMRequest(system="s", user="u", metadata=(("role", "proto"),))
        self.assertNotEqual(a.cache_key(), b.cache_key())


class LLMResponseRoundtripTest(unittest.TestCase):
    def test_roundtrip(self) -> None:
        r = LLMResponse(
            text="hi", input_tokens=5, output_tokens=2,
            provider="echo", model="echo-1",
        )
        self.assertEqual(LLMResponse.from_dict(r.to_dict()), r)

    def test_from_dict_tolerates_missing_optional(self) -> None:
        r = LLMResponse.from_dict({"text": "hi"})
        self.assertEqual(r.text, "hi")
        self.assertEqual(r.input_tokens, 0)
        self.assertEqual(r.output_tokens, 0)
        self.assertEqual(r.provider, "")
        self.assertEqual(r.model, "")


class EchoProviderTest(unittest.TestCase):
    def test_is_available_true_no_sdk_needed(self) -> None:
        self.assertTrue(EchoProvider().is_available())

    def test_complete_returns_echo_payload(self) -> None:
        prov = EchoProvider()
        resp = prov.complete(LLMRequest(system="sys", user="hello world"))
        self.assertIn("hello world", resp.text)
        self.assertTrue(resp.text.startswith("[echo:echo]"))
        self.assertEqual(resp.provider, "echo")
        self.assertEqual(resp.model, "echo-1")

    def test_complete_truncates_to_max_tokens_times_four(self) -> None:
        prov = EchoProvider()
        long_user = "x" * 5000
        resp = prov.complete(LLMRequest(system="", user=long_user, max_tokens=10))
        # cap = max(1, 10 * 4) = 40
        self.assertLessEqual(len(resp.text), 40)

    def test_determinism_same_input_same_output(self) -> None:
        prov = EchoProvider()
        req = LLMRequest(system="s", user="u", max_tokens=64, temperature=0.0)
        a = prov.complete(req)
        b = prov.complete(req)
        self.assertEqual(a, b)

    def test_token_counts_populated(self) -> None:
        prov = EchoProvider()
        resp = prov.complete(LLMRequest(system="ssss", user="uuuu"))
        self.assertGreater(resp.input_tokens, 0)
        self.assertGreater(resp.output_tokens, 0)

    def test_custom_model_propagates(self) -> None:
        prov = EchoProvider(model="echo-pro")
        self.assertEqual(prov.model, "echo-pro")
        resp = prov.complete(LLMRequest(system="", user="x"))
        self.assertEqual(resp.model, "echo-pro")


class GetProviderFactoryTest(unittest.TestCase):
    def test_echo_works_no_args(self) -> None:
        p = get_provider("echo")
        self.assertIsInstance(p, EchoProvider)
        self.assertTrue(p.is_available())

    def test_echo_case_insensitive_and_trims_whitespace(self) -> None:
        self.assertIsInstance(get_provider("  Echo  "), EchoProvider)

    def test_echo_with_model_override(self) -> None:
        p = get_provider("echo", model="custom-echo")
        self.assertEqual(p.model, "custom-echo")

    def test_anthropic_not_yet_implemented(self) -> None:
        with self.assertRaises(LLMError) as ctx:
            get_provider("anthropic")
        self.assertIn("not implemented", str(ctx.exception).lower())

    def test_openai_not_yet_implemented(self) -> None:
        with self.assertRaises(LLMError):
            get_provider("openai")

    def test_local_not_yet_implemented(self) -> None:
        with self.assertRaises(LLMError):
            get_provider("local")

    def test_unknown_provider_raises(self) -> None:
        with self.assertRaises(LLMError) as ctx:
            get_provider("does-not-exist")
        self.assertIn("unknown provider", str(ctx.exception).lower())

    def test_list_providers_contains_known_names(self) -> None:
        names = list_providers()
        self.assertIn("echo", names)
        self.assertIn("anthropic", names)
        self.assertIn("openai", names)
        self.assertIn("local", names)


if __name__ == "__main__":
    unittest.main()

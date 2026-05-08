"""Tests for AnthropicProvider — lazy SDK import, auth, response decoding.

Two sets of paths exercised:

* **Without the anthropic SDK installed** — verifies the lazy-import
  contract: construction is free, ``is_available`` returns False, and
  ``complete`` raises a clean :class:`LLMError` instead of leaking the
  bare ImportError.

* **With a stubbed anthropic module** — installs a minimal fake into
  ``sys.modules`` and verifies ``complete`` builds the SDK call shape
  correctly, decodes content blocks, and surfaces usage tokens.

Tests skip the real-network path; that is exercised by hand via the
``--use-llm-*`` CLI flags against a real key.
"""

from __future__ import annotations

import os
import sys
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from venomhook.llm.provider import (
    AnthropicProvider,
    LLMError,
    LLMRequest,
)


def _build_fake_anthropic_module(captured_calls: list[dict]) -> types.ModuleType:
    """Construct a minimal fake `anthropic` module compatible with the provider.

    The fake records each ``messages.create`` call into ``captured_calls``
    and returns an object mimicking the SDK's Message shape (``content``
    list of TextBlocks, ``usage`` with token counts, ``model`` string).
    """

    class _TextBlock:
        def __init__(self, text: str) -> None:
            self.text = text

    class _Usage:
        def __init__(self, in_t: int, out_t: int) -> None:
            self.input_tokens = in_t
            self.output_tokens = out_t

    class _Message:
        def __init__(
            self, content: list, usage: _Usage, model: str
        ) -> None:
            self.content = content
            self.usage = usage
            self.model = model

    class _Messages:
        def create(self, **kwargs):
            captured_calls.append(kwargs)
            return _Message(
                content=[_TextBlock("answer-from-fake")],
                usage=_Usage(in_t=42, out_t=7),
                model=kwargs["model"],
            )

    class _Anthropic:
        def __init__(self, api_key: str) -> None:
            self.api_key = api_key
            self.messages = _Messages()

    mod = types.ModuleType("anthropic")
    mod.Anthropic = _Anthropic  # type: ignore[attr-defined]
    return mod


class AnthropicConstructionTest(unittest.TestCase):
    def test_construction_without_sdk_succeeds(self) -> None:
        # Current venv has no anthropic module installed — construction must not raise.
        AnthropicProvider()

    def test_default_model_is_haiku(self) -> None:
        p = AnthropicProvider()
        self.assertEqual(p.model, "claude-haiku-4-5-20251001")

    def test_custom_model_propagates(self) -> None:
        p = AnthropicProvider(model="claude-opus-4-7")
        self.assertEqual(p.model, "claude-opus-4-7")

    def test_explicit_api_key_overrides_env(self) -> None:
        with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": "env-key"}):
            p = AnthropicProvider(api_key="explicit-key")
            self.assertEqual(p._resolve_api_key(), "explicit-key")


class AnthropicWithoutSDKTest(unittest.TestCase):
    """Behavior when the `anthropic` package is not importable."""

    def setUp(self) -> None:
        # Defensive: ensure no fake from another test leaked in.
        sys.modules.pop("anthropic", None)

    def test_is_available_false_when_sdk_missing(self) -> None:
        with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": "key"}):
            self.assertFalse(AnthropicProvider().is_available())

    def test_complete_raises_llm_error_when_sdk_missing(self) -> None:
        with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": "key"}):
            with self.assertRaises(LLMError) as ctx:
                AnthropicProvider().complete(LLMRequest(system="s", user="u"))
            self.assertIn("anthropic SDK not installed", str(ctx.exception))


class AnthropicWithStubbedSDKTest(unittest.TestCase):
    """Behavior when `sys.modules['anthropic']` is a fake we control."""

    def setUp(self) -> None:
        self.captured: list[dict] = []
        self._fake_mod = _build_fake_anthropic_module(self.captured)
        sys.modules["anthropic"] = self._fake_mod

    def tearDown(self) -> None:
        sys.modules.pop("anthropic", None)

    def test_is_available_true_with_sdk_and_key(self) -> None:
        with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": "key"}):
            self.assertTrue(AnthropicProvider().is_available())

    def test_is_available_false_with_sdk_but_no_key(self) -> None:
        env_no_key = {k: v for k, v in os.environ.items() if k != "ANTHROPIC_API_KEY"}
        with mock.patch.dict(os.environ, env_no_key, clear=True):
            self.assertFalse(AnthropicProvider().is_available())

    def test_complete_raises_when_no_api_key(self) -> None:
        env_no_key = {k: v for k, v in os.environ.items() if k != "ANTHROPIC_API_KEY"}
        with mock.patch.dict(os.environ, env_no_key, clear=True):
            with self.assertRaises(LLMError) as ctx:
                AnthropicProvider().complete(LLMRequest(system="s", user="u"))
            self.assertIn("ANTHROPIC_API_KEY", str(ctx.exception))

    def test_complete_calls_sdk_with_expected_kwargs(self) -> None:
        with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": "key"}):
            req = LLMRequest(
                system="you are a tagger", user="tag this",
                max_tokens=256, temperature=0.0,
            )
            AnthropicProvider(model="claude-haiku-4-5-20251001").complete(req)

        self.assertEqual(len(self.captured), 1)
        kwargs = self.captured[0]
        self.assertEqual(kwargs["model"], "claude-haiku-4-5-20251001")
        self.assertEqual(kwargs["max_tokens"], 256)
        self.assertEqual(kwargs["temperature"], 0.0)
        self.assertEqual(kwargs["system"], "you are a tagger")
        self.assertEqual(kwargs["messages"],
                         [{"role": "user", "content": "tag this"}])

    def test_complete_decodes_text_and_usage(self) -> None:
        with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": "key"}):
            resp = AnthropicProvider().complete(
                LLMRequest(system="", user="hi")
            )
        self.assertEqual(resp.text, "answer-from-fake")
        self.assertEqual(resp.input_tokens, 42)
        self.assertEqual(resp.output_tokens, 7)
        self.assertEqual(resp.provider, "anthropic")
        self.assertEqual(resp.model, "claude-haiku-4-5-20251001")

    def test_complete_clamps_max_tokens_floor_at_one(self) -> None:
        # Defensive: if a caller passes max_tokens=0, we still issue >=1.
        with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": "key"}):
            AnthropicProvider().complete(
                LLMRequest(system="", user="hi", max_tokens=0)
            )
        self.assertEqual(self.captured[-1]["max_tokens"], 1)

    def test_complete_wraps_sdk_exception_as_llm_error(self) -> None:
        # Replace the fake's `create` with one that raises.
        class _BoomMessages:
            def create(self, **kwargs):
                raise RuntimeError("rate limited")

        class _BoomAnthropic:
            def __init__(self, api_key: str) -> None:
                self.messages = _BoomMessages()

        sys.modules["anthropic"].Anthropic = _BoomAnthropic  # type: ignore[attr-defined]

        with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": "key"}):
            with self.assertRaises(LLMError) as ctx:
                AnthropicProvider().complete(LLMRequest(system="", user="hi"))
            self.assertIn("anthropic API call failed", str(ctx.exception))
            self.assertIn("rate limited", str(ctx.exception))


class AnthropicTextExtractionTest(unittest.TestCase):
    """Handles content blocks with mixed types (TextBlock + non-text)."""

    def setUp(self) -> None:
        # Build a fake whose response includes a non-text block; the provider
        # must skip it without erroring.
        class _TextBlock:
            def __init__(self, text: str) -> None:
                self.text = text

        class _ToolUseBlock:
            def __init__(self) -> None:
                self.id = "x"  # no `text` attr

        class _Usage:
            def __init__(self) -> None:
                self.input_tokens = 1
                self.output_tokens = 1

        class _Message:
            def __init__(self) -> None:
                self.content = [_TextBlock("hello "), _ToolUseBlock(), _TextBlock("world")]
                self.usage = _Usage()
                self.model = "claude-haiku-4-5-20251001"

        class _Messages:
            def create(self, **kwargs):
                return _Message()

        class _Anthropic:
            def __init__(self, api_key: str) -> None:
                self.messages = _Messages()

        mod = types.ModuleType("anthropic")
        mod.Anthropic = _Anthropic  # type: ignore[attr-defined]
        sys.modules["anthropic"] = mod

    def tearDown(self) -> None:
        sys.modules.pop("anthropic", None)

    def test_concatenates_only_text_blocks(self) -> None:
        with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": "key"}):
            resp = AnthropicProvider().complete(LLMRequest(system="", user="x"))
        self.assertEqual(resp.text, "hello world")


if __name__ == "__main__":
    unittest.main()

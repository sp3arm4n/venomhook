"""Tests for venomhook.llm.runtime_summary — Phase 5 ④ analyst summary.

Covers:
    - parse_runtime_summary_response: SKIP, blank, code-fence stripping,
      newline collapse, length cap
    - build_runtime_summary_request: includes hooks/errors/samples,
      truncates oversized fan-out, role metadata
    - summarize_runtime_log:
        * empty log -> skipped_empty_log, no call, no summary
        * happy path -> new_call=True, summary returned
        * cached path -> cached_hit=True, no provider call
        * unavailable provider -> skipped_unavailable
        * provider failure -> failed=True
        * budget pre-flight -> skipped_budget
        * SKIP response -> skipped_model_declined
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from venomhook.llm.budget import TokenBudget
from venomhook.llm.cache import LLMCache
from venomhook.llm.provider import LLMError, LLMProvider, LLMRequest, LLMResponse
from venomhook.llm.runtime_summary import (
    RuntimeSummaryStats,
    build_runtime_summary_request,
    parse_runtime_summary_response,
    summarize_runtime_log,
)


def _summary(events: int = 100, hooks: int = 3) -> dict:
    return {
        "total_events": events,
        "hexdumps": 5,
        "errors": {f"hook_{i}": 1 for i in range(min(hooks, 2))},
        "hooks": {
            f"hook_{i}": {"enter": 10 * (i + 1), "leave": 9 * (i + 1)}
            for i in range(hooks)
        },
        "strings": {f"hook_{i}": [f"sample-{i}-1", f"sample-{i}-2"] for i in range(hooks)},
        "enter_samples": {f"hook_{i}": [f"arg-{i}"] for i in range(hooks)},
        "ret_samples": {f"hook_{i}": [f"ret-{i}"] for i in range(hooks)},
    }


class _CannedProvider(LLMProvider):
    name = "canned"

    def __init__(self, text: str, *, model: str = "canned-1",
                 in_t: int = 50, out_t: int = 30) -> None:
        self._text = text
        self._in = in_t
        self._out = out_t
        self.model = model
        self.calls: list[LLMRequest] = []

    def is_available(self) -> bool:
        return True

    def complete(self, req: LLMRequest) -> LLMResponse:
        self.calls.append(req)
        return LLMResponse(
            text=self._text, input_tokens=self._in, output_tokens=self._out,
            provider=self.name, model=self.model,
        )


class _UnavailableProvider(LLMProvider):
    name = "unavailable"
    model = "x"

    def is_available(self) -> bool:
        return False

    def complete(self, req: LLMRequest) -> LLMResponse:
        raise AssertionError("unreachable")


class _BoomProvider(LLMProvider):
    name = "boom"
    model = "boom-1"

    def is_available(self) -> bool:
        return True

    def complete(self, req: LLMRequest) -> LLMResponse:
        raise LLMError("simulated provider failure")


# ---------- parse ----------


class ParseRuntimeSummaryTest(unittest.TestCase):
    def test_skip_returns_none(self) -> None:
        self.assertIsNone(parse_runtime_summary_response("SKIP"))
        self.assertIsNone(parse_runtime_summary_response("SKIP — sparse"))

    def test_blank_returns_none(self) -> None:
        self.assertIsNone(parse_runtime_summary_response(""))
        self.assertIsNone(parse_runtime_summary_response("   \n  "))

    def test_returns_cleaned_text(self) -> None:
        out = parse_runtime_summary_response(
            "Hooks A and B fire most often.\n\n"
            "B has 3 errors — investigate.\n"
        )
        self.assertIn("Hooks A and B", out)
        self.assertIn("3 errors", out)

    def test_strips_code_fences(self) -> None:
        out = parse_runtime_summary_response("```\nfoo\n```")
        self.assertEqual(out, "foo")
        out = parse_runtime_summary_response("```markdown\nfoo\nbar\n```")
        self.assertEqual(out, "foo\nbar")

    def test_collapses_excessive_newlines(self) -> None:
        out = parse_runtime_summary_response("a\n\n\n\nb")
        self.assertEqual(out, "a\n\nb")

    def test_caps_length(self) -> None:
        long = "x" * 2000
        out = parse_runtime_summary_response(long)
        self.assertIsNotNone(out)
        self.assertLessEqual(len(out), 1501)
        self.assertTrue(out.endswith("…"))


# ---------- build_runtime_summary_request ----------


class BuildRuntimeSummaryRequestTest(unittest.TestCase):
    def test_includes_hooks_and_metrics(self) -> None:
        req = build_runtime_summary_request(_summary())
        self.assertIn("hook_0", req.user)
        self.assertIn("total_events", req.user)
        self.assertIn(("role", "report"), req.metadata)

    def test_truncates_excess_hooks(self) -> None:
        big = {
            "total_events": 5000,
            "hexdumps": 0,
            "errors": {},
            "hooks": {f"h_{i:03d}": {"enter": 1} for i in range(60)},
            "strings": {}, "enter_samples": {}, "ret_samples": {},
        }
        req = build_runtime_summary_request(big)
        # Only the first 30 (alpha-sorted) hooks should appear.
        self.assertIn("h_000", req.user)
        self.assertNotIn("h_059", req.user)


# ---------- summarize_runtime_log ----------


class SummarizeRuntimeLogTest(unittest.TestCase):
    def test_empty_log_skipped(self) -> None:
        prov = _CannedProvider("should not be called")
        result, stats = summarize_runtime_log(
            {"total_events": 0, "hooks": {}, "errors": {}},
            provider=prov, budget=TokenBudget(cap=10000),
        )
        self.assertIsNone(result)
        self.assertTrue(stats.skipped_empty_log)
        self.assertFalse(stats.invoked)
        self.assertEqual(prov.calls, [])

    def test_happy_path(self) -> None:
        prov = _CannedProvider(
            "Hooks 0 and 1 dominate event counts. Hook 0 has 1 error — "
            "review enter samples for malformed input."
        )
        result, stats = summarize_runtime_log(
            _summary(),
            provider=prov, budget=TokenBudget(cap=10000),
        )
        self.assertIsNotNone(result)
        self.assertIn("dominate", result)
        self.assertTrue(stats.invoked)
        self.assertTrue(stats.new_call)
        self.assertFalse(stats.cached_hit)

    def test_skip_response_counted(self) -> None:
        prov = _CannedProvider("SKIP")
        result, stats = summarize_runtime_log(
            _summary(), provider=prov, budget=TokenBudget(cap=10000),
        )
        self.assertIsNone(result)
        self.assertTrue(stats.invoked)
        self.assertTrue(stats.new_call)
        self.assertTrue(stats.skipped_model_declined)

    def test_unavailable_provider(self) -> None:
        result, stats = summarize_runtime_log(
            _summary(),
            provider=_UnavailableProvider(),
            budget=TokenBudget(cap=10000),
        )
        self.assertIsNone(result)
        self.assertTrue(stats.skipped_unavailable)
        self.assertFalse(stats.invoked)

    def test_provider_failure(self) -> None:
        result, stats = summarize_runtime_log(
            _summary(),
            provider=_BoomProvider(),
            budget=TokenBudget(cap=10000),
        )
        self.assertIsNone(result)
        self.assertTrue(stats.failed)

    def test_budget_pre_flight(self) -> None:
        prov = _CannedProvider("text")
        result, stats = summarize_runtime_log(
            _summary(), provider=prov, budget=TokenBudget(cap=5),
        )
        self.assertIsNone(result)
        self.assertTrue(stats.skipped_budget)
        self.assertEqual(prov.calls, [])

    def test_cache_hit_no_provider_call(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cache = LLMCache(Path(td) / "llm.sqlite3")
            req = build_runtime_summary_request(_summary())
            cache.put(req, LLMResponse(
                text="cached analyst paragraph",
                input_tokens=10, output_tokens=5,
                provider="canned", model="canned-1",
            ))
            prov = _CannedProvider("UNUSED")
            result, stats = summarize_runtime_log(
                _summary(), provider=prov,
                budget=TokenBudget(cap=10000), cache=cache,
            )
            self.assertEqual(result, "cached analyst paragraph")
            self.assertTrue(stats.cached_hit)
            self.assertFalse(stats.new_call)
            self.assertEqual(prov.calls, [])


# ---------- write_markdown_summary integration ----------


class WriteMarkdownSummaryWithAnalystTest(unittest.TestCase):
    def test_analyst_summary_appended(self) -> None:
        from venomhook.runtime_report import write_markdown_summary
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "summary.md"
            write_markdown_summary(
                _summary(), out, analyst_summary="Hooks 0/1 dominate events.",
            )
            text = out.read_text()
            self.assertIn("# Runtime Log Summary", text)
            self.assertIn("## Analyst Summary", text)
            self.assertIn("Hooks 0/1 dominate events.", text)

    def test_no_analyst_summary_no_section(self) -> None:
        from venomhook.runtime_report import write_markdown_summary
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "summary.md"
            write_markdown_summary(_summary(), out)
            text = out.read_text()
            self.assertNotIn("Analyst Summary", text)

    def test_html_analyst_block_escaped(self) -> None:
        from venomhook.runtime_report import write_html_summary
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "summary.html"
            write_html_summary(
                _summary(), out,
                analyst_summary="<script>alert(1)</script> noted.",
            )
            text = out.read_text()
            self.assertIn("Analyst Summary", text)
            # HTML escape protects the report from injection.
            self.assertNotIn("<script>", text)
            self.assertIn("&lt;script&gt;", text)


if __name__ == "__main__":
    unittest.main()

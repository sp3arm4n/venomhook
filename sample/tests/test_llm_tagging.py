"""Tests for venomhook.llm.tagging — semantic tagging integration point.

Covers:
    - parse_tagging_response: well-formed lines, malformed lines, bullets,
      blank lines, limit cap
    - build_tagging_request: includes name/imports/strings/existing_tags;
      truncates strings; metadata role tag set
    - tag_endpoints happy path with EchoProvider (no parsed tags from echo
      response — exercises the silent-no-op path) and a controlled
      stub provider returning canned tag lines (full apply path)
    - tag_endpoints with cache hit (no provider call)
    - tag_endpoints budget refusal / post-charge overrun (skipped_budget incremented)
    - tag_endpoints provider not available (skipped_unavailable for all)
    - tag_endpoints provider raises (failed counter, no exception out)
    - tag_endpoints applies semantic: prefix and llm: reason prefix,
      deduplicates against existing tags
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
from venomhook.llm.provider import (
    EchoProvider,
    LLMError,
    LLMProvider,
    LLMRequest,
    LLMResponse,
)
from venomhook.llm.tagging import (
    TaggingStats,
    build_tagging_request,
    parse_tagging_response,
    tag_endpoints,
)
from venomhook.models import EndpointMeta, FunctionMeta


def _endpoint(rva: int = 0x1000, tags: list[str] | None = None) -> EndpointMeta:
    return EndpointMeta(
        module="libfoo.so", arch="arm64", rva=rva, score=42,
        tags=list(tags or ["network"]),
        reason=["imports: connect"],
    )


def _function(rva: int = 0x1000, name: str = "Java_com_x_login") -> FunctionMeta:
    return FunctionMeta(
        va=0x401000, rva=rva, name=name,
        size=128, basic_blocks=12,
        callers=[0x500, 0x600],
        callees=[],
        strings=["password=", "Authorization: Bearer "],
        imports=["recv", "send", "EVP_DecryptInit_ex"],
    )


class _CannedProvider(LLMProvider):
    """Deterministic provider returning a fixed text and usage."""

    name = "canned"

    def __init__(self, text: str, *, in_t: int = 100, out_t: int = 50,
                 model: str = "canned-1") -> None:
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
        raise AssertionError("should not be called when unavailable")


class _BoomProvider(LLMProvider):
    name = "boom"
    model = "boom-1"

    def is_available(self) -> bool:
        return True

    def complete(self, req: LLMRequest) -> LLMResponse:
        raise LLMError("simulated provider failure")


# ---------- parse_tagging_response ----------


class ParseTaggingResponseTest(unittest.TestCase):
    def test_well_formed_lines(self) -> None:
        text = "login-handler: handles login\ntoken-refresh: refreshes session\n"
        out = parse_tagging_response(text)
        self.assertEqual(out, [
            ("login-handler", "handles login"),
            ("token-refresh", "refreshes session"),
        ])

    def test_strips_bullets_and_dashes(self) -> None:
        text = "- login-handler: handles login\n* token-refresh: refreshes session\n"
        out = parse_tagging_response(text)
        self.assertEqual(len(out), 2)

    def test_skips_malformed_lines(self) -> None:
        text = "Sorry, here are the tags:\nlogin-handler: real tag\nnotag here\n"
        out = parse_tagging_response(text)
        self.assertEqual(out, [("login-handler", "real tag")])

    def test_blank_lines_ignored(self) -> None:
        text = "\n\nlogin-handler: x\n\n"
        self.assertEqual(parse_tagging_response(text), [("login-handler", "x")])

    def test_limit_caps_output(self) -> None:
        text = "\n".join(f"tag-{i}: r" for i in range(10))
        out = parse_tagging_response(text, limit=3)
        self.assertEqual(len(out), 3)

    def test_uppercase_tag_rejected(self) -> None:
        # Pattern requires lowercase start; "Login-handler" should be skipped.
        out = parse_tagging_response("Login-handler: x\nlogin-handler: y\n")
        self.assertEqual(out, [("login-handler", "y")])


# ---------- build_tagging_request ----------


class BuildTaggingRequestTest(unittest.TestCase):
    def test_includes_function_metadata(self) -> None:
        ep = _endpoint(tags=["network", "jni"])
        fn = _function()
        req = build_tagging_request(ep, fn)
        self.assertIn("Java_com_x_login", req.user)
        self.assertIn("recv", req.user)
        self.assertIn("password=", req.user)
        self.assertIn("network, jni", req.user)
        self.assertIn("rva: 0x1000", req.user)

    def test_metadata_role_set(self) -> None:
        req = build_tagging_request(_endpoint(), _function())
        self.assertIn(("role", "tagging"), req.metadata)

    def test_truncates_long_strings(self) -> None:
        fn = FunctionMeta(va=0, rva=0x1000, name="x",
                          strings=["a" * 500], imports=[])
        req = build_tagging_request(_endpoint(), fn)
        # Each string is clipped to 80 chars + ellipsis
        self.assertNotIn("a" * 200, req.user)

    def test_handles_missing_function(self) -> None:
        req = build_tagging_request(_endpoint(), None)
        self.assertIn("(unnamed)", req.user)
        # Should still include endpoint metadata
        self.assertIn("rva: 0x1000", req.user)

    def test_existing_tags_none_label(self) -> None:
        ep = EndpointMeta(module="x.so", arch="arm64", rva=0x1, score=10,
                          tags=[], reason=[])
        req = build_tagging_request(ep, None)
        self.assertIn("existing_tags: (none)", req.user)


# ---------- tag_endpoints orchestration ----------


class TagEndpointsHappyPathTest(unittest.TestCase):
    def test_canned_provider_applies_tags_with_semantic_prefix(self) -> None:
        ep = _endpoint(tags=["network"])
        prov = _CannedProvider(
            "login-handler: validates credentials\n"
            "token-refresh: rotates JWT\n",
            in_t=10, out_t=5,
        )
        budget = TokenBudget(cap=10000)
        stats = tag_endpoints([ep], [_function()], provider=prov, budget=budget)

        self.assertEqual(stats.total_endpoints, 1)
        self.assertEqual(stats.new_calls, 1)
        self.assertEqual(stats.cached_hits, 0)
        self.assertEqual(stats.total_tags_added, 2)
        self.assertIn("semantic:login-handler", ep.tags)
        self.assertIn("semantic:token-refresh", ep.tags)
        self.assertTrue(any(r.startswith("llm: login-handler — ") for r in ep.reason))
        # Existing rule-based tag preserved
        self.assertIn("network", ep.tags)
        # Budget was charged
        self.assertEqual(budget.spent, 15)

    def test_dedupes_existing_semantic_tag(self) -> None:
        ep = _endpoint(tags=["network", "semantic:login-handler"])
        prov = _CannedProvider("login-handler: dup\nfresh-tag: real\n")
        stats = tag_endpoints([ep], [_function()],
                              provider=prov, budget=TokenBudget(cap=10000))
        # Only the not-yet-present tag was added
        self.assertEqual(stats.total_tags_added, 1)
        self.assertEqual(ep.tags.count("semantic:login-handler"), 1)
        self.assertIn("semantic:fresh-tag", ep.tags)


class TagEndpointsCacheTest(unittest.TestCase):
    def test_cache_hit_skips_provider_call(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with LLMCache(Path(td) / "llm.sqlite3") as cache:
                ep = _endpoint()
                fn = _function()
                req = build_tagging_request(ep, fn)
                cache.put(req, LLMResponse(
                    text="login-handler: cached\n",
                    input_tokens=10, output_tokens=5,
                    provider="canned", model="canned-1",
                ))
                # Provider would raise if called — proves cache hit short-circuits.
                stats = tag_endpoints(
                    [ep], [fn],
                    provider=_BoomProvider() if False else _CannedProvider("UNUSED", model="canned-1"),
                    budget=TokenBudget(cap=10000),
                    cache=cache,
                )
            self.assertEqual(stats.cached_hits, 1)
            self.assertEqual(stats.new_calls, 0)
            self.assertEqual(stats.total_tags_added, 1)
            self.assertIn("semantic:login-handler", ep.tags)


class TagEndpointsBudgetTest(unittest.TestCase):
    def test_can_afford_request_refuses_pre_flight(self) -> None:
        # Budget too small to cover any request — every endpoint skipped.
        ep = _endpoint()
        prov = _CannedProvider("login-handler: x\n")
        budget = TokenBudget(cap=10)  # request estimate >> 10
        stats = tag_endpoints([ep], [_function()], provider=prov, budget=budget)
        self.assertEqual(stats.skipped_budget, 1)
        self.assertEqual(stats.new_calls, 0)
        self.assertEqual(stats.total_tags_added, 0)
        self.assertEqual(prov.calls, [])

    def test_charge_overrun_discards_response_and_stops(self) -> None:
        # Pre-flight passes (low estimate) but actual usage blows the cap.
        ep1 = _endpoint(rva=0x1000)
        ep2 = _endpoint(rva=0x2000)
        prov = _CannedProvider(
            "login-handler: x\n",
            in_t=10000, out_t=10000,  # massive actual usage
        )
        budget = TokenBudget(cap=30000)
        stats = tag_endpoints(
            [ep1, ep2], [_function(rva=0x1000), _function(rva=0x2000)],
            provider=prov, budget=budget,
        )
        # First call's actual usage = 20000, fits within 30000 -> applies + new_calls=1
        # Second call: pre-flight estimate is small -> can_afford returns True for
        # input estimate, but charge of another 20000 would push to 40000 > 30000.
        # So second call's charge raises BudgetExhausted -> skipped_budget=1.
        # The over-budget response is discarded instead of being applied.
        self.assertEqual(stats.new_calls, 2)
        self.assertEqual(stats.skipped_budget, 1)
        self.assertIn("semantic:login-handler", ep1.tags)
        self.assertNotIn("semantic:login-handler", ep2.tags)
        self.assertEqual(budget.spent, 20000)


class TagEndpointsUnavailableProviderTest(unittest.TestCase):
    def test_skipped_unavailable_set_for_all_endpoints(self) -> None:
        eps = [_endpoint(rva=0x1000), _endpoint(rva=0x2000)]
        stats = tag_endpoints(
            eps, [_function(rva=0x1000), _function(rva=0x2000)],
            provider=_UnavailableProvider(),
            budget=TokenBudget(cap=10000),
        )
        self.assertEqual(stats.skipped_unavailable, 2)
        self.assertEqual(stats.new_calls, 0)
        self.assertEqual(stats.total_tags_added, 0)
        # Endpoints unchanged
        for ep in eps:
            self.assertNotIn(
                next((t for t in ep.tags if t.startswith("semantic:")), None),
                ep.tags,
            )

    def test_empty_endpoints_is_no_op(self) -> None:
        stats = tag_endpoints([], [], provider=_UnavailableProvider(),
                              budget=TokenBudget(cap=10))
        self.assertEqual(stats, TaggingStats(total_endpoints=0))


class TagEndpointsFailureTest(unittest.TestCase):
    def test_provider_error_counted_not_raised(self) -> None:
        ep = _endpoint()
        stats = tag_endpoints(
            [ep], [_function()],
            provider=_BoomProvider(),
            budget=TokenBudget(cap=10000),
        )
        self.assertEqual(stats.failed, 1)
        self.assertEqual(stats.total_tags_added, 0)
        # No semantic tags applied
        self.assertFalse(any(t.startswith("semantic:") for t in ep.tags))


class TagEndpointsEchoProviderTest(unittest.TestCase):
    def test_echo_response_does_not_match_format_zero_tags(self) -> None:
        # The Echo provider returns "[echo:echo] <user>" which doesn't match the
        # tag:reason pattern -> no tags applied, no failure.
        ep = _endpoint()
        stats = tag_endpoints(
            [ep], [_function()],
            provider=EchoProvider(),
            budget=TokenBudget(cap=100000),
        )
        self.assertEqual(stats.new_calls, 1)
        self.assertEqual(stats.total_tags_added, 0)
        self.assertEqual(stats.failed, 0)


if __name__ == "__main__":
    unittest.main()

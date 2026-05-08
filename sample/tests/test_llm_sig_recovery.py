"""Tests for venomhook.llm.sig_recovery — Phase 5 ⑤ wildcard recovery.

Covers:
    - parse_recovery_response validation:
        * SKIP / blank / no sig: line -> None
        * token count mismatch -> None (rejected)
        * non-hex non-?? token -> None
        * byte-rewrite (LLM tries to change a non-?? byte) -> None
        * wildcard ratio cap exceeded -> None
        * happy path -> cleaned uppercase sig
    - build_recovery_request: includes original sig, raw_bytes, role
    - recover_sigs orchestration:
        * specs without sig -> skipped_no_sig
        * unavailable provider -> skipped_unavailable for eligible
        * happy path -> sig replaced, count incremented
        * model SKIP -> skipped_model_declined
        * model returns invalid -> skipped_invalid_response
        * model returns unchanged sig -> skipped_model_declined (no improvement)
        * provider failure -> failed
        * cache hit -> no provider call
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
from venomhook.llm.sig_recovery import (
    SigRecoveryStats,
    build_recovery_request,
    parse_recovery_response,
    recover_sigs,
)
from venomhook.models import (
    FunctionMeta,
    HookConfig,
    HookProto,
    HookSpec,
)


def _spec(offset: int = 0x1000, sig: str | None = "48 89 5C 24 08 57 48 83") -> HookSpec:
    return HookSpec(
        module="libfoo.so", arch="arm64", offset=offset,
        sig=sig, name="login", tags=[],
        proto=HookProto(ret=None, args=[]),
        hook=HookConfig(),
    )


def _function(rva: int = 0x1000) -> FunctionMeta:
    return FunctionMeta(
        va=0x401000, rva=rva, name="login",
        size=128, basic_blocks=12,
        callers=[],
        callees=[],
        strings=[],
        imports=["recv", "send"],
        raw_bytes="48 89 5C 24 08 57 48 83 EC 20 48 8B FA 48 8B D9",
    )


class _CannedProvider(LLMProvider):
    name = "canned"

    def __init__(self, text: str, *, model: str = "canned-1",
                 in_t: int = 30, out_t: int = 20) -> None:
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


# ---------- parse_recovery_response ----------


class ParseRecoveryResponseTest(unittest.TestCase):
    ORIG = "48 89 5C 24 08 57 48 83"

    def test_skip_returns_none(self) -> None:
        self.assertIsNone(parse_recovery_response("SKIP", original_sig=self.ORIG))

    def test_blank_returns_none(self) -> None:
        self.assertIsNone(parse_recovery_response("", original_sig=self.ORIG))

    def test_no_sig_line_returns_none(self) -> None:
        self.assertIsNone(parse_recovery_response("48 89 5C 24",
                                                   original_sig=self.ORIG))

    def test_happy_path_inserts_wildcards(self) -> None:
        out = parse_recovery_response(
            "sig: 48 89 5C 24 ?? 57 48 83",
            original_sig=self.ORIG,
        )
        self.assertEqual(out, "48 89 5C 24 ?? 57 48 83")

    def test_uppercases_hex_tokens(self) -> None:
        out = parse_recovery_response(
            "sig: 48 89 5c 24 ?? 57 48 83",
            original_sig=self.ORIG,
        )
        self.assertEqual(out, "48 89 5C 24 ?? 57 48 83")

    def test_token_count_mismatch_rejected(self) -> None:
        # Too short
        self.assertIsNone(parse_recovery_response(
            "sig: 48 89 5C 24",
            original_sig=self.ORIG,
        ))
        # Too long
        self.assertIsNone(parse_recovery_response(
            "sig: 48 89 5C 24 08 57 48 83 ??",
            original_sig=self.ORIG,
        ))

    def test_invalid_token_rejected(self) -> None:
        self.assertIsNone(parse_recovery_response(
            "sig: 48 89 5C XX 08 57 48 83",
            original_sig=self.ORIG,
        ))

    def test_byte_rewrite_rejected(self) -> None:
        # LLM tried to change byte 0 (48 -> 90) — not allowed.
        self.assertIsNone(parse_recovery_response(
            "sig: 90 89 5C 24 08 57 48 83",
            original_sig=self.ORIG,
        ))

    def test_wildcard_ratio_cap(self) -> None:
        # 7 of 8 = 87.5% > 75% cap
        self.assertIsNone(parse_recovery_response(
            "sig: 48 ?? ?? ?? ?? ?? ?? ??",
            original_sig=self.ORIG,
        ))

    def test_wildcard_ratio_cap_at_75_pct(self) -> None:
        # 6 of 8 = 75.0% — at cap, allowed.
        out = parse_recovery_response(
            "sig: 48 89 ?? ?? ?? ?? ?? ??",
            original_sig=self.ORIG,
        )
        self.assertIsNotNone(out)

    def test_apologetic_header_skipped(self) -> None:
        text = "Sure! Here is the recovered sig:\nsig: 48 89 5C 24 ?? 57 48 83\n"
        out = parse_recovery_response(text, original_sig=self.ORIG)
        self.assertEqual(out, "48 89 5C 24 ?? 57 48 83")


# ---------- build_recovery_request ----------


class BuildRecoveryRequestTest(unittest.TestCase):
    def test_includes_sig_and_raw_bytes(self) -> None:
        req = build_recovery_request(_spec(), _function())
        self.assertIn("current_sig: 48 89 5C 24 08 57 48 83", req.user)
        self.assertIn("raw_bytes:", req.user)
        self.assertIn(("role", "recovery"), req.metadata)

    def test_handles_missing_function(self) -> None:
        req = build_recovery_request(_spec(), None)
        self.assertIn("current_sig:", req.user)
        self.assertNotIn("raw_bytes:", req.user)


# ---------- recover_sigs orchestration ----------


class RecoverSigsRuleFirstTest(unittest.TestCase):
    def test_specs_without_sig_skipped(self) -> None:
        specs = [_spec(sig=None), _spec(offset=0x2000, sig="")]
        prov = _CannedProvider("sig: ??")  # would error if called
        stats = recover_sigs(specs, [_function()],
                             provider=prov, budget=TokenBudget(cap=10000))
        self.assertEqual(stats.skipped_no_sig, 2)
        self.assertEqual(stats.eligible_specs, 0)
        self.assertEqual(prov.calls, [])

    def test_eligible_count_excludes_no_sig(self) -> None:
        specs = [_spec(), _spec(offset=0x2000, sig=None)]
        prov = _CannedProvider("sig: 48 89 5C 24 ?? 57 48 83")
        stats = recover_sigs(specs, [_function(), _function(rva=0x2000)],
                             provider=prov, budget=TokenBudget(cap=10000))
        self.assertEqual(stats.eligible_specs, 1)
        self.assertEqual(stats.skipped_no_sig, 1)


class RecoverSigsHappyPathTest(unittest.TestCase):
    def test_recovers_sig(self) -> None:
        spec = _spec()
        prov = _CannedProvider("sig: 48 89 5C 24 ?? 57 48 83")
        stats = recover_sigs([spec], [_function()],
                             provider=prov, budget=TokenBudget(cap=10000))
        self.assertEqual(stats.sigs_recovered, 1)
        self.assertEqual(spec.sig, "48 89 5C 24 ?? 57 48 83")

    def test_skip_response(self) -> None:
        spec = _spec()
        original = spec.sig
        prov = _CannedProvider("SKIP")
        stats = recover_sigs([spec], [_function()],
                             provider=prov, budget=TokenBudget(cap=10000))
        self.assertEqual(stats.sigs_recovered, 0)
        self.assertEqual(stats.skipped_model_declined, 1)
        self.assertEqual(spec.sig, original)

    def test_unchanged_sig_counted_as_decline(self) -> None:
        spec = _spec()
        prov = _CannedProvider("sig: 48 89 5C 24 08 57 48 83")  # identical
        stats = recover_sigs([spec], [_function()],
                             provider=prov, budget=TokenBudget(cap=10000))
        self.assertEqual(stats.sigs_recovered, 0)
        self.assertEqual(stats.skipped_model_declined, 1)

    def test_invalid_response_counted(self) -> None:
        spec = _spec()
        prov = _CannedProvider("sig: 48 ZZ 5C 24 08 57 48 83")
        stats = recover_sigs([spec], [_function()],
                             provider=prov, budget=TokenBudget(cap=10000))
        self.assertEqual(stats.skipped_invalid_response, 1)
        self.assertEqual(spec.sig, "48 89 5C 24 08 57 48 83")  # unchanged

    def test_byte_rewrite_attempt_rejected(self) -> None:
        spec = _spec()
        # Attempt to change byte[0] from 48 to 90 — disallowed.
        prov = _CannedProvider("sig: 90 89 5C 24 08 57 48 83")
        stats = recover_sigs([spec], [_function()],
                             provider=prov, budget=TokenBudget(cap=10000))
        self.assertEqual(stats.skipped_invalid_response, 1)
        # Original sig untouched.
        self.assertEqual(spec.sig, "48 89 5C 24 08 57 48 83")


class RecoverSigsCacheTest(unittest.TestCase):
    def test_cache_hit_no_provider_call(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cache = LLMCache(Path(td) / "llm.sqlite3")
            spec = _spec()
            fn = _function()
            req = build_recovery_request(spec, fn)
            cache.put(req, LLMResponse(
                text="sig: 48 89 5C 24 ?? 57 48 83",
                input_tokens=10, output_tokens=5,
                provider="canned", model="canned-1",
            ))
            prov = _CannedProvider("UNUSED")
            stats = recover_sigs([spec], [fn], provider=prov,
                                 budget=TokenBudget(cap=10000), cache=cache)
            self.assertEqual(stats.cached_hits, 1)
            self.assertEqual(stats.new_calls, 0)
            self.assertEqual(prov.calls, [])
            self.assertEqual(spec.sig, "48 89 5C 24 ?? 57 48 83")


class RecoverSigsFailureTest(unittest.TestCase):
    def test_unavailable_provider(self) -> None:
        spec = _spec()
        stats = recover_sigs([spec], [_function()],
                             provider=_UnavailableProvider(),
                             budget=TokenBudget(cap=10000))
        self.assertEqual(stats.skipped_unavailable, 1)
        self.assertEqual(spec.sig, "48 89 5C 24 08 57 48 83")  # unchanged

    def test_provider_failure(self) -> None:
        spec = _spec()
        stats = recover_sigs([spec], [_function()],
                             provider=_BoomProvider(),
                             budget=TokenBudget(cap=10000))
        self.assertEqual(stats.failed, 1)
        self.assertEqual(spec.sig, "48 89 5C 24 08 57 48 83")

    def test_budget_pre_flight(self) -> None:
        spec = _spec()
        prov = _CannedProvider("sig: 48 89 5C 24 ?? 57 48 83")
        stats = recover_sigs([spec], [_function()],
                             provider=prov, budget=TokenBudget(cap=5))
        self.assertEqual(stats.skipped_budget, 1)
        self.assertEqual(prov.calls, [])

    def test_empty_input_no_op(self) -> None:
        stats = recover_sigs([], [], provider=_UnavailableProvider(),
                             budget=TokenBudget(cap=10))
        self.assertEqual(stats, SigRecoveryStats(total_specs=0))


if __name__ == "__main__":
    unittest.main()

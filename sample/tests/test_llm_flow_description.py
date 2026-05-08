"""Tests for venomhook.llm.flow_description — Phase 5 ③ flow description.

Covers:
    - parse_flow_response: well-formed, SKIP, blank, multi-line, quote/
      bullet stripping, length cap
    - build_flow_request: with bridge (precise), without bridge (demangle
      fallback), JNI symbol vs unnamed, role metadata
    - describe_flows: rule-first (skips already-described), JNI gating
      (non-JNI specs skipped), happy path with/without bridge, cache,
      budget, unavailable, provider failure
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
from venomhook.llm.flow_description import (
    FlowDescriptionStats,
    build_flow_request,
    describe_flows,
    parse_flow_response,
)
from venomhook.llm.provider import LLMError, LLMProvider, LLMRequest, LLMResponse
from venomhook.models import (
    FunctionMeta,
    HookConfig,
    HookProto,
    HookSpec,
    JavaNativeMethod,
    JniBridge,
)


def _spec_jni(
    offset: int = 0x1000,
    name: str = "Java_com_example_AuthClient_login",
    description: str | None = None,
) -> HookSpec:
    return HookSpec(
        module="libfoo.so", arch="arm64", offset=offset,
        sig=None, name=name, tags=["jni"],
        proto=HookProto(ret=None, args=[]),
        hook=HookConfig(),
        description=description,
    )


def _spec_non_jni(offset: int = 0x2000, name: str = "rust_main") -> HookSpec:
    return HookSpec(
        module="libfoo.so", arch="arm64", offset=offset,
        sig=None, name=name, tags=[],
        proto=HookProto(ret=None, args=[]),
        hook=HookConfig(),
    )


def _function(rva: int = 0x1000, name: str = "Java_com_example_AuthClient_login") -> FunctionMeta:
    return FunctionMeta(
        va=0x401000, rva=rva, name=name,
        size=128, basic_blocks=12,
        callers=[0x500],
        callees=[],
        strings=["password=", "Bearer "],
        imports=["GetStringUTFChars", "EVP_DigestInit_ex"],
    )


def _bridge(symbol: str = "Java_com_example_AuthClient_login") -> JniBridge:
    return JniBridge(
        java_method=JavaNativeMethod(
            class_fqn="com.example.AuthClient",
            method_name="login",
            return_type="String",
            arg_types=["String", "String"],
        ),
        predicted_short=symbol,
        matched_symbol=symbol,
    )


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


# ---------- parse_flow_response ----------


class ParseFlowResponseTest(unittest.TestCase):
    def test_well_formed_sentence(self) -> None:
        out = parse_flow_response("Validates credentials and returns a token.")
        self.assertEqual(out, "Validates credentials and returns a token.")

    def test_skip_sentinel_returns_none(self) -> None:
        self.assertIsNone(parse_flow_response("SKIP"))
        self.assertIsNone(parse_flow_response("SKIP - too sparse"))

    def test_blank_returns_none(self) -> None:
        self.assertIsNone(parse_flow_response(""))
        self.assertIsNone(parse_flow_response("   \n\n  \n"))

    def test_takes_first_nonempty_line(self) -> None:
        text = "\nFirst sentence.\nrationale that we ignore.\n"
        self.assertEqual(parse_flow_response(text), "First sentence.")

    def test_strips_quotes_and_bullets(self) -> None:
        self.assertEqual(parse_flow_response('"Wrapped sentence."'),
                         "Wrapped sentence.")
        self.assertEqual(parse_flow_response("- Bulleted sentence."),
                         "Bulleted sentence.")
        self.assertEqual(parse_flow_response("* Asterisk."), "Asterisk.")

    def test_collapses_whitespace(self) -> None:
        self.assertEqual(parse_flow_response("foo   bar    baz"),
                         "foo bar baz")

    def test_caps_length(self) -> None:
        long = "x" * 400
        out = parse_flow_response(long)
        self.assertIsNotNone(out)
        self.assertLessEqual(len(out), 281)
        self.assertTrue(out.endswith("…"))


# ---------- build_flow_request ----------


class BuildFlowRequestTest(unittest.TestCase):
    def test_with_bridge_uses_precise_java_signature(self) -> None:
        req = build_flow_request(_spec_jni(), _function(), _bridge())
        self.assertIn("com.example.AuthClient.login", req.user)
        self.assertIn("String", req.user)
        self.assertIn(("role", "flow"), req.metadata)

    def test_without_bridge_demangles_symbol(self) -> None:
        req = build_flow_request(_spec_jni(), _function())
        # Demangle: Java_com_example_AuthClient_login -> class com.example.AuthClient, method login
        self.assertIn("java_class_guess: com.example.AuthClient", req.user)
        self.assertIn("java_method_guess: login", req.user)

    def test_includes_imports_and_strings(self) -> None:
        req = build_flow_request(_spec_jni(), _function())
        self.assertIn("GetStringUTFChars", req.user)
        self.assertIn("password=", req.user)

    def test_handles_missing_function(self) -> None:
        req = build_flow_request(_spec_jni(), None)
        self.assertIn("native_symbol:", req.user)


# ---------- describe_flows orchestration ----------


class DescribeFlowsRuleFirstTest(unittest.TestCase):
    def test_existing_description_skipped(self) -> None:
        spec = _spec_jni(description="prior summary")
        prov = _CannedProvider("New summary")
        stats = describe_flows([spec], [_function()],
                               provider=prov, budget=TokenBudget(cap=10000))
        self.assertEqual(stats.skipped_already_described, 1)
        self.assertEqual(prov.calls, [])
        self.assertEqual(spec.description, "prior summary")

    def test_non_jni_spec_skipped(self) -> None:
        spec = _spec_non_jni()
        prov = _CannedProvider("Should not be called.")
        stats = describe_flows([spec], [_function(rva=0x2000, name="rust_main")],
                               provider=prov, budget=TokenBudget(cap=10000))
        self.assertEqual(stats.skipped_non_jni, 1)
        self.assertEqual(stats.eligible_specs, 0)
        self.assertEqual(prov.calls, [])
        self.assertIsNone(spec.description)


class DescribeFlowsHappyPathTest(unittest.TestCase):
    def test_with_bridge_fills_description(self) -> None:
        spec = _spec_jni()
        prov = _CannedProvider("Validates user credentials and returns a session token.")
        budget = TokenBudget(cap=10000)
        stats = describe_flows(
            [spec], [_function()],
            provider=prov, budget=budget, bridges=[_bridge()],
        )
        self.assertEqual(stats.descriptions_filled, 1)
        self.assertEqual(spec.description,
                         "Validates user credentials and returns a session token.")
        self.assertEqual(stats.new_calls, 1)

    def test_without_bridge_still_works_via_demangle(self) -> None:
        spec = _spec_jni()
        prov = _CannedProvider("Logs the user in.")
        stats = describe_flows([spec], [_function()],
                               provider=prov, budget=TokenBudget(cap=10000))
        self.assertEqual(spec.description, "Logs the user in.")
        # The request was built without a bridge -> the prompt contains the
        # demangle fallback labels, not the precise Java signature.
        self.assertIn("java_class_guess", prov.calls[0].user)
        self.assertNotIn("java_signature:", prov.calls[0].user)

    def test_skip_response_counts_model_declined(self) -> None:
        spec = _spec_jni()
        prov = _CannedProvider("SKIP")
        stats = describe_flows([spec], [_function()],
                               provider=prov, budget=TokenBudget(cap=10000))
        self.assertEqual(stats.new_calls, 1)
        self.assertEqual(stats.descriptions_filled, 0)
        self.assertEqual(stats.skipped_model_declined, 1)
        self.assertIsNone(spec.description)


class DescribeFlowsCacheTest(unittest.TestCase):
    def test_cache_hit_no_provider_call(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cache = LLMCache(Path(td) / "llm.sqlite3")
            spec = _spec_jni()
            fn = _function()
            req = build_flow_request(spec, fn)
            cache.put(req, LLMResponse(
                text="Cached description sentence.",
                input_tokens=10, output_tokens=5,
                provider="canned", model="canned-1",
            ))
            prov = _CannedProvider("UNUSED")
            stats = describe_flows([spec], [fn], provider=prov,
                                   budget=TokenBudget(cap=10000), cache=cache)
            self.assertEqual(stats.cached_hits, 1)
            self.assertEqual(stats.new_calls, 0)
            self.assertEqual(prov.calls, [])
            self.assertEqual(spec.description, "Cached description sentence.")


class DescribeFlowsFailureModeTest(unittest.TestCase):
    def test_unavailable_provider_skips_all_eligible(self) -> None:
        specs = [_spec_jni(offset=0x1000), _spec_jni(offset=0x2000),
                 _spec_non_jni()]
        stats = describe_flows(
            specs,
            [_function(rva=0x1000), _function(rva=0x2000)],
            provider=_UnavailableProvider(),
            budget=TokenBudget(cap=10000),
        )
        self.assertEqual(stats.skipped_unavailable, 2)
        self.assertEqual(stats.skipped_non_jni, 1)
        for s in specs:
            self.assertIsNone(s.description)

    def test_provider_failure_counted(self) -> None:
        spec = _spec_jni()
        stats = describe_flows([spec], [_function()],
                               provider=_BoomProvider(),
                               budget=TokenBudget(cap=10000))
        self.assertEqual(stats.failed, 1)
        self.assertIsNone(spec.description)

    def test_budget_pre_flight_refusal(self) -> None:
        spec = _spec_jni()
        prov = _CannedProvider("desc")
        stats = describe_flows([spec], [_function()],
                               provider=prov, budget=TokenBudget(cap=5))
        self.assertEqual(stats.skipped_budget, 1)
        self.assertEqual(stats.new_calls, 0)
        self.assertEqual(prov.calls, [])

    def test_empty_input_no_op(self) -> None:
        stats = describe_flows([], [], provider=_UnavailableProvider(),
                               budget=TokenBudget(cap=10))
        self.assertEqual(stats, FlowDescriptionStats(total_specs=0))


# ---------- HookSpec.description roundtrip ----------


class HookSpecDescriptionRoundtripTest(unittest.TestCase):
    def test_to_dict_omits_none_description(self) -> None:
        spec = _spec_jni()
        self.assertNotIn("description", spec.to_dict())

    def test_to_dict_includes_set_description(self) -> None:
        spec = _spec_jni(description="x")
        self.assertEqual(spec.to_dict()["description"], "x")

    def test_from_dict_accepts_missing_description(self) -> None:
        spec = HookSpec.from_dict({
            "module": "libx.so", "arch": "arm64", "offset": "0x100",
        })
        self.assertIsNone(spec.description)

    def test_from_dict_accepts_explicit_description(self) -> None:
        spec = HookSpec.from_dict({
            "module": "libx.so", "arch": "arm64", "offset": "0x100",
            "description": "explicit",
        })
        self.assertEqual(spec.description, "explicit")


if __name__ == "__main__":
    unittest.main()

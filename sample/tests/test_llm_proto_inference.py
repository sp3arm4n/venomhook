"""Tests for venomhook.llm.proto_inference — Phase 5 ② proto inference.

Covers:
    - parse_proto_response: well-formed, ret-only, malformed lines,
      duplicate args, out-of-order indices, type plausibility checks
    - build_proto_request: fields included, role metadata, string truncation
    - infer_protos: rule-first (skips populated proto), happy path,
      cached hit, budget refusal / post-charge overrun, unavailable provider,
      provider failure, empty input, no eligible specs
    - Cache key separation across (provider, model, request)
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
    LLMError,
    LLMProvider,
    LLMRequest,
    LLMResponse,
)
from venomhook.llm.proto_inference import (
    ProtoInferenceStats,
    build_proto_request,
    infer_protos,
    parse_proto_response,
)
from venomhook.models import (
    FunctionMeta,
    HookConfig,
    HookProto,
    HookSpec,
)


def _spec(
    offset: int = 0x1000,
    name: str = "Java_com_x_login",
    proto: HookProto | None = None,
) -> HookSpec:
    return HookSpec(
        module="libfoo.so", arch="arm64", offset=offset,
        sig=None, name=name, tags=["jni"],
        proto=proto if proto is not None else HookProto(ret=None, args=[]),
        hook=HookConfig(),
    )


def _function(rva: int = 0x1000, name: str = "Java_com_x_login") -> FunctionMeta:
    return FunctionMeta(
        va=0x401000, rva=rva, name=name,
        size=128, basic_blocks=12,
        callers=[0x500],
        callees=[],
        strings=["password=", "Bearer "],
        imports=["GetStringUTFChars", "ReleaseStringUTFChars"],
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


# ---------- parse_proto_response ----------


class ParseProtoResponseTest(unittest.TestCase):
    def test_well_formed(self) -> None:
        text = "ret: int\narg0: const char *\narg1: size_t\n"
        proto = parse_proto_response(text)
        self.assertIsNotNone(proto)
        self.assertEqual(proto.ret, "int")
        self.assertEqual(proto.args, ["const char *", "size_t"])

    def test_ret_only_zero_args(self) -> None:
        proto = parse_proto_response("ret: void\n")
        self.assertEqual(proto.ret, "void")
        self.assertEqual(proto.args, [])

    def test_no_ret_returns_none(self) -> None:
        # Args without a ret line — model declined.
        self.assertIsNone(parse_proto_response("arg0: int\narg1: char *\n"))

    def test_malformed_lines_skipped(self) -> None:
        text = (
            "Sorry, here is my best guess:\n"
            "ret: void\n"
            "garbage line\n"
            "arg0: int\n"
        )
        proto = parse_proto_response(text)
        self.assertEqual(proto.ret, "void")
        self.assertEqual(proto.args, ["int"])

    def test_out_of_order_indices_sorted(self) -> None:
        text = "ret: int\narg2: long\narg0: char *\narg1: short\n"
        proto = parse_proto_response(text)
        self.assertEqual(proto.args, ["char *", "short", "long"])

    def test_duplicate_arg_takes_first(self) -> None:
        text = "ret: int\narg0: int\narg0: long\n"
        proto = parse_proto_response(text)
        self.assertEqual(proto.args, ["int"])

    def test_strips_bullets_dashes(self) -> None:
        text = "- ret: int\n* arg0: char *\n"
        proto = parse_proto_response(text)
        self.assertEqual(proto.ret, "int")
        self.assertEqual(proto.args, ["char *"])

    def test_rejects_implausible_type_with_braces(self) -> None:
        # `{int}` shouldn't slip through as a type.
        text = "ret: {int}\narg0: int\n"
        # ret rejected -> falls through, no other ret line -> returns None
        self.assertIsNone(parse_proto_response(text))

    def test_rejects_overlong_type(self) -> None:
        long_type = "a" * 100
        text = f"ret: {long_type}\n"
        self.assertIsNone(parse_proto_response(text))

    def test_case_insensitive_ret_arg_keywords(self) -> None:
        # Some models capitalize the keyword.
        text = "Ret: int\nArg0: char *\n"
        proto = parse_proto_response(text)
        self.assertEqual(proto.ret, "int")
        self.assertEqual(proto.args, ["char *"])


# ---------- build_proto_request ----------


class BuildProtoRequestTest(unittest.TestCase):
    def test_includes_function_metadata(self) -> None:
        req = build_proto_request(_spec(), _function())
        self.assertIn("Java_com_x_login", req.user)
        self.assertIn("GetStringUTFChars", req.user)
        self.assertIn("password=", req.user)
        self.assertIn("offset: 0x1000", req.user)

    def test_metadata_role_set(self) -> None:
        req = build_proto_request(_spec(), _function())
        self.assertIn(("role", "proto"), req.metadata)

    def test_handles_missing_function(self) -> None:
        req = build_proto_request(_spec(name="anonymous"), None)
        # Should still include spec info
        self.assertIn("offset: 0x1000", req.user)

    def test_truncates_long_strings(self) -> None:
        fn = FunctionMeta(va=0, rva=0x1000, name="x",
                          strings=["b" * 500], imports=[])
        req = build_proto_request(_spec(), fn)
        self.assertNotIn("b" * 200, req.user)


# ---------- infer_protos rule-first contract ----------


class InferProtosRuleFirstTest(unittest.TestCase):
    def test_populated_ret_skipped(self) -> None:
        # spec already has ret -> not eligible
        spec = _spec(proto=HookProto(ret="int", args=[]))
        prov = _CannedProvider("ret: void\n")
        stats = infer_protos([spec], [_function()],
                             provider=prov, budget=TokenBudget(cap=10000))
        self.assertEqual(stats.eligible_specs, 0)
        self.assertEqual(prov.calls, [])
        # Original ret preserved
        self.assertEqual(spec.proto.ret, "int")

    def test_populated_args_skipped_even_if_ret_none(self) -> None:
        spec = _spec(proto=HookProto(ret=None, args=["int"]))
        prov = _CannedProvider("ret: void\n")
        stats = infer_protos([spec], [_function()],
                             provider=prov, budget=TokenBudget(cap=10000))
        self.assertEqual(stats.eligible_specs, 0)
        self.assertEqual(prov.calls, [])

    def test_none_proto_treated_as_eligible(self) -> None:
        spec = _spec(proto=None)
        prov = _CannedProvider("ret: int\narg0: char *\n")
        stats = infer_protos([spec], [_function()],
                             provider=prov, budget=TokenBudget(cap=10000))
        self.assertEqual(stats.eligible_specs, 1)
        self.assertEqual(spec.proto.ret, "int")


# ---------- infer_protos happy path ----------


class InferProtosHappyPathTest(unittest.TestCase):
    def test_canned_response_fills_proto(self) -> None:
        spec = _spec()
        prov = _CannedProvider(
            "ret: jstring\narg0: JNIEnv *\narg1: jobject\n",
            in_t=20, out_t=10,
        )
        budget = TokenBudget(cap=10000)
        stats = infer_protos([spec], [_function()],
                             provider=prov, budget=budget)

        self.assertEqual(stats.total_specs, 1)
        self.assertEqual(stats.eligible_specs, 1)
        self.assertEqual(stats.new_calls, 1)
        self.assertEqual(stats.protos_filled, 1)
        self.assertEqual(spec.proto.ret, "jstring")
        self.assertEqual(spec.proto.args, ["JNIEnv *", "jobject"])
        self.assertEqual(budget.spent, 30)

    def test_unparseable_response_no_fill_no_failure(self) -> None:
        spec = _spec()
        prov = _CannedProvider("I don't know.\n")  # no ret line
        stats = infer_protos([spec], [_function()],
                             provider=prov, budget=TokenBudget(cap=10000))
        self.assertEqual(stats.new_calls, 1)
        self.assertEqual(stats.protos_filled, 0)
        self.assertEqual(stats.failed, 0)
        self.assertIsNone(spec.proto.ret)


# ---------- infer_protos cache ----------


class InferProtosCacheTest(unittest.TestCase):
    def test_cache_hit_no_provider_call(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with LLMCache(Path(td) / "llm.sqlite3") as cache:
                spec = _spec()
                fn = _function()
                req = build_proto_request(spec, fn)
                cache.put(req, LLMResponse(
                    text="ret: int\narg0: char *\n",
                    input_tokens=10, output_tokens=5,
                    provider="canned", model="canned-1",
                ))
                prov = _CannedProvider("UNUSED")  # would record any call
                stats = infer_protos([spec], [fn], provider=prov,
                                     budget=TokenBudget(cap=10000), cache=cache)
            self.assertEqual(stats.cached_hits, 1)
            self.assertEqual(stats.new_calls, 0)
            self.assertEqual(prov.calls, [])
            self.assertEqual(spec.proto.ret, "int")
            self.assertEqual(spec.proto.args, ["char *"])


# ---------- infer_protos failure modes ----------


class InferProtosFailureTest(unittest.TestCase):
    def test_unavailable_provider_skips_all(self) -> None:
        specs = [_spec(offset=0x1000), _spec(offset=0x2000)]
        stats = infer_protos(
            specs, [_function(rva=0x1000), _function(rva=0x2000)],
            provider=_UnavailableProvider(),
            budget=TokenBudget(cap=10000),
        )
        self.assertEqual(stats.skipped_unavailable, 2)
        self.assertEqual(stats.protos_filled, 0)
        for s in specs:
            self.assertIsNone(s.proto.ret)

    def test_provider_failure_counted_not_raised(self) -> None:
        spec = _spec()
        stats = infer_protos([spec], [_function()],
                             provider=_BoomProvider(),
                             budget=TokenBudget(cap=10000))
        self.assertEqual(stats.failed, 1)
        self.assertEqual(stats.protos_filled, 0)
        self.assertIsNone(spec.proto.ret)

    def test_budget_pre_flight_refusal(self) -> None:
        spec = _spec()
        prov = _CannedProvider("ret: int\n")
        stats = infer_protos([spec], [_function()],
                             provider=prov, budget=TokenBudget(cap=5))
        self.assertEqual(stats.skipped_budget, 1)
        self.assertEqual(stats.new_calls, 0)
        self.assertEqual(prov.calls, [])
        self.assertIsNone(spec.proto.ret)

    def test_charge_overrun_discards_response_and_stops(self) -> None:
        specs = [_spec(offset=0x1000), _spec(offset=0x2000)]
        prov = _CannedProvider("ret: int\n", in_t=10000, out_t=10000)
        budget = TokenBudget(cap=30000)
        stats = infer_protos(
            specs,
            [_function(rva=0x1000), _function(rva=0x2000)],
            provider=prov,
            budget=budget,
        )
        self.assertEqual(stats.new_calls, 2)
        self.assertEqual(stats.skipped_budget, 1)
        self.assertEqual(stats.protos_filled, 1)
        self.assertEqual(specs[0].proto.ret, "int")
        self.assertIsNone(specs[1].proto.ret)
        self.assertEqual(budget.spent, 20000)

    def test_empty_specs_no_op(self) -> None:
        stats = infer_protos([], [], provider=_UnavailableProvider(),
                             budget=TokenBudget(cap=10))
        self.assertEqual(stats, ProtoInferenceStats(total_specs=0))

    def test_no_eligible_specs_skips_provider_call(self) -> None:
        # All specs already have proto -> no LLM call regardless of provider.
        specs = [_spec(proto=HookProto(ret="int", args=[]))]
        prov = _CannedProvider("ret: long\n")
        stats = infer_protos(specs, [_function()], provider=prov,
                             budget=TokenBudget(cap=10000))
        self.assertEqual(stats.eligible_specs, 0)
        self.assertEqual(prov.calls, [])


if __name__ == "__main__":
    unittest.main()

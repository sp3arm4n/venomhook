"""Tests for venomhook.llm.budget — TokenBudget and helpers.

Covers:
    - estimate_tokens char/4 with non-empty floor
    - TokenBudget construction validation (cap >= 0)
    - remaining / exhausted properties
    - can_afford pre-flight (positive, negative, zero cap)
    - can_afford_request estimates from system + user + max_tokens
    - charge happy path (incremental spend)
    - charge over the cap raises BudgetExhausted
    - charge with 0 token counts falls back to text estimate
    - charge with explicit token counts overrides estimate
    - BudgetExhausted is an LLMError
    - reset zeros spent without changing cap
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from venomhook.llm.budget import BudgetExhausted, TokenBudget, estimate_tokens
from venomhook.llm.provider import LLMError, LLMRequest, LLMResponse


class EstimateTokensTest(unittest.TestCase):
    def test_empty_string_yields_zero(self) -> None:
        self.assertEqual(estimate_tokens(""), 0)

    def test_short_string_yields_at_least_one(self) -> None:
        self.assertEqual(estimate_tokens("a"), 1)
        self.assertEqual(estimate_tokens("abc"), 1)

    def test_long_string_uses_char_div_four(self) -> None:
        self.assertEqual(estimate_tokens("x" * 80), 20)


class TokenBudgetConstructionTest(unittest.TestCase):
    def test_cap_zero_allowed_disables_layer(self) -> None:
        b = TokenBudget(cap=0)
        self.assertEqual(b.remaining, 0)
        self.assertTrue(b.exhausted)
        self.assertFalse(b.can_afford(1))

    def test_cap_negative_raises(self) -> None:
        with self.assertRaises(ValueError):
            TokenBudget(cap=-1)

    def test_default_spent_is_zero(self) -> None:
        self.assertEqual(TokenBudget(cap=100).spent, 0)


class TokenBudgetCanAffordTest(unittest.TestCase):
    def test_can_afford_within_cap(self) -> None:
        b = TokenBudget(cap=100)
        self.assertTrue(b.can_afford(50))
        self.assertTrue(b.can_afford(100))

    def test_cannot_afford_over_cap(self) -> None:
        b = TokenBudget(cap=100)
        self.assertFalse(b.can_afford(101))

    def test_cannot_afford_with_existing_spend(self) -> None:
        b = TokenBudget(cap=100, spent=80)
        self.assertTrue(b.can_afford(20))
        self.assertFalse(b.can_afford(21))

    def test_cap_zero_refuses_everything(self) -> None:
        b = TokenBudget(cap=0)
        self.assertFalse(b.can_afford(0))
        self.assertFalse(b.can_afford(1))

    def test_negative_estimate_refused(self) -> None:
        self.assertFalse(TokenBudget(cap=100).can_afford(-1))

    def test_can_afford_request_uses_request_max_tokens(self) -> None:
        b = TokenBudget(cap=200)
        req = LLMRequest(system="s" * 40, user="u" * 40, max_tokens=64)
        # estimate = 10 + 10 + 64 = 84 < 200
        self.assertTrue(b.can_afford_request(req))

    def test_can_afford_request_refuses_when_max_tokens_too_big(self) -> None:
        b = TokenBudget(cap=50)
        req = LLMRequest(system="", user="", max_tokens=1000)
        self.assertFalse(b.can_afford_request(req))


class TokenBudgetChargeTest(unittest.TestCase):
    def _resp(self, in_t: int = 0, out_t: int = 0, text: str = "answer") -> LLMResponse:
        return LLMResponse(text=text, input_tokens=in_t, output_tokens=out_t,
                           provider="echo", model="echo-1")

    def test_charge_adds_explicit_token_counts(self) -> None:
        b = TokenBudget(cap=100)
        spent = b.charge(self._resp(in_t=10, out_t=5))
        self.assertEqual(spent, 15)
        self.assertEqual(b.spent, 15)
        self.assertEqual(b.remaining, 85)

    def test_charge_falls_back_to_text_estimate_when_counts_zero(self) -> None:
        b = TokenBudget(cap=100)
        # text length 12 -> char/4 = 3
        spent = b.charge(self._resp(text="answer here!"))
        self.assertEqual(spent, 3)

    def test_charge_over_cap_raises_budget_exhausted(self) -> None:
        b = TokenBudget(cap=10)
        with self.assertRaises(BudgetExhausted) as ctx:
            b.charge(self._resp(in_t=5, out_t=10))
        msg = str(ctx.exception)
        self.assertIn("token budget exhausted", msg)
        self.assertIn("cap=10", msg)
        # spent should remain unchanged after a failed charge
        self.assertEqual(b.spent, 0)

    def test_budget_exhausted_is_llm_error_subclass(self) -> None:
        self.assertTrue(issubclass(BudgetExhausted, LLMError))

    def test_charge_at_cap_boundary_succeeds(self) -> None:
        b = TokenBudget(cap=15)
        b.charge(self._resp(in_t=10, out_t=5))
        self.assertEqual(b.spent, 15)
        self.assertTrue(b.exhausted)

    def test_charge_negative_usage_raises(self) -> None:
        b = TokenBudget(cap=100)
        with self.assertRaises(ValueError):
            b.charge(self._resp(in_t=-1, out_t=0))

    def test_multiple_charges_accumulate(self) -> None:
        b = TokenBudget(cap=100)
        b.charge(self._resp(in_t=10, out_t=10))
        b.charge(self._resp(in_t=20, out_t=10))
        self.assertEqual(b.spent, 50)


class TokenBudgetResetTest(unittest.TestCase):
    def test_reset_zeros_spent_keeps_cap(self) -> None:
        b = TokenBudget(cap=100, spent=80)
        b.reset()
        self.assertEqual(b.spent, 0)
        self.assertEqual(b.cap, 100)
        self.assertEqual(b.remaining, 100)


if __name__ == "__main__":
    unittest.main()

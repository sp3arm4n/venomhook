"""Token budget tracker for opt-in LLM calls.

Phase 5 / Unit 3. Caps total spend per operator session so a forgotten
``--use-llm-*`` flag on a large APK can't run up an unbounded bill.
The CLI surfaces this as ``--llm-token-budget N`` (default to be wired
in Unit 5+); when the cap is exhausted, integration points fall back
to their rule-based output.

Two failure modes:

    * **Pre-flight refusal** — :meth:`TokenBudget.can_afford` returns
      False. Caller skips the LLM and uses its rule-based path. Quiet,
      no exception. This is the recommended path because it lets the
      pipeline finish.

    * **Post-charge overrun** — :meth:`TokenBudget.charge` raises
      :class:`BudgetExhausted`. This happens when the SDK reports more
      output tokens than the pre-flight estimate. Caller can catch and
      degrade, or let it bubble up if they treat it as a config error.

Token counts are advisory: providers that can't report usage fall back
to a char/4 estimate (see :func:`estimate_tokens`). The tracker treats
0-counted responses as "estimate it for me".
"""

from __future__ import annotations

from dataclasses import dataclass

from venomhook.llm.provider import LLMError, LLMRequest, LLMResponse


__all__ = [
    "BudgetExhausted",
    "TokenBudget",
    "estimate_tokens",
]


class BudgetExhausted(LLMError):
    """Raised by :meth:`TokenBudget.charge` when the cap is exceeded.

    Subclasses :class:`LLMError` so a single ``except LLMError`` clause
    catches both this and provider failures.
    """


def estimate_tokens(text: str) -> int:
    """char/4 rough token estimate. Fast, no SDK dep, good enough for budgeting.

    Returns at least 1 for any non-empty string so single-token prompts
    still consume from the budget.
    """
    if not text:
        return 0
    return max(1, len(text) // 4)


@dataclass
class TokenBudget:
    """Mutable budget tracker for one operator session.

    ``cap`` is the maximum total tokens (input + output). 0 disables the
    LLM layer entirely (every call is refused). Negative ``cap`` raises
    at construction time.

    Not thread-safe; callers serialize access. Phase 5 integration
    points are synchronous so this is fine.
    """

    cap: int
    spent: int = 0

    def __post_init__(self) -> None:
        if self.cap < 0:
            raise ValueError(f"token budget cap must be >= 0, got {self.cap}")

    @property
    def remaining(self) -> int:
        return max(0, self.cap - self.spent)

    @property
    def exhausted(self) -> bool:
        return self.spent >= self.cap

    def can_afford(self, estimated_tokens: int) -> bool:
        """Cheap pre-flight check. Returns False if the estimate doesn't fit.

        Use this to skip LLM calls *before* they happen so the pipeline
        can fall back to rule-based output without raising.
        """
        if self.cap == 0:
            return False
        if estimated_tokens < 0:
            return False
        return self.spent + estimated_tokens <= self.cap

    def can_afford_request(self, req: LLMRequest) -> bool:
        """Pre-flight against an :class:`LLMRequest`. Estimates from system+user
        plus the request's ``max_tokens`` cap on output.
        """
        est = (
            estimate_tokens(req.system)
            + estimate_tokens(req.user)
            + max(1, req.max_tokens)
        )
        return self.can_afford(est)

    def charge(self, response: LLMResponse) -> int:
        """Deduct the actual token cost of a completed call. Returns the
        running ``spent`` total. Raises :class:`BudgetExhausted` if this
        charge pushes the total over the cap.

        If the response carries ``input_tokens=output_tokens=0`` (provider
        couldn't report usage), the tracker estimates from the response
        text via :func:`estimate_tokens`.
        """
        used = response.input_tokens + response.output_tokens
        if used == 0:
            used = estimate_tokens(response.text)
        if used < 0:
            raise ValueError(f"negative token usage from response: {used}")

        new_total = self.spent + used
        if new_total > self.cap:
            raise BudgetExhausted(
                f"token budget exhausted: spent={self.spent}, "
                f"this_call={used}, cap={self.cap}"
            )
        self.spent = new_total
        return self.spent

    def reset(self) -> None:
        """Zero out ``spent``. ``cap`` is unchanged."""
        self.spent = 0

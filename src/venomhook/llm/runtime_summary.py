"""Runtime report summary — Phase 5 ④ (`--use-llm-report`).

Reads the structured summary produced by
:func:`venomhook.runtime_report.summarize_log_file` and asks the LLM
to write an "Analyst Summary" — a few sentences highlighting
interesting patterns the operator should notice (hot hooks, error
spikes, suspicious return values, etc.). The result is appended to
the markdown / HTML report.

Same contract shape as Units 5 / 6 / 7:
    * Pure additive — never overwrites the rule-based table or sample
      sections; produces a dedicated section appended at the end.
    * Opt-in, failure-tolerant. If the model declines (returns the
      ``SKIP`` sentinel) or the response is empty, no section is added.
    * Cache-aware via the shared LLMCache.
    * Bounded — we only feed the structured summary, not raw log
      lines, so the prompt size is independent of log volume.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Any, Optional

from venomhook.llm.budget import BudgetExhausted, TokenBudget
from venomhook.llm.cache import LLMCache
from venomhook.llm.provider import LLMError, LLMProvider, LLMRequest, LLMResponse


logger = logging.getLogger(__name__)


__all__ = [
    "RuntimeSummaryStats",
    "build_runtime_summary_request",
    "parse_runtime_summary_response",
    "summarize_runtime_log",
]


_MAX_HOOKS_IN_PROMPT = 30
_MAX_SAMPLES_PER_HOOK = 3
_MAX_SAMPLE_LEN = 80
_MAX_SUMMARY_LEN = 1500  # final post-clean cap on the markdown block


_SYSTEM_PROMPT = (
    "You are a security-research assistant writing a brief 'Analyst "
    "Summary' for a Frida runtime log. The user gives you structured "
    "stats (per-hook event counts, errors, hexdump count, sample args/"
    "rets/strings). You output a short paragraph for an analyst — what "
    "looks interesting, what looks normal, where they should look "
    "next.\n"
    "\n"
    "Rules:\n"
    "  - 5 lines max, plain markdown, no headers.\n"
    "  - Be grounded: only assert patterns the stats support. If a hook "
    "    has 0 events you cannot claim it ran.\n"
    "  - If the stats are too sparse (e.g. zero events total), output "
    "    exactly: SKIP\n"
    "  - Prefer concrete observations over generic security boilerplate."
)


@dataclass
class RuntimeSummaryStats:
    """One-shot stats for a runtime-summary call."""

    invoked: bool = False
    cached_hit: bool = False
    new_call: bool = False
    skipped_budget: bool = False
    skipped_unavailable: bool = False
    skipped_empty_log: bool = False
    skipped_model_declined: bool = False
    failed: bool = False

    def as_summary_line(self) -> str:
        return (
            f"llm-report: invoked={self.invoked} cached={self.cached_hit} "
            f"new_call={self.new_call} skipped_budget={self.skipped_budget} "
            f"skipped_unavailable={self.skipped_unavailable} "
            f"skipped_empty_log={self.skipped_empty_log} "
            f"skipped_model_declined={self.skipped_model_declined} "
            f"failed={self.failed}"
        )


def _trim_sample(s: str) -> str:
    if len(s) > _MAX_SAMPLE_LEN:
        return s[:_MAX_SAMPLE_LEN] + "…"
    return s


def _pack_summary_for_prompt(summary: dict[str, Any]) -> dict[str, Any]:
    """Reduce the structured summary to a prompt-safe slice.

    The full ``summary`` dict can carry arbitrarily many hooks if the
    log is large; we cap the per-hook fan-out so prompt size stays
    predictable. Hooks are kept in deterministic alpha order so the
    cache key is stable.
    """
    hooks = summary.get("hooks", {}) or {}
    errors = summary.get("errors", {}) or {}
    strings = summary.get("strings", {}) or {}
    enter_samples = summary.get("enter_samples", {}) or {}
    ret_samples = summary.get("ret_samples", {}) or {}

    sorted_hooks = sorted(hooks.keys())[:_MAX_HOOKS_IN_PROMPT]
    packed_hooks = {}
    for h in sorted_hooks:
        packed_hooks[h] = {
            "events": dict(hooks[h]) if isinstance(hooks[h], dict) else hooks[h],
            "errors": int(errors.get(h, 0)),
            "string_samples": [
                _trim_sample(str(x))
                for x in (strings.get(h, []) or [])[:_MAX_SAMPLES_PER_HOOK]
            ],
            "enter_samples": [
                _trim_sample(str(x))
                for x in (enter_samples.get(h, []) or [])[:_MAX_SAMPLES_PER_HOOK]
            ],
            "ret_samples": [
                _trim_sample(str(x))
                for x in (ret_samples.get(h, []) or [])[:_MAX_SAMPLES_PER_HOOK]
            ],
        }

    return {
        "total_events": int(summary.get("total_events", 0)),
        "hexdumps": int(summary.get("hexdumps", 0)),
        "hooks_with_errors": len(errors),
        "hooks": packed_hooks,
    }


def build_runtime_summary_request(
    summary: dict[str, Any],
    *,
    max_tokens: int = 384,
) -> LLMRequest:
    packed = _pack_summary_for_prompt(summary)
    user = json.dumps(packed, sort_keys=True, indent=2, ensure_ascii=False)
    return LLMRequest(
        system=_SYSTEM_PROMPT,
        user=user,
        max_tokens=max_tokens,
        temperature=0.0,
        metadata=(("role", "report"),),
    )


def parse_runtime_summary_response(text: str) -> Optional[str]:
    """Clean the model's raw output into a markdown-safe paragraph.

    Returns None when the response is empty, only whitespace, or starts
    with the ``SKIP`` sentinel. Otherwise the text is collapsed of
    excessive blank lines and capped at ``_MAX_SUMMARY_LEN``.
    """
    if not text:
        return None
    body = text.strip()
    if not body:
        return None
    if body.upper().startswith("SKIP"):
        return None

    # Collapse 3+ consecutive newlines to 2 (preserve paragraph breaks).
    body = re.sub(r"\n{3,}", "\n\n", body)
    # Strip surrounding code fences if the model wrapped its answer.
    body = re.sub(r"^```[a-zA-Z]*\n", "", body)
    body = re.sub(r"\n```$", "", body)
    body = body.strip()

    if len(body) > _MAX_SUMMARY_LEN:
        body = body[:_MAX_SUMMARY_LEN].rstrip() + "…"
    return body


def summarize_runtime_log(
    summary: dict[str, Any],
    *,
    provider: LLMProvider,
    budget: TokenBudget,
    cache: Optional[LLMCache] = None,
) -> tuple[Optional[str], RuntimeSummaryStats]:
    """Return (analyst_summary, stats). ``analyst_summary`` is None when
    no section should be appended (provider unavailable, budget empty,
    model declined, log empty, or call failed).

    The function never raises out — failure modes are reported through
    ``RuntimeSummaryStats`` flags so the caller can degrade silently.
    """
    stats = RuntimeSummaryStats()

    if int(summary.get("total_events", 0)) == 0:
        stats.skipped_empty_log = True
        return None, stats

    if not provider.is_available():
        stats.skipped_unavailable = True
        logger.info(
            "llm-report skipped: provider %r reports not available",
            provider.name,
        )
        return None, stats

    request = build_runtime_summary_request(summary)

    cached: Optional[LLMResponse] = None
    if cache is not None:
        cached = cache.get(provider.name, provider.model, request)

    if cached is not None:
        stats.invoked = True
        stats.cached_hit = True
        response = cached
    else:
        if not budget.can_afford_request(request):
            stats.skipped_budget = True
            return None, stats
        try:
            response = provider.complete(request)
        except LLMError as e:
            stats.failed = True
            logger.warning("llm-report failed: %s", e)
            return None, stats
        try:
            budget.charge(response)
        except BudgetExhausted as e:
            stats.skipped_budget = True
            stats.invoked = True
            stats.new_call = True
            logger.warning("llm-report budget overrun: %s", e)
            return None, stats
        stats.invoked = True
        stats.new_call = True
        if cache is not None:
            cache.put(request, response)

    cleaned = parse_runtime_summary_response(response.text)
    if cleaned is None:
        stats.skipped_model_declined = True
        return None, stats
    return cleaned, stats

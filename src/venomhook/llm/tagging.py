"""Semantic tagging — first Phase 5 LLM integration point (`--use-llm-tagging`).

Reads scored :class:`EndpointMeta` objects + their backing
:class:`FunctionMeta` and asks the LLM to produce extra *semantic*
tags that the rule-based scorer can't infer from imports/strings
alone — things like ``semantic:login-handler``, ``semantic:tls-pin``,
``semantic:device-fingerprint``.

Contract:
    * **In place** — endpoints are mutated by appending tags to
      ``EndpointMeta.tags`` (always prefixed ``semantic:``) and
      reasons to ``EndpointMeta.reason`` (always prefixed ``llm:``).
      No EndpointMeta is replaced or reordered, so downstream
      callers (`hookspec_builder`, `report`) see the same objects.
    * **Opt-in** — never invoked unless the caller explicitly
      passes a provider. The pipeline default is rule-only.
    * **Failure-tolerant** — provider errors, budget refusals,
      malformed responses all degrade silently to "no semantic
      tags added for this endpoint". The pipeline finishes; nothing
      raises out of this module on a per-endpoint LLM error.
    * **Cache-aware** — when a cache is supplied, each (provider,
      model, request) is looked up before paying for a new call,
      restoring determinism across re-runs.

The output format the LLM is asked to follow is intentionally simple
(one ``tag: reason`` line per row) so a small/cheap model can stay
reliable without JSON schema enforcement.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Optional

from venomhook.llm.budget import BudgetExhausted, TokenBudget
from venomhook.llm.cache import LLMCache
from venomhook.llm.provider import LLMError, LLMProvider, LLMRequest, LLMResponse
from venomhook.models import EndpointMeta, FunctionMeta


logger = logging.getLogger(__name__)


__all__ = [
    "TaggingStats",
    "build_tagging_request",
    "parse_tagging_response",
    "tag_endpoints",
]


# Hard cap on input we send the LLM per function. Strings tend to be the
# largest input; we truncate the list and clip per-string length so a
# pathological binary doesn't blow the budget. Numbers picked to fit a
# small Haiku-class context window comfortably.
_MAX_STRINGS = 25
_STRING_CLIP = 80
_MAX_IMPORTS = 30


_SYSTEM_PROMPT = (
    "You are a static-analysis assistant labeling native functions for a "
    "reverse-engineering pipeline. The user gives you metadata about one "
    "function (name, strings, imports, neighbor counts, existing rule-"
    "based tags). You output extra semantic tags that describe the "
    "function's *purpose* — things rule-based scoring would miss.\n"
    "\n"
    "Output format: one tag per line, lowercase kebab-case (must contain "
    "at least one '-'), followed by ': ' and a short justification (<=10 "
    "words). Tags must NOT duplicate the rule-based tags already supplied. "
    "If the metadata is too sparse to label confidently, output nothing.\n"
    "\n"
    "Examples of good tags: login-handler, token-refresh, tls-pin, "
    "device-fingerprint, license-check, root-detect, anti-debug, "
    "config-loader, telemetry-emit, decryption-routine.\n"
    "\n"
    "Output AT MOST 5 tags. No prose, no headers, no markdown — just the "
    "lines."
)


@dataclass
class TaggingStats:
    """Summary of one ``tag_endpoints`` invocation. Useful for CLI reporting."""

    total_endpoints: int = 0
    cached_hits: int = 0
    new_calls: int = 0
    skipped_budget: int = 0
    skipped_unavailable: int = 0
    failed: int = 0
    total_tags_added: int = 0

    def as_summary_line(self) -> str:
        return (
            f"llm-tagging: endpoints={self.total_endpoints} "
            f"cached={self.cached_hits} new_calls={self.new_calls} "
            f"skipped_budget={self.skipped_budget} "
            f"skipped_unavailable={self.skipped_unavailable} "
            f"failed={self.failed} tags_added={self.total_tags_added}"
        )


def _truncate_strings(strings: list[str]) -> list[str]:
    out = []
    for s in strings[:_MAX_STRINGS]:
        if len(s) > _STRING_CLIP:
            out.append(s[:_STRING_CLIP] + "…")
        else:
            out.append(s)
    return out


def build_tagging_request(
    endpoint: EndpointMeta,
    function: Optional[FunctionMeta],
    *,
    max_tokens: int = 256,
) -> LLMRequest:
    """Compose the :class:`LLMRequest` for one endpoint's semantic tagging.

    ``function`` may be ``None`` if the endpoint's RVA didn't match any
    FunctionMeta — in that case only the endpoint metadata is sent and
    the LLM will likely return nothing.
    """
    fn_name = function.name if function and function.name else "(unnamed)"
    imports = (function.imports if function else [])[:_MAX_IMPORTS]
    strings = _truncate_strings(function.strings if function else [])
    callers_n = len(function.callers) if function else 0
    callees_n = len(function.callees) if function else 0
    blocks = function.basic_blocks if function and function.basic_blocks else 0

    user_lines = [
        f"function: {fn_name}",
        f"module: {endpoint.module}",
        f"arch: {endpoint.arch}",
        f"rva: {hex(endpoint.rva)}",
        f"score: {endpoint.score}",
        f"basic_blocks: {blocks}",
        f"callers: {callers_n}",
        f"callees: {callees_n}",
        f"existing_tags: {', '.join(endpoint.tags) if endpoint.tags else '(none)'}",
    ]
    if imports:
        user_lines.append("imports:")
        user_lines.extend(f"  - {imp}" for imp in imports)
    if strings:
        user_lines.append("strings:")
        user_lines.extend(f"  - {s}" for s in strings)

    return LLMRequest(
        system=_SYSTEM_PROMPT,
        user="\n".join(user_lines),
        max_tokens=max_tokens,
        temperature=0.0,
        metadata=(("role", "tagging"),),
    )


# Require at least one '-' in the tag — keeps semantic tags like
# "login-handler"/"tls-pin" while rejecting echoed metadata keys like
# "module:", "arch:", "rva:" that happen to match a generic tag pattern.
_TAG_LINE = re.compile(r"^([a-z][a-z0-9]*-[a-z0-9-]{1,40})\s*:\s*(.+)$")


def parse_tagging_response(text: str, *, limit: int = 5) -> list[tuple[str, str]]:
    """Parse the strict ``tag: reason`` line format into ``(tag, reason)``.

    Tolerates blank lines, leading bullets/dashes, and surrounding
    whitespace. Lines that don't match the pattern are silently
    skipped — the LLM occasionally drops in an apologetic header
    ("Sorry, here are the tags:") that we don't want to surface as a
    bogus tag.
    """
    out: list[tuple[str, str]] = []
    for raw in text.splitlines():
        s = raw.strip().lstrip("-* ").strip()
        if not s:
            continue
        m = _TAG_LINE.match(s)
        if not m:
            continue
        tag = m.group(1).strip("-_")
        reason = m.group(2).strip()
        if not tag or not reason:
            continue
        out.append((tag, reason))
        if len(out) >= limit:
            break
    return out


def _index_functions_by_rva(functions: list[FunctionMeta]) -> dict[int, FunctionMeta]:
    return {fn.rva: fn for fn in functions if fn.rva is not None}


def _apply_tags(endpoint: EndpointMeta, parsed: list[tuple[str, str]]) -> int:
    """Append the parsed tag/reason pairs to the endpoint. Skips duplicates.

    Returns the count of tags actually added.
    """
    existing = set(endpoint.tags)
    added = 0
    for tag, reason in parsed:
        full = f"semantic:{tag}"
        if full in existing:
            continue
        endpoint.tags.append(full)
        endpoint.reason.append(f"llm: {tag} — {reason}")
        existing.add(full)
        added += 1
    return added


def tag_endpoints(
    endpoints: list[EndpointMeta],
    functions: list[FunctionMeta],
    *,
    provider: LLMProvider,
    budget: TokenBudget,
    cache: Optional[LLMCache] = None,
    max_tags_per_endpoint: int = 5,
) -> TaggingStats:
    """Annotate ``endpoints`` in place with ``semantic:*`` tags from an LLM.

    Returns a :class:`TaggingStats` describing what happened. Never
    raises on per-endpoint LLM failures — those are counted in the
    ``failed`` field so the pipeline can finish and the operator can
    audit the rate.
    """
    stats = TaggingStats(total_endpoints=len(endpoints))
    if not endpoints:
        return stats

    if not provider.is_available():
        stats.skipped_unavailable = len(endpoints)
        logger.info(
            "llm-tagging skipped: provider %r reports not available",
            provider.name,
        )
        return stats

    fn_by_rva = _index_functions_by_rva(functions)

    for idx, endpoint in enumerate(endpoints):
        function = fn_by_rva.get(endpoint.rva)
        request = build_tagging_request(endpoint, function)

        cached: Optional[LLMResponse] = None
        if cache is not None:
            cached = cache.get(provider.name, provider.model, request)

        if cached is not None:
            stats.cached_hits += 1
            response = cached
        else:
            if not budget.can_afford_request(request):
                stats.skipped_budget += 1
                continue
            try:
                response = provider.complete(request)
            except LLMError as e:
                stats.failed += 1
                logger.warning(
                    "llm-tagging failed for endpoint %s@%s: %s",
                    endpoint.module, hex(endpoint.rva), e,
                )
                continue
            try:
                budget.charge(response)
            except BudgetExhausted as e:
                stats.new_calls += 1
                stats.skipped_budget += len(endpoints) - idx
                logger.warning(
                    "llm-tagging budget overrun for endpoint %s@%s: %s",
                    endpoint.module, hex(endpoint.rva), e,
                )
                break
            stats.new_calls += 1
            if cache is not None:
                cache.put(request, response)

        added = _apply_tags(
            endpoint,
            parse_tagging_response(response.text, limit=max_tags_per_endpoint),
        )
        stats.total_tags_added += added

    return stats

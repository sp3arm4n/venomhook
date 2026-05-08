"""Signature self-recovery — Phase 5 ⑤ (`--use-llm-recovery`).

Asks the LLM to insert ``??`` wildcards into ``HookSpec.sig`` at byte
positions that are likely to vary across builds (immediates,
relocation targets, addresses pointing into .data/.rodata). The
result is a more resilient signature that still matches the same
function across patch revisions, at the cost of slightly more
expensive Memory.scan inside Frida.

Input to the model:
    * Original sig hex bytes (e.g. "48 89 5C 24 08 ...")
    * The function's raw_bytes (where available, longer view than sig)
    * Function name and imports (so the model can reason about which
      bytes are likely opcodes vs operands)

Strict output format:
    ``sig: 48 89 5C 24 ?? 57 48 83 EC 20 ?? ??``

Parser rules (defensive):
    * Tokens must be either 2-hex-digit or ``??``. Any other token
      rejects the response.
    * Length must equal the original sig (token-count parity). The
      model wildcarding bytes is fine; replacing whole bytes with
      different bytes would not be a "self-recovery" and is rejected.
    * Wildcard ratio cap: a sig that becomes >75% wildcards is
      rejected (it would match too much memory).

Same contract shape as Units 5/6/7/8:
    * Mutates HookSpec.sig in place when accepted.
    * Rule-first: only operates on specs that already have a sig.
      Specs without raw_bytes-derived sig are skipped.
    * Opt-in, failure-tolerant, cache-aware.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Optional

from venomhook.llm.budget import BudgetExhausted, TokenBudget
from venomhook.llm.cache import LLMCache
from venomhook.llm.provider import LLMError, LLMProvider, LLMRequest, LLMResponse
from venomhook.models import FunctionMeta, HookSpec


logger = logging.getLogger(__name__)


__all__ = [
    "SigRecoveryStats",
    "build_recovery_request",
    "parse_recovery_response",
    "recover_sigs",
]


_HEX_TOKEN = re.compile(r"^[0-9a-fA-F]{2}$")
_MAX_IMPORTS = 30
_MAX_WILDCARD_RATIO = 0.75


_SYSTEM_PROMPT = (
    "You are a static-analysis assistant hardening byte signatures for "
    "binary patching tools (Frida, etc.). The user gives you the "
    "function's current short signature, optionally a longer raw byte "
    "sample, and the function's name + imports. You output a signature "
    "of the SAME length where bytes likely to vary across builds "
    "(immediates, relocation targets, address-bearing operands) are "
    "replaced with '??'.\n"
    "\n"
    "Output format (strict, single line):\n"
    "  sig: <hex byte> <hex byte> ...\n"
    "\n"
    "Rules:\n"
    "  - Use ?? for wildcards, two-digit hex (e.g. 4C, 89) for fixed bytes.\n"
    "  - Do NOT change byte values. Only replace fixed bytes with ?? "
    "    where you have evidence they vary.\n"
    "  - Token count MUST equal the input. No insertions, no deletions.\n"
    "  - If you cannot improve the signature, output exactly: SKIP\n"
    "  - No prose, no markdown, no headers."
)


@dataclass
class SigRecoveryStats:
    """Counters for one ``recover_sigs`` invocation."""

    total_specs: int = 0
    eligible_specs: int = 0
    cached_hits: int = 0
    new_calls: int = 0
    skipped_budget: int = 0
    skipped_unavailable: int = 0
    skipped_no_sig: int = 0
    skipped_model_declined: int = 0
    skipped_invalid_response: int = 0
    failed: int = 0
    sigs_recovered: int = 0

    def as_summary_line(self) -> str:
        return (
            f"llm-recovery: specs={self.total_specs} "
            f"eligible={self.eligible_specs} "
            f"cached={self.cached_hits} new_calls={self.new_calls} "
            f"skipped_budget={self.skipped_budget} "
            f"skipped_unavailable={self.skipped_unavailable} "
            f"skipped_no_sig={self.skipped_no_sig} "
            f"skipped_model_declined={self.skipped_model_declined} "
            f"skipped_invalid_response={self.skipped_invalid_response} "
            f"failed={self.failed} recovered={self.sigs_recovered}"
        )


def build_recovery_request(
    spec: HookSpec,
    function: Optional[FunctionMeta],
    *,
    max_tokens: int = 256,
) -> LLMRequest:
    fn_name = function.name if function and function.name else (spec.name or "(unnamed)")
    imports = (function.imports if function else [])[:_MAX_IMPORTS]
    raw_bytes = function.raw_bytes if function else None

    user_lines = [
        f"function: {fn_name}",
        f"module: {spec.module}",
        f"arch: {spec.arch}",
        f"offset: {hex(spec.offset)}",
        f"current_sig: {spec.sig}",
    ]
    if raw_bytes:
        user_lines.append(f"raw_bytes: {raw_bytes}")
    if imports:
        user_lines.append("imports:")
        user_lines.extend(f"  - {imp}" for imp in imports)

    return LLMRequest(
        system=_SYSTEM_PROMPT,
        user="\n".join(user_lines),
        max_tokens=max_tokens,
        temperature=0.0,
        metadata=(("role", "recovery"),),
    )


_SIG_LINE = re.compile(r"^sig\s*:\s*(.+?)\s*$", re.IGNORECASE)


def _is_valid_token(tok: str) -> bool:
    return tok == "??" or bool(_HEX_TOKEN.match(tok))


def parse_recovery_response(text: str, *, original_sig: str) -> Optional[str]:
    """Validate the LLM's recovered sig.

    Returns the cleaned wildcard sig string (space-separated tokens) or
    ``None`` if the response is invalid for any reason. Validation:

    * Must contain a ``sig:`` line.
    * Must NOT be ``SKIP`` (returns None).
    * Token count must equal the original.
    * Every token must be 2-hex or ``??``.
    * Wildcard ratio must not exceed _MAX_WILDCARD_RATIO.
    * Non-wildcard tokens must match the original byte at that index
      (the LLM is *only* allowed to add ?? — it cannot rewrite bytes).
    """
    if not text:
        return None
    body = text.strip()
    if not body:
        return None
    if body.upper().startswith("SKIP"):
        return None

    # Find the first sig: line; ignore any chatter before it.
    sig_line: Optional[str] = None
    for raw in body.splitlines():
        line = raw.strip()
        if not line:
            continue
        m = _SIG_LINE.match(line)
        if m:
            sig_line = m.group(1).strip()
            break

    if sig_line is None:
        return None

    tokens = sig_line.split()
    orig_tokens = original_sig.split()
    if len(tokens) != len(orig_tokens):
        return None

    for tok in tokens:
        if not _is_valid_token(tok):
            return None

    wildcard_count = sum(1 for t in tokens if t == "??")
    if wildcard_count / len(tokens) > _MAX_WILDCARD_RATIO:
        return None

    # Non-wildcard tokens must match the original byte (case-insensitive).
    for orig, new in zip(orig_tokens, tokens):
        if new == "??":
            continue
        if new.upper() != orig.upper():
            return None

    return " ".join(t.upper() if t != "??" else t for t in tokens)


def _index_functions_by_rva(functions: list[FunctionMeta]) -> dict[int, FunctionMeta]:
    return {fn.rva: fn for fn in functions if fn.rva is not None}


def recover_sigs(
    specs: list[HookSpec],
    functions: list[FunctionMeta],
    *,
    provider: LLMProvider,
    budget: TokenBudget,
    cache: Optional[LLMCache] = None,
) -> SigRecoveryStats:
    """Replace HookSpec.sig with wildcard-augmented version where the LLM
    suggests one. Mutates ``specs`` in place.

    Specs without an existing sig are skipped (counted in
    ``skipped_no_sig``) — the LLM has nothing to recover from.
    """
    stats = SigRecoveryStats(total_specs=len(specs))
    if not specs:
        return stats

    eligible: list[HookSpec] = []
    for spec in specs:
        if not spec.sig:
            stats.skipped_no_sig += 1
            continue
        eligible.append(spec)
    stats.eligible_specs = len(eligible)
    if not eligible:
        return stats

    if not provider.is_available():
        stats.skipped_unavailable = len(eligible)
        logger.info(
            "llm-recovery skipped: provider %r reports not available",
            provider.name,
        )
        return stats

    fn_by_rva = _index_functions_by_rva(functions)

    for spec in eligible:
        function = fn_by_rva.get(spec.offset)
        request = build_recovery_request(spec, function)

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
                    "llm-recovery failed for %s@%s: %s",
                    spec.module, hex(spec.offset), e,
                )
                continue
            try:
                budget.charge(response)
            except BudgetExhausted:
                stats.skipped_budget += 1
                if cache is not None:
                    cache.put(request, response)
                stats.new_calls += 1
                _apply_recovery(spec, response.text, stats)
                continue
            stats.new_calls += 1
            if cache is not None:
                cache.put(request, response)

        _apply_recovery(spec, response.text, stats)

    return stats


def _apply_recovery(spec: HookSpec, text: str, stats: SigRecoveryStats) -> None:
    recovered = parse_recovery_response(text, original_sig=spec.sig or "")
    if recovered is None:
        # Distinguish "model declined" (SKIP / empty) from "model returned
        # something we rejected on validation" — both get a counter so the
        # operator can see which is happening.
        if "SKIP" in (text or "").upper() or not text.strip():
            stats.skipped_model_declined += 1
        else:
            stats.skipped_invalid_response += 1
        return
    if recovered == (spec.sig or "").strip():
        # No improvement (model returned the original); count as decline.
        stats.skipped_model_declined += 1
        return
    spec.sig = recovered
    stats.sigs_recovered += 1

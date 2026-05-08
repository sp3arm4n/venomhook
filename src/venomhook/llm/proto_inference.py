"""Proto inference — Phase 5 ② (`--use-llm-proto`).

Ask the LLM to fill ``HookSpec.proto`` (return type + arg types) for
specs whose rule-based proto is empty. The rule layer (`hookspec_builder`)
intentionally stops at signatures and tags; type recovery from a
stripped binary is exactly the kind of judgment call where a small/cheap
model adds value while staying cheap thanks to caching.

Same contract shape as :mod:`venomhook.llm.tagging`:
    * In-place mutation of HookSpec.proto, never replaces or reorders specs.
    * Opt-in — caller decides whether to invoke this module at all.
    * Failure-tolerant — provider/budget/parse errors degrade silently
      to "no proto inferred for this spec".
    * Cache-aware — same (provider, model, request_hash) cache layer.
    * Rule-first — never overwrites an already-populated HookProto. A
      proto is "populated" iff it has either a ret type or any arg.

Output format the LLM is asked to follow:

    ret: <type>
    arg0: <type>
    arg1: <type>

Types are short C-style strings ("int", "const char *", "void *",
"size_t", "JNIEnv *", "jobject"). The parser is lenient on spacing
and stops at the first malformed line (so a trailing comment doesn't
silently drop the rest).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Optional

from venomhook.llm.budget import BudgetExhausted, TokenBudget
from venomhook.llm.cache import LLMCache
from venomhook.llm.provider import LLMError, LLMProvider, LLMRequest, LLMResponse
from venomhook.models import FunctionMeta, HookProto, HookSpec


logger = logging.getLogger(__name__)


__all__ = [
    "ProtoInferenceStats",
    "build_proto_request",
    "infer_protos",
    "parse_proto_response",
]


_MAX_STRINGS = 25
_STRING_CLIP = 80
_MAX_IMPORTS = 30


_SYSTEM_PROMPT = (
    "You are a static-analysis assistant inferring C function signatures "
    "from reverse-engineering metadata. The user gives you a function's "
    "name, observed strings, imported symbols, and existing tags. You "
    "output a best-guess prototype.\n"
    "\n"
    "Output format (strict, one item per line):\n"
    "  ret: <type>\n"
    "  arg0: <type>\n"
    "  arg1: <type>\n"
    "  ...\n"
    "\n"
    "Types use short C-style names: int, void, void *, const char *, "
    "size_t, uint32_t, JNIEnv *, jobject, jstring, jbyteArray. If the "
    "function is JNI (name starts with Java_), the first two args are "
    "always 'JNIEnv *' and 'jobject' (or 'jclass' for static).\n"
    "\n"
    "If the metadata is too sparse to guess confidently, output only "
    "'ret: void' and stop. Do not invent argument types under uncertainty."
)


@dataclass
class ProtoInferenceStats:
    """Summary counters for one ``infer_protos`` invocation."""

    total_specs: int = 0
    eligible_specs: int = 0  # proto missing -> candidate for inference
    cached_hits: int = 0
    new_calls: int = 0
    skipped_budget: int = 0
    skipped_unavailable: int = 0
    failed: int = 0
    protos_filled: int = 0

    def as_summary_line(self) -> str:
        return (
            f"llm-proto: specs={self.total_specs} "
            f"eligible={self.eligible_specs} "
            f"cached={self.cached_hits} new_calls={self.new_calls} "
            f"skipped_budget={self.skipped_budget} "
            f"skipped_unavailable={self.skipped_unavailable} "
            f"failed={self.failed} filled={self.protos_filled}"
        )


def _proto_is_empty(proto: Optional[HookProto]) -> bool:
    """True iff the rule layer didn't populate any type information."""
    if proto is None:
        return True
    return proto.ret is None and not proto.args


def _truncate_strings(strings: list[str]) -> list[str]:
    out = []
    for s in strings[:_MAX_STRINGS]:
        if len(s) > _STRING_CLIP:
            out.append(s[:_STRING_CLIP] + "…")
        else:
            out.append(s)
    return out


def build_proto_request(
    spec: HookSpec,
    function: Optional[FunctionMeta],
    *,
    max_tokens: int = 256,
) -> LLMRequest:
    """Compose the :class:`LLMRequest` for one spec's proto inference."""
    fn_name = (
        function.name if function and function.name
        else (spec.name or "(unnamed)")
    )
    imports = (function.imports if function else [])[:_MAX_IMPORTS]
    strings = _truncate_strings(function.strings if function else [])
    callers_n = len(function.callers) if function else 0

    user_lines = [
        f"function: {fn_name}",
        f"module: {spec.module}",
        f"arch: {spec.arch}",
        f"offset: {hex(spec.offset)}",
        f"tags: {', '.join(spec.tags) if spec.tags else '(none)'}",
        f"callers: {callers_n}",
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
        metadata=(("role", "proto"),),
    )


_RET_LINE = re.compile(r"^ret\s*:\s*(.+?)\s*$", re.IGNORECASE)
_ARG_LINE = re.compile(r"^arg\s*(\d+)\s*:\s*(.+?)\s*$", re.IGNORECASE)
# Reject obviously bogus type strings — a type can't contain code-fence
# markers, leading punctuation, or markdown bullets after we strip.
_BAD_CHARS = re.compile(r"[`<>{}]")


def _is_plausible_type(t: str) -> bool:
    """Reject types with obvious markdown/explanatory residue."""
    if not t:
        return False
    if _BAD_CHARS.search(t):
        return False
    if len(t) > 80:
        return False
    return True


def parse_proto_response(text: str) -> Optional[HookProto]:
    """Parse the strict ``ret:``/``argN:`` line format into a HookProto.

    Returns ``None`` if no ``ret:`` line was found at all (we treat
    that as "model declined to answer"). Args are returned in the
    order their indices appear; out-of-order indices are accepted but
    duplicates take the first occurrence.
    """
    ret: Optional[str] = None
    args_by_idx: dict[int, str] = {}

    for raw in text.splitlines():
        line = raw.strip().lstrip("-* ").strip()
        if not line:
            continue

        m_ret = _RET_LINE.match(line)
        if m_ret and ret is None:
            candidate = m_ret.group(1).strip()
            if _is_plausible_type(candidate):
                ret = candidate
            continue

        m_arg = _ARG_LINE.match(line)
        if m_arg:
            idx = int(m_arg.group(1))
            t = m_arg.group(2).strip()
            if _is_plausible_type(t) and idx not in args_by_idx:
                args_by_idx[idx] = t
            continue
        # Unrecognized line — keep scanning; the LLM occasionally drops
        # an apologetic header before the structured output.

    if ret is None:
        return None

    args = [args_by_idx[i] for i in sorted(args_by_idx)]
    return HookProto(ret=ret, args=args)


def _index_functions_by_rva(functions: list[FunctionMeta]) -> dict[int, FunctionMeta]:
    return {fn.rva: fn for fn in functions if fn.rva is not None}


def infer_protos(
    specs: list[HookSpec],
    functions: list[FunctionMeta],
    *,
    provider: LLMProvider,
    budget: TokenBudget,
    cache: Optional[LLMCache] = None,
) -> ProtoInferenceStats:
    """Fill empty ``HookSpec.proto`` slots via LLM inference.

    Mutates ``specs`` in place. Specs whose proto already carries a
    ret type or any arg are left untouched (rule-based wins). Returns
    a :class:`ProtoInferenceStats` describing what happened.
    """
    stats = ProtoInferenceStats(total_specs=len(specs))
    if not specs:
        return stats

    eligible = [s for s in specs if _proto_is_empty(s.proto)]
    stats.eligible_specs = len(eligible)
    if not eligible:
        return stats

    if not provider.is_available():
        stats.skipped_unavailable = len(eligible)
        logger.info(
            "llm-proto skipped: provider %r reports not available",
            provider.name,
        )
        return stats

    fn_by_rva = _index_functions_by_rva(functions)

    for spec in eligible:
        function = fn_by_rva.get(spec.offset)
        request = build_proto_request(spec, function)

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
                    "llm-proto failed for %s@%s: %s",
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
                # Apply this one response, then stop accepting new ones.
                proto = parse_proto_response(response.text)
                if proto is not None:
                    spec.proto = proto
                    stats.protos_filled += 1
                continue
            stats.new_calls += 1
            if cache is not None:
                cache.put(request, response)

        proto = parse_proto_response(response.text)
        if proto is not None:
            spec.proto = proto
            stats.protos_filled += 1

    return stats

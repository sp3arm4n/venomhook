"""Java↔Native flow description — Phase 5 ③ (`--use-llm-flow`).

Produces a one-sentence natural-language description of what a JNI
function does, populating ``HookSpec.description``. The intent is
analyst-readable context that survives in the report alongside
rule-based tags and proto:

    [JNI] Java_com_example_AuthClient_login
        proto: jstring (JNIEnv *, jobject, jstring username, jstring password)
        description: "Validates the supplied credentials and returns a session
                      token; calls native HMAC + HTTPS POST."

Inputs accepted:

    * Required: HookSpec list + FunctionMeta list (rva-keyed).
    * Optional: list[JniBridge]. When supplied, each bridge contributes
      precise Java metadata (class FQN, declared method, return/arg
      types) to the LLM prompt, indexed by ``matched_symbol``. When
      absent, we fall back to demangling the JNI symbol name (good
      enough for descriptive purposes — the LLM only needs the class/
      method label, not a full Java signature).

Same contract shape as Units 5 / 6:
    * Mutates HookSpec.description in place; rule-first (skips specs
      with description already set).
    * Opt-in, failure-tolerant, cache-aware.
    * Only operates on JNI symbols (name starts with ``Java_``); pure
      C exports are skipped because the prompt's premise — there *is*
      a Java caller — wouldn't apply.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Optional

from venomhook.llm.budget import BudgetExhausted, TokenBudget
from venomhook.llm.cache import LLMCache
from venomhook.llm.provider import LLMError, LLMProvider, LLMRequest, LLMResponse
from venomhook.models import FunctionMeta, HookSpec, JavaNativeMethod, JniBridge


logger = logging.getLogger(__name__)


__all__ = [
    "FlowDescriptionStats",
    "build_flow_request",
    "describe_flows",
    "parse_flow_response",
]


_MAX_STRINGS = 25
_STRING_CLIP = 80
_MAX_IMPORTS = 30
_MAX_DESCRIPTION_LEN = 280  # post-clean cap on description length


_SYSTEM_PROMPT = (
    "You are a static-analysis assistant summarizing JNI functions for "
    "an analyst's report. The user gives you the Java caller's class "
    "and method, the native function's strings/imports, and any "
    "available rule-based tags. You output a single sentence (<=40 "
    "words) describing what the Java↔native flow does in plain terms.\n"
    "\n"
    "Rules:\n"
    "  - Output ONLY the sentence. No prefixes, no markdown, no quotes.\n"
    "  - Stay grounded: only assert behaviors the metadata supports.\n"
    "  - If the metadata is too sparse, output exactly: SKIP\n"
    "  - Avoid speculation about specific algorithms unless an obvious "
    "    string or import names them (e.g. AES_encrypt -> 'AES encryption').\n"
)


@dataclass
class FlowDescriptionStats:
    """Counters for one ``describe_flows`` invocation."""

    total_specs: int = 0
    eligible_specs: int = 0  # JNI-named, description not yet set
    cached_hits: int = 0
    new_calls: int = 0
    skipped_budget: int = 0
    skipped_unavailable: int = 0
    skipped_non_jni: int = 0
    skipped_already_described: int = 0
    skipped_model_declined: int = 0
    failed: int = 0
    descriptions_filled: int = 0

    def as_summary_line(self) -> str:
        return (
            f"llm-flow: specs={self.total_specs} "
            f"eligible={self.eligible_specs} "
            f"cached={self.cached_hits} new_calls={self.new_calls} "
            f"skipped_budget={self.skipped_budget} "
            f"skipped_unavailable={self.skipped_unavailable} "
            f"skipped_non_jni={self.skipped_non_jni} "
            f"skipped_already_described={self.skipped_already_described} "
            f"skipped_model_declined={self.skipped_model_declined} "
            f"failed={self.failed} filled={self.descriptions_filled}"
        )


_JNI_SYMBOL = re.compile(r"^Java_([A-Za-z0-9_]+)$")


def _is_jni_symbol(name: Optional[str]) -> bool:
    return bool(name) and bool(_JNI_SYMBOL.match(name))


def _demangle_jni_symbol(symbol: str) -> Optional[tuple[str, str]]:
    """Best-effort split of ``Java_<class>_<method>`` -> (class_dotted, method).

    JNI mangling escapes underscores in class/method names (``_1`` for
    ``_``, ``_0XXXX`` for unicode), but for pure descriptive purposes
    the unescaped split is good enough — we just want a class label
    the LLM can read. Returns None if the pattern doesn't match.
    """
    m = _JNI_SYMBOL.match(symbol)
    if not m:
        return None
    body = m.group(1)
    # Last '_' separates class from method (unless mangled, but again,
    # we only need a readable label). e.g. "com_example_Foo_bar" ->
    # ("com.example.Foo", "bar").
    if "_" not in body:
        return ("(unknown)", body)
    class_part, _, method = body.rpartition("_")
    class_dotted = class_part.replace("_", ".")
    return (class_dotted, method)


def _truncate_strings(strings: list[str]) -> list[str]:
    out = []
    for s in strings[:_MAX_STRINGS]:
        if len(s) > _STRING_CLIP:
            out.append(s[:_STRING_CLIP] + "…")
        else:
            out.append(s)
    return out


def _index_bridges_by_symbol(bridges: list[JniBridge]) -> dict[str, JniBridge]:
    """Index matched bridges by their resolved native symbol."""
    return {b.matched_symbol: b for b in bridges if b.matched_symbol}


def _java_signature_line(jm: JavaNativeMethod) -> str:
    args = ", ".join(jm.arg_types) if jm.arg_types else ""
    return f"{jm.return_type} {jm.class_fqn}.{jm.method_name}({args})"


def build_flow_request(
    spec: HookSpec,
    function: Optional[FunctionMeta],
    bridge: Optional[JniBridge] = None,
    *,
    max_tokens: int = 256,
) -> LLMRequest:
    """Compose the LLM request for one JNI spec's flow description.

    ``bridge`` is preferred when provided. When None, falls back to
    demangling the spec's JNI symbol name.
    """
    user_lines = [
        f"native_symbol: {spec.name}",
        f"module: {spec.module}",
        f"arch: {spec.arch}",
        f"offset: {hex(spec.offset)}",
        f"tags: {', '.join(spec.tags) if spec.tags else '(none)'}",
    ]

    if bridge is not None:
        user_lines.append(f"java_signature: {_java_signature_line(bridge.java_method)}")
        user_lines.append(f"is_static: {bridge.java_method.is_static}")
    else:
        demangled = _demangle_jni_symbol(spec.name or "")
        if demangled is not None:
            class_, method = demangled
            user_lines.append(f"java_class_guess: {class_}")
            user_lines.append(f"java_method_guess: {method}")

    imports = (function.imports if function else [])[:_MAX_IMPORTS]
    strings = _truncate_strings(function.strings if function else [])
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
        metadata=(("role", "flow"),),
    )


def parse_flow_response(text: str) -> Optional[str]:
    """Return the cleaned description sentence, or ``None`` on SKIP / empty.

    The model is instructed to output a single line. We strip leading
    bullets/quotes, collapse whitespace, drop a trailing period if
    multiple, and cap at ``_MAX_DESCRIPTION_LEN`` to bound report
    storage. If the cleaned content is empty or starts with the
    sentinel ``SKIP``, we return None so the caller leaves the
    description unset.
    """
    if not text:
        return None
    # Take the first non-empty line so a noisy model that adds a
    # trailing rationale doesn't pollute the description.
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if not lines:
        return None
    body = lines[0]

    # Strip leading bullet/quote/dash artifacts.
    body = body.lstrip("-*•> ").strip()
    body = body.strip("\"'`")

    if not body or body.upper().startswith("SKIP"):
        return None

    # Collapse repeated internal whitespace.
    body = re.sub(r"\s+", " ", body)
    if len(body) > _MAX_DESCRIPTION_LEN:
        body = body[:_MAX_DESCRIPTION_LEN].rstrip() + "…"
    return body


def describe_flows(
    specs: list[HookSpec],
    functions: list[FunctionMeta],
    *,
    provider: LLMProvider,
    budget: TokenBudget,
    cache: Optional[LLMCache] = None,
    bridges: Optional[list[JniBridge]] = None,
) -> FlowDescriptionStats:
    """Fill ``HookSpec.description`` for JNI-named specs that don't have one.

    Mutates ``specs`` in place. When ``bridges`` is supplied, matched
    bridges enrich the prompt with precise Java metadata; otherwise
    the JNI symbol name is demangled for class/method labels.
    """
    stats = FlowDescriptionStats(total_specs=len(specs))
    if not specs:
        return stats

    bridge_by_symbol = _index_bridges_by_symbol(bridges or [])
    fn_by_rva = {fn.rva: fn for fn in functions if fn.rva is not None}

    eligible: list[HookSpec] = []
    for spec in specs:
        if spec.description is not None:
            stats.skipped_already_described += 1
            continue
        if not _is_jni_symbol(spec.name):
            stats.skipped_non_jni += 1
            continue
        eligible.append(spec)
    stats.eligible_specs = len(eligible)
    if not eligible:
        return stats

    if not provider.is_available():
        stats.skipped_unavailable = len(eligible)
        logger.info(
            "llm-flow skipped: provider %r reports not available",
            provider.name,
        )
        return stats

    for idx, spec in enumerate(eligible):
        function = fn_by_rva.get(spec.offset)
        bridge = bridge_by_symbol.get(spec.name or "")
        request = build_flow_request(spec, function, bridge)

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
                    "llm-flow failed for %s@%s: %s",
                    spec.module, hex(spec.offset), e,
                )
                continue
            try:
                budget.charge(response)
            except BudgetExhausted as e:
                stats.new_calls += 1
                stats.skipped_budget += len(eligible) - idx
                logger.warning(
                    "llm-flow budget overrun for %s@%s: %s",
                    spec.module, hex(spec.offset), e,
                )
                break
            stats.new_calls += 1
            if cache is not None:
                cache.put(request, response)

        desc = parse_flow_response(response.text)
        if desc is not None:
            spec.description = desc
            stats.descriptions_filled += 1
        else:
            stats.skipped_model_declined += 1

    return stats

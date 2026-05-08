"""Opt-in LLM layer for VenomHook (Phase 5).

Re-exports the public surface of the provider/cache/budget modules. Importing
this package never triggers a network call — every backend uses lazy imports
for SDKs, and ``EchoProvider`` is the only built-in that runs without any
optional dependency.

The pipeline only touches this package when one of the ``--use-llm-*`` flags
is set. Without those flags VenomHook stays 100% deterministic, matching the
"automation core + opt-in LLM" direction (see project memory direction B).
"""

from __future__ import annotations

from venomhook.llm.budget import BudgetExhausted, TokenBudget, estimate_tokens
from venomhook.llm.cache import (
    CachedLLMEntry,
    LLMCache,
    SCHEMA_VERSION,
)
from venomhook.llm.provider import (
    EchoProvider,
    LLMError,
    LLMProvider,
    LLMRequest,
    LLMResponse,
    get_provider,
    list_providers,
)

__all__ = [
    "BudgetExhausted",
    "CachedLLMEntry",
    "EchoProvider",
    "LLMCache",
    "LLMError",
    "LLMProvider",
    "LLMRequest",
    "LLMResponse",
    "SCHEMA_VERSION",
    "TokenBudget",
    "estimate_tokens",
    "get_provider",
    "list_providers",
]

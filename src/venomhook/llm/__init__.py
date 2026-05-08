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
    AnthropicProvider,
    EchoProvider,
    LLMError,
    LLMProvider,
    LLMRequest,
    LLMResponse,
    get_provider,
    list_providers,
)
from venomhook.llm.flow_description import (
    FlowDescriptionStats,
    build_flow_request,
    describe_flows,
    parse_flow_response,
)
from venomhook.llm.proto_inference import (
    ProtoInferenceStats,
    build_proto_request,
    infer_protos,
    parse_proto_response,
)
from venomhook.llm.runtime_summary import (
    RuntimeSummaryStats,
    build_runtime_summary_request,
    parse_runtime_summary_response,
    summarize_runtime_log,
)
from venomhook.llm.tagging import (
    TaggingStats,
    build_tagging_request,
    parse_tagging_response,
    tag_endpoints,
)

__all__ = [
    "AnthropicProvider",
    "BudgetExhausted",
    "CachedLLMEntry",
    "EchoProvider",
    "FlowDescriptionStats",
    "LLMCache",
    "LLMError",
    "LLMProvider",
    "LLMRequest",
    "LLMResponse",
    "ProtoInferenceStats",
    "RuntimeSummaryStats",
    "SCHEMA_VERSION",
    "TaggingStats",
    "TokenBudget",
    "build_flow_request",
    "build_proto_request",
    "build_runtime_summary_request",
    "build_tagging_request",
    "describe_flows",
    "estimate_tokens",
    "get_provider",
    "infer_protos",
    "list_providers",
    "parse_flow_response",
    "parse_proto_response",
    "parse_runtime_summary_response",
    "parse_tagging_response",
    "summarize_runtime_log",
    "tag_endpoints",
]

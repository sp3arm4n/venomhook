from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from venomhook.ghidra_runner import GhidraRunner
from venomhook.hookspec_builder import build_hookspecs
from venomhook.models import HookSpec, StaticMeta
from venomhook.scoring import ScoreConfig, score_endpoints
from venomhook.store import HookSpecStore, StaticMetaStore
from venomhook.report import write_markdown

logger = logging.getLogger(__name__)


@dataclass
class LLMTaggingOptions:
    """Opt-in configuration for the Phase 5 ``--use-llm-tagging`` integration.

    Wiring is intentionally narrow: the pipeline only checks whether
    ``provider`` is set. When None, the pipeline runs identically to
    pre-Phase-5 builds (no LLM calls, no API key needed).
    """

    provider: object  # venomhook.llm.LLMProvider — typed loosely to keep this module lazy
    budget: object    # venomhook.llm.TokenBudget
    cache: object | None = None  # venomhook.llm.LLMCache or None


@dataclass
class LLMProtoOptions:
    """Opt-in configuration for the Phase 5 ``--use-llm-proto`` integration."""

    provider: object
    budget: object
    cache: object | None = None


@dataclass
class LLMFlowOptions:
    """Opt-in configuration for the Phase 5 ``--use-llm-flow`` integration.

    ``bridges`` (a list of JniBridge) is optional. When supplied it makes
    the flow description prompt precise (Java class FQN + declared method
    signature). When None, the module falls back to demangling the JNI
    symbol name in HookSpec.name.
    """

    provider: object
    budget: object
    cache: object | None = None
    bridges: object | None = None


@dataclass
class LLMRecoveryOptions:
    """Opt-in configuration for the Phase 5 ``--use-llm-recovery`` integration."""

    provider: object
    budget: object
    cache: object | None = None


class StaticPipeline:
    def __init__(
        self,
        top_n: int = 10,
        score_config: ScoreConfig | None = None,
        sig_max_bytes: int = 12,
        ghidra_runner: GhidraRunner | None = None,
        llm_tagging: LLMTaggingOptions | None = None,
        llm_proto: LLMProtoOptions | None = None,
        llm_flow: LLMFlowOptions | None = None,
        llm_recovery: LLMRecoveryOptions | None = None,
    ):
        self.top_n = top_n
        self.score_config = score_config or ScoreConfig()
        self.sig_max_bytes = sig_max_bytes
        self.ghidra_runner = ghidra_runner
        self.llm_tagging = llm_tagging
        self.llm_proto = llm_proto
        self.llm_flow = llm_flow
        self.llm_recovery = llm_recovery

    def run_from_static_meta(
        self, static_meta_path: Path, out_hookspec: Path, report_md: Path | None = None
    ) -> list[HookSpec]:
        logger.info("loading StaticMeta from %s", static_meta_path)
        meta: StaticMeta = StaticMetaStore.load(static_meta_path)
        endpoints = score_endpoints(meta, top_n=self.top_n, config=self.score_config)
        logger.info("scored %d endpoints (top %d)", len(endpoints), self.top_n)
        if self.llm_tagging is not None:
            # Lazy import: venomhook.llm.tagging pulls in the LLM stack which
            # we want to keep out of the import path of users not using it.
            from venomhook.llm.tagging import tag_endpoints
            stats = tag_endpoints(
                endpoints,
                meta.functions,
                provider=self.llm_tagging.provider,  # type: ignore[arg-type]
                budget=self.llm_tagging.budget,  # type: ignore[arg-type]
                cache=self.llm_tagging.cache,  # type: ignore[arg-type]
            )
            logger.info(stats.as_summary_line())
        hookspecs = build_hookspecs(endpoints, functions=meta.functions, sig_max_bytes=self.sig_max_bytes)
        if self.llm_proto is not None:
            from venomhook.llm.proto_inference import infer_protos
            proto_stats = infer_protos(
                hookspecs,
                meta.functions,
                provider=self.llm_proto.provider,  # type: ignore[arg-type]
                budget=self.llm_proto.budget,  # type: ignore[arg-type]
                cache=self.llm_proto.cache,  # type: ignore[arg-type]
            )
            logger.info(proto_stats.as_summary_line())
        if self.llm_flow is not None:
            from venomhook.llm.flow_description import describe_flows
            flow_stats = describe_flows(
                hookspecs,
                meta.functions,
                provider=self.llm_flow.provider,  # type: ignore[arg-type]
                budget=self.llm_flow.budget,  # type: ignore[arg-type]
                cache=self.llm_flow.cache,  # type: ignore[arg-type]
                bridges=self.llm_flow.bridges,  # type: ignore[arg-type]
            )
            logger.info(flow_stats.as_summary_line())
        if self.llm_recovery is not None:
            from venomhook.llm.sig_recovery import recover_sigs
            recovery_stats = recover_sigs(
                hookspecs,
                meta.functions,
                provider=self.llm_recovery.provider,  # type: ignore[arg-type]
                budget=self.llm_recovery.budget,  # type: ignore[arg-type]
                cache=self.llm_recovery.cache,  # type: ignore[arg-type]
            )
            logger.info(recovery_stats.as_summary_line())
        HookSpecStore.save(out_hookspec, hookspecs)
        logger.info("wrote HookSpec to %s", out_hookspec)
        if report_md:
            write_markdown(hookspecs, report_md)
            logger.info("wrote HookSpec markdown report to %s", report_md)
        return hookspecs

    def run_from_binary(
        self,
        binary_path: Path,
        out_static_meta: Path,
        out_hookspec: Path,
        report_md: Path | None = None,
        ghidra_runner: GhidraRunner | None = None,
    ) -> list[HookSpec]:
        runner = ghidra_runner or self.ghidra_runner
        if runner is None:
            raise RuntimeError("GhidraRunner is not configured; provide ghidra options.")
        runner.run(binary_path=binary_path, out_static_meta=out_static_meta)
        return self.run_from_static_meta(out_static_meta, out_hookspec, report_md=report_md)

    def run(
        self,
        *,
        static_meta: Optional[Path],
        binary: Optional[Path],
        out: Path,
        report_md: Path | None = None,
        ghidra_runner: GhidraRunner | None = None,
    ) -> list[HookSpec]:
        if static_meta:
            return self.run_from_static_meta(static_meta, out, report_md=report_md)
        if binary:
            return self.run_from_binary(
                binary,
                out_static_meta=out.with_suffix(".static.json"),
                out_hookspec=out,
                report_md=report_md,
                ghidra_runner=ghidra_runner,
            )
        raise ValueError("Either static_meta or binary must be provided.")

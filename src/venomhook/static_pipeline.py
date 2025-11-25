from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from venomhook.ghidra_runner import GhidraRunner
from venomhook.hookspec_builder import build_hookspecs
from venomhook.models import HookSpec, StaticMeta
from venomhook.scoring import ScoreConfig, score_endpoints
from venomhook.store import HookSpecStore, StaticMetaStore
from venomhook.report import write_markdown

logger = logging.getLogger(__name__)


class StaticPipeline:
    def __init__(
        self,
        top_n: int = 10,
        score_config: ScoreConfig | None = None,
        sig_max_bytes: int = 12,
        ghidra_runner: GhidraRunner | None = None,
    ):
        self.top_n = top_n
        self.score_config = score_config or ScoreConfig()
        self.sig_max_bytes = sig_max_bytes
        self.ghidra_runner = ghidra_runner

    def run_from_static_meta(
        self, static_meta_path: Path, out_hookspec: Path, report_md: Path | None = None
    ) -> list[HookSpec]:
        logger.info("loading StaticMeta from %s", static_meta_path)
        meta: StaticMeta = StaticMetaStore.load(static_meta_path)
        endpoints = score_endpoints(meta, top_n=self.top_n, config=self.score_config)
        logger.info("scored %d endpoints (top %d)", len(endpoints), self.top_n)
        hookspecs = build_hookspecs(endpoints, functions=meta.functions, sig_max_bytes=self.sig_max_bytes)
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

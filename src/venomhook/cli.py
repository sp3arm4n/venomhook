from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from venomhook import __version__
from venomhook.analysis_cache import SCHEMA_VERSION, AnalysisCache
from venomhook.analysis_diff import diff_analyses, format_diff_text
from venomhook.android_pipeline import AndroidPipelineError, analyze_apk
from venomhook.apk_decoder import ApktoolConfig
from venomhook.apk_extractor import (
    ApkExtractError,
    extract_apk_meta,
    extract_native_lib,
    select_abi,
)
from venomhook.dynamic_pipeline import DynamicPipeline
from venomhook.ghidra_runner import GhidraRunner
from venomhook.jadx_runner import JadxConfig
from venomhook.manifest_audit import (
    SEV_CRITICAL,
    SEV_HIGH,
    SEV_INFO,
    SEV_LOW,
    SEV_MEDIUM,
    audit_manifest,
    format_audit_summary,
)
from venomhook.orchestrator import run_frida
from venomhook.poc_export import export_pocs
from venomhook.poc_generator import format_pocs_text, generate_pocs
from venomhook.scoring import ScoreConfig
from venomhook.static_pipeline import StaticPipeline
from venomhook.runtime_report import summarize_log_file, write_markdown_summary, write_html_summary
from venomhook.store import HookSpecStore
from venomhook.config import load_profile

LOG_FORMAT = "%(levelname)s %(message)s"


STATIC_DEFAULTS = {
    "sig_max_bytes": 12,
    "score_network": 30,
    "score_file": 20,
    "score_auth": 15,
    "score_url": 10,
    "score_crypto": 10,
    "score_jni": 30,
    "score_callers_per": 2,
    "score_callers_cap": 10,
    "score_callees_per": 1,
    "score_callees_cap": 5,
    "score_bb_bonus": 5,
    "score_bb_threshold": 10,
}


DYNAMIC_DEFAULTS = {
    "hexdump_len": 64,
    "string_arg": None,
    "string_ret": False,
    "string_len": 128,
    "scan_size": None,
    "retry_attach": 1,
}


_LLM_FEATURE_FLAGS = {
    "tagging": (
        "--use-llm-tagging",
        "Phase 5 ① — call LLM to add semantic:* tags on top of rule-based scoring",
    ),
    "proto": (
        "--use-llm-proto",
        "Phase 5 ② — call LLM to fill HookSpec.proto (ret + arg types) "
        "for specs the rule layer left empty",
    ),
    "flow": (
        "--use-llm-flow",
        "Phase 5 ③ — call LLM to write a one-sentence Java↔Native "
        "description into HookSpec.description (JNI-named specs only)",
    ),
    "report": (
        "--use-llm-report",
        "Phase 5 ④ — call LLM to append an 'Analyst Summary' to the runtime report",
    ),
    "recovery": (
        "--use-llm-recovery",
        "Phase 5 ⑤ — call LLM to insert wildcards (??) into HookSpec.sig "
        "at byte positions likely to vary across builds",
    ),
}


def _add_llm_flags(
    parser: argparse.ArgumentParser,
    *,
    features: tuple[str, ...],
) -> None:
    """Attach only the LLM feature flags that affect this subcommand."""
    for feature in features:
        try:
            flag, help_text = _LLM_FEATURE_FLAGS[feature]
        except KeyError as exc:
            raise ValueError(f"unknown LLM feature: {feature}") from exc
        parser.add_argument(flag, action="store_true", help=help_text)
    parser.add_argument(
        "--llm-provider",
        type=str,
        default="anthropic",
        help="LLM provider name (default: anthropic). Use 'echo' for offline tests.",
    )
    parser.add_argument(
        "--llm-model",
        type=str,
        help="Override the provider's default model (e.g., claude-haiku-4-5-20251001)",
    )
    parser.add_argument(
        "--llm-token-budget",
        type=int,
        default=20000,
        help="Hard cap on total input+output tokens per run (default: 20000)",
    )
    parser.add_argument(
        "--llm-cache-dir",
        type=Path,
        help="Directory for the LLM response cache (default: ~/.venomhook/llm_cache.sqlite3)",
    )
    parser.add_argument(
        "--no-llm-cache",
        action="store_true",
        help="Disable the LLM response cache for this run",
    )


def _build_llm_runtime(args: argparse.Namespace):
    """Construct (provider, budget, cache) once per run, shared by every
    Phase 5 integration point. Returns None when no ``--use-llm-*`` flag
    is set so the pipeline stays import-clean.

    Sharing is deliberate: a single budget cap applies across tagging +
    proto + future flow/report/recovery, and a single cache file lets
    every integration point benefit from any other point's hits on the
    same prompt (in practice they don't collide because metadata role
    tags differ, but the cache layer remains consistent).
    """
    enabled_flags = [
        getattr(args, "use_llm_tagging", False),
        getattr(args, "use_llm_proto", False),
        getattr(args, "use_llm_flow", False),
        getattr(args, "use_llm_report", False),
        getattr(args, "use_llm_recovery", False),
    ]
    if not any(enabled_flags):
        return None

    from venomhook.llm.budget import TokenBudget
    from venomhook.llm.cache import LLMCache
    from venomhook.llm.provider import get_provider

    provider = get_provider(args.llm_provider, model=args.llm_model)
    budget = TokenBudget(cap=args.llm_token_budget)

    cache = None
    if not getattr(args, "no_llm_cache", False):
        cache_path = args.llm_cache_dir
        if cache_path is None:
            cache_path = Path.home() / ".venomhook" / "llm_cache.sqlite3"
        elif cache_path.is_dir() or not cache_path.suffix:
            cache_path = Path(cache_path) / "llm_cache.sqlite3"
        cache = LLMCache(cache_path)

    return provider, budget, cache


def _build_llm_options(args: argparse.Namespace):
    """Build the per-integration-point Options dataclasses once, sharing a
    single (provider, budget, cache) so the budget cap and cache are
    enforced across *all* enabled Phase 5 points rather than per-point.

    Returns ``(tagging_options, proto_options, flow_options, recovery_options)`` tuple.
    Each element is None when the corresponding ``--use-llm-*`` flag
    wasn't set.
    """
    static_enabled_flags = [
        getattr(args, "use_llm_tagging", False),
        getattr(args, "use_llm_proto", False),
        getattr(args, "use_llm_flow", False),
        getattr(args, "use_llm_recovery", False),
    ]
    if not any(static_enabled_flags):
        return None, None, None, None

    runtime = _build_llm_runtime(args)
    if runtime is None:
        return None, None, None, None
    provider, budget, cache = runtime

    tagging_options = None
    if getattr(args, "use_llm_tagging", False):
        from venomhook.static_pipeline import LLMTaggingOptions
        tagging_options = LLMTaggingOptions(
            provider=provider, budget=budget, cache=cache
        )

    proto_options = None
    if getattr(args, "use_llm_proto", False):
        from venomhook.static_pipeline import LLMProtoOptions
        proto_options = LLMProtoOptions(
            provider=provider, budget=budget, cache=cache
        )

    flow_options = None
    if getattr(args, "use_llm_flow", False):
        from venomhook.static_pipeline import LLMFlowOptions
        # bridges=None: the offset-static path doesn't currently feed JNI
        # bridges into the static pipeline. The flow module falls back to
        # demangling Java_<class>_<method> from the symbol name, which
        # gives the LLM a usable class/method label without bridges.
        flow_options = LLMFlowOptions(
            provider=provider, budget=budget, cache=cache, bridges=None,
        )

    recovery_options = None
    if getattr(args, "use_llm_recovery", False):
        from venomhook.static_pipeline import LLMRecoveryOptions
        recovery_options = LLMRecoveryOptions(
            provider=provider, budget=budget, cache=cache,
        )

    return tagging_options, proto_options, flow_options, recovery_options


def _close_llm_option_caches(*options: object | None) -> None:
    """Close each unique LLM cache carried by option objects, if any."""
    seen: set[int] = set()
    for option in options:
        cache = getattr(option, "cache", None)
        if cache is None:
            continue
        cache_id = id(cache)
        if cache_id in seen:
            continue
        seen.add(cache_id)
        cache.close()


def app(argv: list[str] | None = None) -> None:
    main(argv)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="venomhook", description="Offset-based Hook Automation CLI")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    subparsers = parser.add_subparsers(dest="command", required=True)

    static_parser = subparsers.add_parser("offset-static", help="Build HookSpec from StaticMeta JSON, binary, or APK (Ghidra)")
    static_parser.add_argument("--static-json", "-s", type=Path, help="Path to StaticMeta JSON")
    static_parser.add_argument("--binary", "-b", type=Path, help="Path to binary (Ghidra headless)")
    static_parser.add_argument("--apk", type=Path, help="Path to Android APK; a native .so is extracted and analyzed via Ghidra")
    static_parser.add_argument("--abi", type=str, default="auto", help='ABI to extract from APK ("auto"/"arm64-v8a"/"armeabi-v7a"/"x86_64"/"x86")')
    static_parser.add_argument("--apk-lib", type=str, help="Specific .so basename within the chosen ABI (default: first available)")
    static_parser.add_argument("--apk-extract-dir", type=Path, help="Where to write the extracted .so (default: temp dir)")
    static_parser.add_argument("--out", "-o", type=Path, default=Path("venomhook.json"), help="Output HookSpec JSON")
    static_parser.add_argument(
        "--out-db",
        type=Path,
        help="Optional SQLite output (venomhook.db). If set, writes both JSON (--out) and SQLite.",
    )
    static_parser.add_argument(
        "--report-md",
        type=Path,
        help="Optional Markdown report output path",
    )
    static_parser.add_argument(
        "--profile",
        type=Path,
        help="Profile JSON for static options (sig_max_bytes, score weights)",
    )
    static_parser.add_argument("--sig-max-bytes", type=int, default=12, help="Signature max bytes for pattern prefix")
    static_parser.add_argument("--score-network", type=int, default=30, help="Weight: network imports")
    static_parser.add_argument("--score-file", type=int, default=20, help="Weight: file imports")
    static_parser.add_argument("--score-auth", type=int, default=15, help="Weight: auth keywords (per distinct)")
    static_parser.add_argument("--score-url", type=int, default=10, help="Weight: url/http strings")
    static_parser.add_argument("--score-crypto", type=int, default=10, help="Weight: crypto keywords")
    static_parser.add_argument("--score-jni", type=int, default=30, help="Weight: JNI / Android (Java_* symbol or JNI imports)")
    static_parser.add_argument("--score-callers-per", type=int, default=2, help="Weight per caller (capped)")
    static_parser.add_argument("--score-callers-cap", type=int, default=10, help="Cap for caller weight")
    static_parser.add_argument("--score-callees-per", type=int, default=1, help="Weight per callee (capped)")
    static_parser.add_argument("--score-callees-cap", type=int, default=5, help="Cap for callee weight")
    static_parser.add_argument("--score-bb-bonus", type=int, default=5, help="Bonus for basic blocks > threshold")
    static_parser.add_argument("--score-bb-threshold", type=int, default=10, help="Threshold for basic block bonus")
    static_parser.add_argument(
        "--ghidra-headless",
        type=str,
        help="Path to ghidraRun (headless). Required when using --binary.",
    )
    static_parser.add_argument(
        "--ghidra-script",
        type=Path,
        help="Ghidra postScript path to export StaticMeta JSON. Required with --binary.",
    )
    static_parser.add_argument(
        "--ghidra-project-dir",
        type=Path,
        help="Ghidra project directory (default: temp dir)",
    )
    static_parser.add_argument(
        "--ghidra-project-name",
        type=str,
        default="venomhook_project",
        help="Ghidra project name",
    )
    static_parser.add_argument("--top", "-t", type=int, default=10, help="Top N endpoints to export")
    _add_llm_flags(static_parser, features=("tagging", "proto", "flow", "recovery"))
    static_parser.set_defaults(func=cmd_offset_static)

    hook_parser = subparsers.add_parser("offset-hook", help="Generate Frida script from HookSpec JSON")
    hook_parser.add_argument("--hookspec", "-i", type=Path, help="HookSpec JSON/SQLite input")
    hook_parser.add_argument(
        "--hookspec-db",
        type=Path,
        help="HookSpec SQLite input (alternative to --hookspec)",
    )
    hook_parser.add_argument(
        "--target",
        "-t",
        type=str,
        required=True,
        help="Target module/process name (e.g., sample.exe)",
    )
    hook_parser.add_argument(
        "--out-script",
        "-o",
        type=Path,
        default=Path("venomhook.js"),
        help="Where to write the generated Frida script",
    )
    hook_parser.add_argument(
        "--print-script",
        action="store_true",
        help="Also print the script to stdout",
    )
    hook_parser.add_argument(
        "--log-format",
        choices=["text", "json"],
        default="text",
        help="Log format inside Frida script",
    )
    hook_parser.add_argument(
        "--log-prefix",
        type=str,
        default="[venomhook]",
        help="Prefix for text logs",
    )
    hook_parser.add_argument(
        "--scenario-message",
        type=str,
        help="Optional scenario marker to send() after hook setup",
    )
    hook_parser.add_argument(
        "--auto-start-scenario",
        action="store_true",
        help="Automatically call runScenario() after hooks are attached",
    )
    hook_parser.add_argument(
        "--hexdump-len",
        type=int,
        default=64,
        help="Length for hexdump in bytes",
    )
    hook_parser.add_argument(
        "--string-arg",
        action="append",
        type=int,
        help="Argument index to read as C-string (can repeat)",
    )
    hook_parser.add_argument(
        "--string-ret",
        action="store_true",
        help="Read return value as C-string",
    )
    hook_parser.add_argument(
        "--string-len",
        type=int,
        default=128,
        help="Max length when reading strings",
    )
    hook_parser.add_argument(
        "--scan-size",
        type=int,
        help="Memory.scan length in bytes for signature fallback (default: module size)",
    )
    hook_parser.add_argument(
        "--retry-attach",
        type=int,
        default=1,
        help="Retry count for Interceptor.attach failures",
    )
    hook_parser.add_argument(
        "--profile",
        type=Path,
        help="Profile JSON for dynamic options (hexdump_len, string args, scan_size, etc.)",
    )
    hook_parser.add_argument(
        "--module-alias",
        action="append",
        help="Additional module name candidate for Frida lookup (can repeat). "
        "Useful for ELF version suffixes (libfoo.so.1.2.3) or Mach-O variants.",
    )
    hook_parser.set_defaults(func=cmd_offset_hook)

    run_parser = subparsers.add_parser("offset-run", help="Run Frida with generated script")
    run_parser.add_argument("--script", "-s", type=Path, required=True, help="Frida script to load (e.g., venomhook.js)")
    run_parser.add_argument(
        "--target",
        "-t",
        type=str,
        required=True,
        help="Target module/process name (for -f) or PID (with --attach)",
    )
    run_parser.add_argument("--frida-path", type=str, default="frida", help="frida executable path")
    run_parser.add_argument("--attach", action="store_true", help="Attach to running process instead of spawn")
    run_parser.add_argument("--no-pause", action="store_true", default=True, help="Pass --no-pause to frida")
    run_parser.add_argument("--extra-arg", action="append", help="Additional args to frida (can repeat)")
    run_parser.add_argument("--log-file", type=Path, help="Path to save frida stdout/stderr")
    run_parser.add_argument("--dry-run", action="store_true", help="Print command without executing")
    run_parser.set_defaults(func=cmd_offset_run)

    runtime_parser = subparsers.add_parser("offset-report-runtime", help="Summarize Frida JSON log to markdown/html")
    runtime_parser.add_argument("--log", "-i", type=Path, required=True, help="Frida log file (JSON lines)")
    runtime_parser.add_argument("--out-md", type=Path, help="Markdown summary output")
    runtime_parser.add_argument("--out-html", type=Path, help="HTML summary output")
    _add_llm_flags(runtime_parser, features=("report",))
    runtime_parser.set_defaults(func=cmd_offset_report_runtime)

    e2e_parser = subparsers.add_parser("offset-e2e", help="Run static->hook->frida script pipeline (optional frida run); supports APK input")
    e2e_parser.add_argument("--static-json", "-s", type=Path, help="Path to StaticMeta JSON")
    e2e_parser.add_argument("--binary", "-b", type=Path, help="Path to binary (Ghidra headless)")
    e2e_parser.add_argument("--apk", type=Path, help="Path to Android APK; a native .so is extracted and analyzed via Ghidra")
    e2e_parser.add_argument("--abi", type=str, default="auto", help='ABI to extract from APK ("auto" prefers arm64-v8a)')
    e2e_parser.add_argument("--apk-lib", type=str, help="Specific .so basename to extract (default: first available)")
    e2e_parser.add_argument("--apk-extract-dir", type=Path, help="Where to write the extracted .so (default: <out-dir>/extracted)")
    e2e_parser.add_argument("--target", "-t", type=str, required=True, help="Target module/process name")
    e2e_parser.add_argument("--out-dir", type=Path, default=Path("out"), help="Output directory for artifacts")
    e2e_parser.add_argument("--profile", type=Path, help="Profile JSON for static/dynamic defaults")
    e2e_parser.add_argument("--top", "-T", type=int, default=10, help="Top N endpoints")
    e2e_parser.add_argument("--sig-max-bytes", type=int, default=STATIC_DEFAULTS["sig_max_bytes"], help="Signature max bytes")
    e2e_parser.add_argument("--score-network", type=int, default=STATIC_DEFAULTS["score_network"], help="Weight: network imports")
    e2e_parser.add_argument("--score-file", type=int, default=STATIC_DEFAULTS["score_file"], help="Weight: file imports")
    e2e_parser.add_argument("--score-auth", type=int, default=STATIC_DEFAULTS["score_auth"], help="Weight: auth keywords")
    e2e_parser.add_argument("--score-url", type=int, default=STATIC_DEFAULTS["score_url"], help="Weight: url/http strings")
    e2e_parser.add_argument("--score-crypto", type=int, default=STATIC_DEFAULTS["score_crypto"], help="Weight: crypto keywords")
    e2e_parser.add_argument("--score-jni", type=int, default=STATIC_DEFAULTS["score_jni"], help="Weight: JNI / Android")
    e2e_parser.add_argument("--score-callers-per", type=int, default=STATIC_DEFAULTS["score_callers_per"], help="Weight per caller")
    e2e_parser.add_argument("--score-callers-cap", type=int, default=STATIC_DEFAULTS["score_callers_cap"], help="Cap for caller weight")
    e2e_parser.add_argument("--score-callees-per", type=int, default=STATIC_DEFAULTS["score_callees_per"], help="Weight per callee")
    e2e_parser.add_argument("--score-callees-cap", type=int, default=STATIC_DEFAULTS["score_callees_cap"], help="Cap for callee weight")
    e2e_parser.add_argument("--score-bb-bonus", type=int, default=STATIC_DEFAULTS["score_bb_bonus"], help="Bonus for basic blocks > threshold")
    e2e_parser.add_argument("--score-bb-threshold", type=int, default=STATIC_DEFAULTS["score_bb_threshold"], help="Basic blocks threshold")
    e2e_parser.add_argument("--ghidra-headless", type=str, help="Path to ghidraRun (headless)")
    e2e_parser.add_argument("--ghidra-script", type=Path, help="Ghidra postScript path")
    e2e_parser.add_argument("--ghidra-project-dir", type=Path, help="Ghidra project directory")
    e2e_parser.add_argument("--ghidra-project-name", type=str, default="venomhook_project", help="Ghidra project name")
    # dynamic options
    e2e_parser.add_argument("--log-format", choices=["text", "json"], default="json", help="Log format")
    e2e_parser.add_argument("--log-prefix", type=str, default="[venomhook]", help="Log prefix")
    e2e_parser.add_argument("--scenario-message", type=str, help="Scenario message")
    e2e_parser.add_argument("--auto-start-scenario", action="store_true", help="Auto run scenario")
    e2e_parser.add_argument("--hexdump-len", type=int, default=DYNAMIC_DEFAULTS["hexdump_len"], help="Hexdump length")
    e2e_parser.add_argument("--string-arg", action="append", type=int, help="Args to read as string")
    e2e_parser.add_argument("--string-ret", action="store_true", help="Read return as string")
    e2e_parser.add_argument("--string-len", type=int, default=DYNAMIC_DEFAULTS["string_len"], help="String length")
    e2e_parser.add_argument("--scan-size", type=int, help="Signature scan length")
    e2e_parser.add_argument("--retry-attach", type=int, default=DYNAMIC_DEFAULTS["retry_attach"], help="Attach retry count")
    e2e_parser.add_argument(
        "--module-alias",
        action="append",
        help="Additional module name candidate for Frida lookup (can repeat).",
    )
    e2e_parser.add_argument("--frida-path", type=str, default="frida", help="frida executable path")
    e2e_parser.add_argument("--frida-log", type=Path, help="frida stdout/stderr log path")
    e2e_parser.add_argument("--run-frida", action="store_true", help="Run frida (otherwise skip)")
    e2e_parser.add_argument("--dry-run", action="store_true", help="Pass --no-pause etc but do not execute (for frida)")
    e2e_parser.add_argument("--summarize-log", action="store_true", help="Summarize frida log if present")
    _add_llm_flags(e2e_parser, features=("tagging", "proto", "flow", "recovery"))
    e2e_parser.set_defaults(func=cmd_offset_e2e)

    audit_parser = subparsers.add_parser(
        "android-audit",
        help="Decode APK manifest, run vulnerability audit, generate PoC recipes",
    )
    audit_parser.add_argument("--apk", type=Path, required=True, help="Path to Android APK")
    audit_parser.add_argument(
        "--abi", type=str, default="auto",
        help='ABI to extract for .so analysis ("auto"/"arm64-v8a"/etc.)',
    )
    audit_parser.add_argument(
        "--apk-lib", type=str, help="Specific .so basename within ABI (default: first available)",
    )
    audit_parser.add_argument(
        "--out-dir", type=Path,
        help="Working directory for apktool/jadx outputs (default: temp dir)",
    )
    audit_parser.add_argument(
        "--report-json", type=Path,
        help="Write full AndroidAnalysis.to_dict() JSON to this path",
    )
    audit_parser.add_argument(
        "--audit-json", type=Path,
        help="Write only the AndroidAuditReport JSON to this path",
    )
    audit_parser.add_argument(
        "--poc-json", type=Path,
        help="Write the PoC artifact list as JSON to this path",
    )
    audit_parser.add_argument(
        "--poc-bundle-dir", type=Path,
        help="Export each PoC as a runnable .sh / .frida.js / .md under this "
        "directory along with a README.md index",
    )
    audit_parser.add_argument(
        "--apktool-path", type=str, help="Override apktool binary path (default: $PATH lookup)",
    )
    audit_parser.add_argument(
        "--jadx-path", type=str, help="Override jadx binary path (default: $PATH lookup)",
    )
    audit_parser.add_argument(
        "--no-jadx", action="store_true",
        help="Skip jadx (java decompile + JNI bridges); audit-only mode",
    )
    audit_parser.add_argument(
        "--strict-tools", action="store_true",
        help="Fail with non-zero exit when apktool/jadx are unavailable",
    )
    audit_parser.add_argument(
        "--severity-threshold",
        choices=[SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM, SEV_LOW, SEV_INFO],
        help="Exit non-zero (CI gate) if any finding's severity is at or above this level",
    )
    audit_parser.add_argument(
        "--quiet", action="store_true",
        help="Suppress per-finding stdout output (still writes JSON if requested)",
    )
    audit_parser.add_argument(
        "--cache-dir", type=Path,
        help="Persist analyses under DIR/cache.db keyed by APK hash. On a "
        "hit the cached AndroidAnalysis is replayed instead of rerunning "
        "apktool / jadx / lief.",
    )
    audit_parser.add_argument(
        "--no-cache-replay", action="store_true",
        help="With --cache-dir, write to the cache but never read from it "
        "(forces a fresh analysis every run).",
    )
    audit_parser.add_argument(
        "--no-cache-write", action="store_true",
        help="With --cache-dir, only read from the cache; do not store this "
        "run's analysis.",
    )
    audit_parser.set_defaults(func=cmd_android_audit)

    cache_list_parser = subparsers.add_parser(
        "android-cache-list",
        help="List entries in an analysis cache (one row per APK hash + schema)",
    )
    cache_list_parser.add_argument(
        "--cache-dir", type=Path, required=True,
        help="Directory containing cache.db (created by `android-audit --cache-dir`)",
    )
    cache_list_parser.add_argument(
        "--json", action="store_true",
        help="Emit machine-readable JSON instead of the default text table",
    )
    cache_list_parser.set_defaults(func=cmd_android_cache_list)

    cache_diff_parser = subparsers.add_parser(
        "android-cache-diff",
        help="Diff two cached AndroidAnalysis records (by APK hash)",
    )
    cache_diff_parser.add_argument(
        "--cache-dir", type=Path, required=True,
        help="Directory containing cache.db",
    )
    cache_diff_parser.add_argument(
        "--old", type=str, required=True,
        help="APK hash (sha256:<hex>) of the baseline analysis",
    )
    cache_diff_parser.add_argument(
        "--new", type=str, required=True,
        help="APK hash (sha256:<hex>) of the comparison analysis",
    )
    cache_diff_parser.add_argument(
        "--old-schema", type=int, default=SCHEMA_VERSION,
        help="Schema version for --old (default: current SCHEMA_VERSION)",
    )
    cache_diff_parser.add_argument(
        "--new-schema", type=int, default=SCHEMA_VERSION,
        help="Schema version for --new (default: current SCHEMA_VERSION)",
    )
    cache_diff_parser.add_argument(
        "--json", type=Path,
        help="Write the diff as JSON to this path (in addition to stdout)",
    )
    cache_diff_parser.add_argument(
        "--exit-on-changes", action="store_true",
        help="Exit non-zero (code 2) if the diff contains any changes — "
        "useful for CI gates that should fail on regression in findings",
    )
    cache_diff_parser.set_defaults(func=cmd_android_cache_diff)

    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format=LOG_FORMAT)
    args.func(args)


def _resolve_apk_to_binary(args: argparse.Namespace, default_extract_dir: Path | None = None) -> None:
    """If --apk is set, extract a .so and route it through args.binary.

    Mutually exclusive with --binary and --static-json. Raises SystemExit on conflict
    or extraction failure.
    """
    apk_path = getattr(args, "apk", None)
    if not apk_path:
        return

    if getattr(args, "binary", None):
        raise SystemExit("--apk and --binary are mutually exclusive")
    if getattr(args, "static_json", None):
        raise SystemExit("--apk and --static-json are mutually exclusive")

    try:
        meta = extract_apk_meta(apk_path)
        chosen_abi = select_abi(meta, getattr(args, "abi", "auto") or "auto")
        extract_dir = (
            getattr(args, "apk_extract_dir", None)
            or default_extract_dir
            or Path(__import__("tempfile").mkdtemp(prefix="venomhook_apk_"))
        )
        so_path = extract_native_lib(
            apk_path,
            abi=chosen_abi,
            lib_name=getattr(args, "apk_lib", None),
            dest_dir=extract_dir,
        )
    except ApkExtractError as e:
        raise SystemExit(f"APK extraction failed: {e}") from e

    logging.info(
        "APK %s -> abi=%s lib=%s extracted to %s",
        meta.name, chosen_abi, so_path.name, extract_dir,
    )
    # Route through the existing --binary path. Ghidra options must still be set.
    args.binary = so_path


def cmd_offset_static(args: argparse.Namespace) -> None:
    _resolve_apk_to_binary(args)
    profile_data = load_profile(args.profile) if getattr(args, "profile", None) else {}
    apply_static_profile(args, profile_data)
    score_cfg = ScoreConfig(
        network_weight=args.score_network,
        file_weight=args.score_file,
        auth_weight=args.score_auth,
        url_weight=args.score_url,
        crypto_weight=args.score_crypto,
        jni_weight=args.score_jni,
        callers_per=args.score_callers_per,
        callers_cap=args.score_callers_cap,
        callees_per=args.score_callees_per,
        callees_cap=args.score_callees_cap,
        basic_blocks_bonus=args.score_bb_bonus,
        basic_blocks_threshold=args.score_bb_threshold,
    )
    ghidra_runner = None
    if args.binary:
        if not args.ghidra_headless or not args.ghidra_script:
            raise SystemExit("Provide --ghidra-headless and --ghidra-script when using --binary")
        ghidra_runner = GhidraRunner(
            headless_cmd=[args.ghidra_headless],
            post_script=args.ghidra_script,
            project_dir=args.ghidra_project_dir,
            project_name=args.ghidra_project_name,
        )
    llm_tagging, llm_proto, llm_flow, llm_recovery = _build_llm_options(args)
    try:
        pipeline = StaticPipeline(
            top_n=args.top,
            score_config=score_cfg,
            sig_max_bytes=args.sig_max_bytes,
            ghidra_runner=ghidra_runner,
            llm_tagging=llm_tagging,
            llm_proto=llm_proto,
            llm_flow=llm_flow,
            llm_recovery=llm_recovery,
        )
        if not args.static_json and not args.binary:
            raise SystemExit("Provide either --static-json or --binary")
        hooks = pipeline.run(
            static_meta=args.static_json,
            binary=args.binary,
            out=args.out,
            report_md=args.report_md,
            ghidra_runner=ghidra_runner,
        )
        if args.out_db:
            HookSpecStore.save(args.out_db, hooks)
            logging.info("also wrote HookSpec to %s", args.out_db)
        logging.info("generated %d HookSpec entries", len(hooks))
    finally:
        _close_llm_option_caches(llm_tagging, llm_proto, llm_flow, llm_recovery)


def cmd_offset_hook(args: argparse.Namespace) -> None:
    hookspec_path = args.hookspec_db or args.hookspec
    if not hookspec_path:
        raise SystemExit("Provide --hookspec or --hookspec-db")
    profile_data = load_profile(args.profile) if getattr(args, "profile", None) else {}
    apply_dynamic_profile(args, profile_data)
    specs = HookSpecStore.load(hookspec_path)
    # Apply CLI-provided module aliases to every spec, preserving any aliases
    # already attached during HookSpec construction.
    extra_aliases = getattr(args, "module_alias", None) or []
    if extra_aliases:
        for spec in specs:
            spec.module_aliases = list(spec.module_aliases) + extra_aliases
    pipeline = DynamicPipeline(
        target=args.target,
        log_format=args.log_format,
        log_prefix=args.log_prefix,
        scenario_message=args.scenario_message,
        auto_start_scenario=args.auto_start_scenario,
        hexdump_len=args.hexdump_len,
        string_args=args.string_arg or [],
        string_ret=args.string_ret,
        string_len=args.string_len,
        scan_size=args.scan_size,
        retry_attach=args.retry_attach,
    )
    script = pipeline.generate_script(specs)
    pipeline.save_script(args.out_script, specs)
    logging.info("Frida script written to %s", args.out_script)
    if args.print_script:
        sys.stdout.write(script)


def apply_static_profile(args: argparse.Namespace, profile: dict) -> None:
    static = profile.get("static", {}) if profile else {}
    if not static:
        return
    if "sig_max_bytes" in static and args.sig_max_bytes == STATIC_DEFAULTS["sig_max_bytes"]:
        args.sig_max_bytes = static["sig_max_bytes"]

    score_prof = static.get("score", {})
    score_map = {
        "network_weight": "score_network",
        "file_weight": "score_file",
        "auth_weight": "score_auth",
        "url_weight": "score_url",
        "crypto_weight": "score_crypto",
        "jni_weight": "score_jni",
        "callers_per": "score_callers_per",
        "callers_cap": "score_callers_cap",
        "callees_per": "score_callees_per",
        "callees_cap": "score_callees_cap",
        "basic_blocks_bonus": "score_bb_bonus",
        "basic_blocks_threshold": "score_bb_threshold",
    }
    for key, arg_name in score_map.items():
        if key in score_prof and getattr(args, arg_name) == STATIC_DEFAULTS[arg_name]:
            setattr(args, arg_name, score_prof[key])


def apply_dynamic_profile(args: argparse.Namespace, profile: dict) -> None:
    dynamic = profile.get("dynamic", {}) if profile else {}
    if not dynamic:
        return
    if "hexdump_len" in dynamic and args.hexdump_len == DYNAMIC_DEFAULTS["hexdump_len"]:
        args.hexdump_len = dynamic["hexdump_len"]
    if "string_arg" in dynamic and (args.string_arg is None or args.string_arg == []):
        args.string_arg = dynamic["string_arg"]
    if "string_ret" in dynamic and args.string_ret == DYNAMIC_DEFAULTS["string_ret"]:
        args.string_ret = bool(dynamic["string_ret"])
    if "string_len" in dynamic and args.string_len == DYNAMIC_DEFAULTS["string_len"]:
        args.string_len = dynamic["string_len"]
    if "scan_size" in dynamic and args.scan_size is None:
        args.scan_size = dynamic["scan_size"]
    if "retry_attach" in dynamic and args.retry_attach == DYNAMIC_DEFAULTS["retry_attach"]:
        args.retry_attach = dynamic["retry_attach"]


def cmd_offset_run(args: argparse.Namespace) -> None:
    cmd_str = run_frida(
        target=args.target,
        script=args.script,
        frida_path=args.frida_path,
        attach=args.attach,
        no_pause=args.no_pause,
        extra_args=args.extra_arg,
        log_file=args.log_file,
        dry_run=args.dry_run,
    )
    if args.dry_run:
        logging.info("frida command (dry-run): %s", cmd_str)
    else:
        logging.info("frida completed: %s", cmd_str)


def cmd_offset_report_runtime(args: argparse.Namespace) -> None:
    summary = summarize_log_file(args.log)
    if not args.out_md and not args.out_html:
        raise SystemExit("Provide at least one of --out-md or --out-html")

    analyst_summary = None
    if getattr(args, "use_llm_report", False):
        runtime = _build_llm_runtime(args)
        if runtime is not None:
            provider, budget, cache = runtime
            try:
                from venomhook.llm.runtime_summary import summarize_runtime_log
                analyst_summary, stats = summarize_runtime_log(
                    summary, provider=provider, budget=budget, cache=cache,
                )
                logging.info(stats.as_summary_line())
            finally:
                if cache is not None:
                    cache.close()

    if args.out_md:
        write_markdown_summary(summary, args.out_md, analyst_summary=analyst_summary)
        logging.info("runtime log summary (md) written to %s", args.out_md)
    if args.out_html:
        write_html_summary(summary, args.out_html, analyst_summary=analyst_summary)
        logging.info("runtime log summary (html) written to %s", args.out_html)


def cmd_offset_e2e(args: argparse.Namespace) -> None:
    out_dir = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    _resolve_apk_to_binary(args, default_extract_dir=out_dir / "extracted")
    profile_data = load_profile(args.profile) if getattr(args, "profile", None) else {}
    apply_static_profile(args, profile_data)
    if not args.static_json and not args.binary:
        raise SystemExit("Provide either --static-json or --binary")
    score_cfg = ScoreConfig(
        network_weight=args.score_network,
        file_weight=args.score_file,
        auth_weight=args.score_auth,
        url_weight=args.score_url,
        crypto_weight=args.score_crypto,
        jni_weight=args.score_jni,
        callers_per=args.score_callers_per,
        callers_cap=args.score_callers_cap,
        callees_per=args.score_callees_per,
        callees_cap=args.score_callees_cap,
        basic_blocks_bonus=args.score_bb_bonus,
        basic_blocks_threshold=args.score_bb_threshold,
    )
    ghidra_runner = None
    if args.binary:
        if not args.ghidra_headless or not args.ghidra_script:
            raise SystemExit("Provide --ghidra-headless and --ghidra-script when using --binary")
        ghidra_runner = GhidraRunner(
            headless_cmd=[args.ghidra_headless],
            post_script=args.ghidra_script,
            project_dir=args.ghidra_project_dir,
            project_name=args.ghidra_project_name,
        )

    hook_json = out_dir / "venomhook.json"
    hook_db = out_dir / "venomhook.db"
    hook_md = out_dir / "venomhook.md"
    frida_js = out_dir / "venomhook.js"

    llm_tagging, llm_proto, llm_flow, llm_recovery = _build_llm_options(args)
    try:
        static_pipe = StaticPipeline(
            top_n=args.top,
            score_config=score_cfg,
            sig_max_bytes=args.sig_max_bytes,
            ghidra_runner=ghidra_runner,
            llm_tagging=llm_tagging,
            llm_proto=llm_proto,
            llm_flow=llm_flow,
            llm_recovery=llm_recovery,
        )
        hooks = static_pipe.run(
            static_meta=args.static_json,
            binary=args.binary,
            out=hook_json,
            report_md=hook_md,
            ghidra_runner=ghidra_runner,
        )
        extra_aliases = getattr(args, "module_alias", None) or []
        if extra_aliases:
            for spec in hooks:
                spec.module_aliases = list(spec.module_aliases) + extra_aliases
        HookSpecStore.save(hook_db, hooks)

        apply_dynamic_profile(args, profile_data)
        dyn_pipe = DynamicPipeline(
            target=args.target,
            log_format=args.log_format,
            log_prefix=args.log_prefix,
            scenario_message=args.scenario_message,
            auto_start_scenario=args.auto_start_scenario,
            hexdump_len=args.hexdump_len,
            string_args=args.string_arg or [],
            string_ret=args.string_ret,
            string_len=args.string_len,
            scan_size=args.scan_size,
            retry_attach=args.retry_attach,
        )
        dyn_pipe.save_script(frida_js, hooks)

        frida_log = args.frida_log or (out_dir / "frida.log")
        if args.run_frida:
            cmd_str = run_frida(
                target=args.target,
                script=frida_js,
                frida_path=args.frida_path,
                attach=False,
                no_pause=True,
                extra_args=None,
                log_file=frida_log,
                dry_run=args.dry_run,
            )
            logging.info(
                "frida command%s: %s",
                " (dry-run)" if args.dry_run else "",
                cmd_str,
            )
            if args.summarize_log and frida_log.exists() and frida_log.stat().st_size > 0:
                summary_md = out_dir / "runtime_summary.md"
                summary_html = out_dir / "runtime_summary.html"
                summary = summarize_log_file(frida_log)
                write_markdown_summary(summary, summary_md)
                write_html_summary(summary, summary_html)
                logging.info("runtime summaries written to %s, %s", summary_md, summary_html)
        else:
            logging.info("frida run skipped (use --run-frida to execute)")
    finally:
        _close_llm_option_caches(llm_tagging, llm_proto, llm_flow, llm_recovery)


def cmd_android_audit(args: argparse.Namespace) -> None:
    """Decode an APK's manifest, run the audit rule engine, and emit PoCs.

    Output channels:
      - stdout   : audit summary + PoC bundle (suppressible with --quiet)
      - --report-json : full AndroidAnalysis.to_dict() (apk_meta, app_meta,
                        bridges, audit_report, pocs, ...)
      - --audit-json  : only AndroidAuditReport.to_dict()
      - --poc-json    : only the PoCArtifact list

    Exit codes:
      0 — success, no severity gate triggered
      1 — pipeline error (APK invalid, manifest decode failure, missing tools
          when --strict-tools, etc.)
      2 — severity gate: at least one finding at or above
          --severity-threshold
    """
    import json
    import tempfile

    def write_json(path: Path, payload: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2))

    if args.out_dir:
        work_dir = args.out_dir
        work_dir.mkdir(parents=True, exist_ok=True)
    else:
        work_dir = Path(tempfile.mkdtemp(prefix="venomhook_audit_"))
        logging.info("using temporary work dir: %s", work_dir)

    apktool_config = ApktoolConfig(apktool_path=args.apktool_path) if args.apktool_path else None
    jadx_config = JadxConfig(jadx_path=args.jadx_path) if args.jadx_path else None

    cache: AnalysisCache | None = None
    if args.cache_dir:
        cache = AnalysisCache(args.cache_dir / "cache.db")

    try:
        result = None
        cache_update_needed = False
        if cache and not args.no_cache_replay:
            # Cheap hash probe: extract_apk_meta only opens the zip + sha256s,
            # which is much cheaper than running apktool/jadx/lief.
            try:
                apk_meta_probe = extract_apk_meta(args.apk)
            except ApkExtractError as e:
                logging.error("android-audit failed: %s", e)
                raise SystemExit(1) from e
            cached = cache.get(apk_meta_probe.hash)
            if cached is not None:
                if cached.app_meta is None:
                    logging.warning(
                        "cache hit for %s has no decoded manifest; "
                        "ignoring cached analysis",
                        apk_meta_probe.hash,
                    )
                else:
                    logging.info("cache hit for %s — replaying stored analysis",
                                 apk_meta_probe.hash)
                    result = cached

        if result is None:
            try:
                result = analyze_apk(
                    args.apk,
                    work_dir,
                    abi=args.abi,
                    lib_name=args.apk_lib,
                    use_apktool=True,
                    use_jadx=not args.no_jadx,
                    apktool_config=apktool_config,
                    jadx_config=jadx_config,
                    fail_on_missing_tools=args.strict_tools,
                    require_native=False,
                )
            except AndroidPipelineError as e:
                logging.error("android-audit failed: %s", e)
                raise SystemExit(1) from e
            cache_update_needed = True

        for w in result.warnings:
            logging.warning("%s", w)

        if result.app_meta is None:
            logging.error(
                "manifest decode skipped — audit cannot run. Install apktool or "
                "pass --apktool-path; or use --strict-tools to surface the error."
            )
            raise SystemExit(1)

        if result.audit_report is None:
            logging.info(
                "cached analysis missing audit report; rebuilding from app_meta"
            )
            result.audit_report = audit_manifest(result.app_meta)
            result.pocs = generate_pocs(result.app_meta, result.audit_report)
            cache_update_needed = True

        audit_report = result.audit_report
        pocs = result.pocs

        if cache and cache_update_needed and not args.no_cache_write:
            cache.put(result)
            logging.info("analysis cached under %s (apk_hash=%s)",
                         args.cache_dir, result.apk_meta.hash)

        if not args.quiet:
            print(format_audit_summary(audit_report))
            print()
            print(format_pocs_text(pocs))

        if args.report_json:
            write_json(args.report_json, result.to_dict())
            logging.info("AndroidAnalysis written to %s", args.report_json)
        if args.audit_json:
            write_json(args.audit_json, audit_report.to_dict())
            logging.info("AndroidAuditReport written to %s", args.audit_json)
        if args.poc_json:
            write_json(args.poc_json, [p.to_dict() for p in pocs])
            logging.info("PoC artifacts written to %s", args.poc_json)
        if args.poc_bundle_dir:
            written = export_pocs(pocs, args.poc_bundle_dir)
            logging.info("PoC bundle (%d files) written under %s",
                         len(written), args.poc_bundle_dir)

        if (
            args.severity_threshold
            and audit_report.has_severity_at_least(args.severity_threshold)
        ):
            logging.error(
                "severity gate triggered: at least one finding at or above '%s'",
                args.severity_threshold,
            )
            raise SystemExit(2)
    finally:
        if cache:
            cache.close()


def cmd_android_cache_list(args: argparse.Namespace) -> None:
    """Print every cache entry. Default output is a fixed-width table;
    ``--json`` emits a JSON list suitable for piping into jq.
    """
    import json

    db_path = args.cache_dir / "cache.db"
    if not db_path.exists():
        logging.error("no cache database at %s", db_path)
        raise SystemExit(1)

    with AnalysisCache(db_path) as cache:
        entries = cache.list_entries()

    if args.json:
        print(json.dumps([
            {
                "apk_hash": e.apk_hash,
                "schema_version": e.schema_version,
                "created_at": e.created_at,
                "package_name": e.package_name,
                "apk_name": e.apk_name,
                "finding_count": e.finding_count,
            }
            for e in entries
        ], indent=2))
        return

    if not entries:
        print("(cache is empty)")
        return

    print(f"{'apk_hash':30}  {'sv':>3}  {'created_at':25}  "
          f"{'findings':>8}  {'package':30}  apk")
    for e in entries:
        short_hash = (e.apk_hash[:26] + "...") if len(e.apk_hash) > 26 else e.apk_hash
        print(
            f"{short_hash:30}  {e.schema_version:>3}  "
            f"{e.created_at[:19]:25}  {e.finding_count:>8}  "
            f"{(e.package_name or '-'):30}  {e.apk_name or '-'}"
        )


def cmd_android_cache_diff(args: argparse.Namespace) -> None:
    """Diff two cached analyses by APK hash. Stdout always shows the
    text rendering; ``--json`` additionally writes the structured form.
    With ``--exit-on-changes``, returns exit code 2 when the diff is
    non-empty (CI regression gate).
    """
    import json

    db_path = args.cache_dir / "cache.db"
    if not db_path.exists():
        logging.error("no cache database at %s", db_path)
        raise SystemExit(1)

    with AnalysisCache(db_path) as cache:
        old = cache.get(args.old, schema_version=args.old_schema)
        new = cache.get(args.new, schema_version=args.new_schema)

    if old is None:
        logging.error(
            "apk_hash not found in cache: %s (schema=%s)",
            args.old,
            args.old_schema,
        )
        raise SystemExit(1)
    if new is None:
        logging.error(
            "apk_hash not found in cache: %s (schema=%s)",
            args.new,
            args.new_schema,
        )
        raise SystemExit(1)

    diff = diff_analyses(old, new)
    print(format_diff_text(diff))

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(diff.to_dict(), indent=2))
        logging.info("diff written to %s", args.json)

    if args.exit_on_changes and diff.has_changes:
        raise SystemExit(2)


if __name__ == "__main__":
    app()

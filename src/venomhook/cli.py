from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from venomhook import __version__
from venomhook.dynamic_pipeline import DynamicPipeline
from venomhook.ghidra_runner import GhidraRunner
from venomhook.orchestrator import run_frida
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


def app(argv: list[str] | None = None) -> None:
    main(argv)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="venomhook", description="Offset-based Hook Automation CLI")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    subparsers = parser.add_subparsers(dest="command", required=True)

    static_parser = subparsers.add_parser("offset-static", help="Build HookSpec from StaticMeta JSON or binary (Ghidra)")
    static_parser.add_argument("--static-json", "-s", type=Path, help="Path to StaticMeta JSON")
    static_parser.add_argument("--binary", "-b", type=Path, help="Path to binary (Ghidra headless)")
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
    runtime_parser.set_defaults(func=cmd_offset_report_runtime)

    e2e_parser = subparsers.add_parser("offset-e2e", help="Run static->hook->frida script pipeline (optional frida run)")
    e2e_parser.add_argument("--static-json", "-s", type=Path, help="Path to StaticMeta JSON")
    e2e_parser.add_argument("--binary", "-b", type=Path, help="Path to binary (Ghidra headless)")
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
    e2e_parser.add_argument("--frida-path", type=str, default="frida", help="frida executable path")
    e2e_parser.add_argument("--frida-log", type=Path, help="frida stdout/stderr log path")
    e2e_parser.add_argument("--run-frida", action="store_true", help="Run frida (otherwise skip)")
    e2e_parser.add_argument("--dry-run", action="store_true", help="Pass --no-pause etc but do not execute (for frida)")
    e2e_parser.add_argument("--summarize-log", action="store_true", help="Summarize frida log if present")
    e2e_parser.set_defaults(func=cmd_offset_e2e)

    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format=LOG_FORMAT)
    args.func(args)


def cmd_offset_static(args: argparse.Namespace) -> None:
    profile_data = load_profile(args.profile) if getattr(args, "profile", None) else {}
    apply_static_profile(args, profile_data)
    score_cfg = ScoreConfig(
        network_weight=args.score_network,
        file_weight=args.score_file,
        auth_weight=args.score_auth,
        url_weight=args.score_url,
        crypto_weight=args.score_crypto,
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
    pipeline = StaticPipeline(top_n=args.top, score_config=score_cfg, sig_max_bytes=args.sig_max_bytes, ghidra_runner=ghidra_runner)
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


def cmd_offset_hook(args: argparse.Namespace) -> None:
    hookspec_path = args.hookspec_db or args.hookspec
    if not hookspec_path:
        raise SystemExit("Provide --hookspec or --hookspec-db")
    profile_data = load_profile(args.profile) if getattr(args, "profile", None) else {}
    apply_dynamic_profile(args, profile_data)
    specs = HookSpecStore.load(hookspec_path)
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
    if args.out_md:
        write_markdown_summary(summary, args.out_md)
        logging.info("runtime log summary (md) written to %s", args.out_md)
    if args.out_html:
        write_html_summary(summary, args.out_html)
        logging.info("runtime log summary (html) written to %s", args.out_html)


def cmd_offset_e2e(args: argparse.Namespace) -> None:
    out_dir = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)
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

    static_pipe = StaticPipeline(top_n=args.top, score_config=score_cfg, sig_max_bytes=args.sig_max_bytes, ghidra_runner=ghidra_runner)
    hooks = static_pipe.run(static_meta=args.static_json, binary=args.binary, out=hook_json, report_md=hook_md, ghidra_runner=ghidra_runner)
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
        logging.info("frida command%s: %s", " (dry-run)" if args.dry_run else "", cmd_str)
        if args.summarize_log and frida_log.exists() and frida_log.stat().st_size > 0:
            summary_md = out_dir / "runtime_summary.md"
            summary_html = out_dir / "runtime_summary.html"
            summary = summarize_log_file(frida_log)
            write_markdown_summary(summary, summary_md)
            write_html_summary(summary, summary_html)
            logging.info("runtime summaries written to %s, %s", summary_md, summary_html)
    else:
        logging.info("frida run skipped (use --run-frida to execute)")


if __name__ == "__main__":
    app()

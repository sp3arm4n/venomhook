#!/usr/bin/env python3
"""apk-batch-audit — run venomhook android-audit on every APK in a dir.

See ../SKILL.md for purpose. This script is the single source of truth for
batch APK regression. Outputs:

  out_audit_runs/                # default (gitignored)
  ├── cache/                     # shared SQLite cache; replay across APKs
  ├── <slug>/
  │   ├── report.json
  │   ├── audit.json
  │   ├── pocs/
  │   └── audit.html
  └── summary.txt                # comparison table (always written)

The script intentionally avoids any heavy deps — stdlib only. It shells out
to the `venomhook` console script that pyproject.toml installs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from collections import defaultdict
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[4]
DEFAULT_APK_DIR = REPO_ROOT / "sample" / "apk"
DEFAULT_OUT_DIR = REPO_ROOT / "out_audit_runs"
ALL_RULES = [f"MANIFEST-00{i}" for i in range(1, 10)]
SEVERITIES = ("critical", "high", "medium", "low", "info")


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


_SLUG_RE = re.compile(r"[^A-Za-z0-9]+")


def _slug(name: str) -> str:
    return _SLUG_RE.sub("-", Path(name).stem.lower()).strip("-") or "apk"


def _run_audit(apk: Path, out_dir: Path, cache_dir: Path, replay_only: bool) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    report_json = out_dir / "report.json"
    audit_json = out_dir / "audit.json"
    cmd = [
        "venomhook", "android-audit",
        "--apk", str(apk),
        "--out-dir", str(out_dir),
        "--report-json", str(report_json),
        "--audit-json", str(audit_json),
        "--poc-bundle-dir", str(out_dir / "pocs"),
        "--out-html", str(out_dir / "audit.html"),
        "--cache-dir", str(cache_dir),
        "--quiet",
    ]
    if replay_only:
        cmd.append("--no-cache-write")
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return {
        "returncode": proc.returncode,
        "stderr_tail": proc.stderr.splitlines()[-3:],
        "report_json": report_json if report_json.exists() else None,
        "audit_json": audit_json if audit_json.exists() else None,
    }


def _summarize(audit_path: Path, report_path: Path | None) -> dict:
    audit = json.loads(audit_path.read_text(encoding="utf-8"))
    rule_counts: dict[str, int] = defaultdict(int)
    sev_counts: dict[str, int] = defaultdict(int)
    for f in audit.get("findings", []):
        rule_counts[f["rule_id"]] += 1
        sev_counts[f["severity"]] += 1
    out: dict = {
        "package": audit.get("package_name"),
        "total": len(audit.get("findings", [])),
        "rules": dict(rule_counts),
        "severity": dict(sev_counts),
    }
    if report_path and report_path.exists():
        report = json.loads(report_path.read_text(encoding="utf-8"))
        meta = report.get("app_meta", {})
        out["min_sdk"] = meta.get("min_sdk")
        out["target_sdk"] = meta.get("target_sdk")
        out["components"] = len(meta.get("components", []))
        out["warnings"] = len(report.get("warnings", []))
        out["natives"] = len(report.get("java_natives", []))
        out["bridges_total"] = len(report.get("bridges", []))
        out["bridges_matched"] = sum(
            1 for b in report.get("bridges", []) if b.get("matched_symbol")
        )
    return out


def _format_table(rows: list[tuple[str, dict, list[str]]]) -> str:
    lines = []
    header = (
        f"{'APK':<20} {'pkg':<32} {'min':>3} {'tgt':>3} "
        f"{'cmp':>3} {'nat':>3} {'br m/t':>7} {'tot':>3} "
        + " ".join(f"{r.split('-')[1]:>3}" for r in ALL_RULES)
    )
    lines.append(header)
    lines.append("-" * len(header))
    for slug, s, aliases in rows:
        rules = s.get("rules", {})
        rule_cells = " ".join(f"{rules.get(r, 0) or '.':>3}" for r in ALL_RULES)
        lines.append(
            f"{slug:<20} {(s.get('package') or '?')[:32]:<32} "
            f"{(s.get('min_sdk') or '?'):>3} {(s.get('target_sdk') or '?'):>3} "
            f"{s.get('components', 0):>3} {s.get('natives', 0):>3} "
            f"{s.get('bridges_matched', 0)}/{s.get('bridges_total', 0):<5} "
            f"{s.get('total', 0):>3} {rule_cells}"
        )
        if aliases:
            lines.append(f"{'':<20} ↳ aliases (same SHA-256): {', '.join(aliases)}")
    return "\n".join(lines)


def _diff_against_baseline(current: dict, baseline_path: Path) -> str:
    try:
        baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        return f"(baseline unreadable: {e})"
    diffs: list[str] = []
    cur_apks = current.get("apks", {})
    base_apks = baseline.get("apks", {})
    for k in sorted(set(cur_apks) | set(base_apks)):
        c = cur_apks.get(k)
        b = base_apks.get(k)
        if c is None:
            diffs.append(f"  - {k}: removed (was findings={b.get('total')})")
            continue
        if b is None:
            diffs.append(f"  + {k}: new (findings={c.get('total')})")
            continue
        c_total = c.get("total", 0)
        b_total = b.get("total", 0)
        if c_total != b_total:
            diffs.append(f"  ~ {k}: findings {b_total} -> {c_total}")
        # rule-level diff
        c_rules = c.get("rules", {})
        b_rules = b.get("rules", {})
        for r in sorted(set(c_rules) | set(b_rules)):
            cc = c_rules.get(r, 0)
            bc = b_rules.get(r, 0)
            if cc != bc:
                diffs.append(f"     · {r}: {bc} -> {cc}")
    if not diffs:
        return "(no changes vs baseline)"
    return "\n".join(diffs)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--apk-dir", type=Path, default=DEFAULT_APK_DIR,
                        help="directory containing .apk files (default: sample/apk)")
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR,
                        help="working dir for reports (default: out_audit_runs/)")
    parser.add_argument("--replay-only", action="store_true",
                        help="don't write to cache (still reads); use to verify replay")
    parser.add_argument("--clean", action="store_true",
                        help="remove out-dir before running")
    parser.add_argument("--json-out", type=Path,
                        help="also write a JSON summary to this path")
    parser.add_argument("--baseline", type=Path,
                        help="compare against a prior --json-out file")
    args = parser.parse_args()

    if not args.apk_dir.is_dir():
        print(f"error: apk dir not found: {args.apk_dir}", file=sys.stderr)
        return 2

    if args.clean and args.out_dir.exists():
        shutil.rmtree(args.out_dir)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    cache_dir = args.out_dir / "cache"
    cache_dir.mkdir(parents=True, exist_ok=True)

    apks = sorted(args.apk_dir.glob("*.apk"))
    if not apks:
        print(f"error: no .apk in {args.apk_dir}", file=sys.stderr)
        return 2

    by_hash: dict[str, list[Path]] = defaultdict(list)
    for apk in apks:
        by_hash[_sha256(apk)].append(apk)

    summaries: dict[str, dict] = {}
    aliases_for: dict[str, list[str]] = {}
    rows: list[tuple[str, dict, list[str]]] = []

    for digest, group in sorted(by_hash.items()):
        canonical = group[0]
        slug = _slug(canonical.name)
        out = args.out_dir / slug
        result = _run_audit(canonical, out, cache_dir, args.replay_only)
        if result["returncode"] != 0 or not result["audit_json"]:
            print(f"FAIL {canonical.name}: rc={result['returncode']}",
                  file=sys.stderr)
            for line in result["stderr_tail"]:
                print(f"  | {line}", file=sys.stderr)
            continue
        s = _summarize(result["audit_json"], result["report_json"])
        s["apk_filename"] = canonical.name
        s["sha256"] = digest
        summaries[slug] = s
        aliases = [p.name for p in group[1:]]
        aliases_for[slug] = aliases
        rows.append((slug, s, aliases))

    table = _format_table(rows)
    summary_text = (
        f"# apk-batch-audit summary — {len(rows)} unique APK(s) "
        f"({sum(len(g) for g in by_hash.values())} files, "
        f"{sum(1 for g in by_hash.values() if len(g) > 1)} dup group(s))\n\n"
        f"{table}\n"
    )

    if args.baseline:
        diff_text = _diff_against_baseline(
            {"apks": summaries}, args.baseline
        )
        summary_text += f"\n## diff vs baseline ({args.baseline})\n{diff_text}\n"

    summary_path = args.out_dir / "summary.txt"
    summary_path.write_text(summary_text, encoding="utf-8")
    print(summary_text)

    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(
            json.dumps({"apks": summaries}, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable


def parse_log_lines(lines: Iterable[str]) -> dict[str, Any]:
    """Parse frida JSON log lines and build a simple summary."""
    counts = Counter()
    errors = Counter()
    hexdumps = 0
    strings: dict[str, list[str]] = defaultdict(list)
    enter_samples: dict[str, list[str]] = defaultdict(list)
    ret_samples: dict[str, list[str]] = defaultdict(list)

    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        event = data.get("event")
        hook = data.get("hook")
        if not event or not hook:
            continue
        counts[(hook, event)] += 1
        if event == "error":
            errors[hook] += 1
        if event == "hexdump":
            hexdumps += 1
        if event == "string":
            msg = data.get("msg")
            if msg and len(strings[hook]) < 5:
                strings[hook].append(msg)
        if event == "enter":
            val = data.get("value") or data.get("arg")
            if val is not None and len(enter_samples[hook]) < 5:
                enter_samples[hook].append(str(val))
        if event == "leave":
            val = data.get("ret")
            if val is not None and len(ret_samples[hook]) < 3:
                ret_samples[hook].append(str(val))

    per_hook = defaultdict(dict)
    for (hook, event), cnt in counts.items():
        per_hook[hook][event] = cnt

    return {
        "hooks": per_hook,
        "errors": errors,
        "hexdumps": hexdumps,
        "total_events": sum(counts.values()),
        "strings": strings,
        "enter_samples": enter_samples,
        "ret_samples": ret_samples,
    }


def summarize_log_file(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fp:
        return parse_log_lines(fp)


def write_markdown_summary(summary: dict[str, Any], path: Path) -> None:
    lines = [
        "# Runtime Log Summary",
        "",
        f"- total_events: {summary.get('total_events', 0)}",
        f"- hexdumps: {summary.get('hexdumps', 0)}",
        f"- hooks with errors: {len(summary.get('errors', {}))}",
        "",
        "| hook | enter | leave | hexdump | error |",
        "| --- | --- | --- | --- | --- |",
    ]
    hooks = summary.get("hooks", {})
    errors = summary.get("errors", {})
    strings = summary.get("strings", {})
    enter_samples = summary.get("enter_samples", {})
    ret_samples = summary.get("ret_samples", {})
    for hook, evs in hooks.items():
        enter = evs.get("enter", 0)
        leave = evs.get("leave", 0)
        hd = evs.get("hexdump", 0)
        err = errors.get(hook, 0)
        lines.append(f"| {hook} | {enter} | {leave} | {hd} | {err} |")
    if strings:
        lines.extend(
            [
                "",
                "## Sample Strings",
            ]
        )
        for hook, samples in strings.items():
            lines.append(f"- {hook}: " + "; ".join(samples))
    if enter_samples or ret_samples:
        lines.extend(["", "## Sample Args/Ret"])
        for hook, samples in enter_samples.items():
            lines.append(f"- {hook} args: " + "; ".join(samples))
        for hook, samples in ret_samples.items():
            lines.append(f"- {hook} ret: " + "; ".join(samples))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def write_html_summary(summary: dict[str, Any], path: Path) -> None:
    hooks = summary.get("hooks", {})
    errors = summary.get("errors", {})
    total_events = summary.get("total_events", 0)
    hexdumps = summary.get("hexdumps", 0)
    strings = summary.get("strings", {})
    enter_samples = summary.get("enter_samples", {})
    ret_samples = summary.get("ret_samples", {})

    rows = []
    for hook, evs in hooks.items():
        enter = evs.get("enter", 0)
        leave = evs.get("leave", 0)
        hd = evs.get("hexdump", 0)
        err = errors.get(hook, 0)
        rows.append(f"<tr><td>{hook}</td><td>{enter}</td><td>{leave}</td><td>{hd}</td><td>{err}</td></tr>")

    string_blocks = []
    for hook, samples in strings.items():
        string_blocks.append(
            "<div><strong>{}</strong>: {}</div>".format(hook, "; ".join(samples))
        )
    args_blocks = []
    for hook, samples in enter_samples.items():
        args_blocks.append("<div><strong>{}</strong> args: {}</div>".format(hook, "; ".join(samples)))
    for hook, samples in ret_samples.items():
        args_blocks.append("<div><strong>{}</strong> ret: {}</div>".format(hook, "; ".join(samples)))

    html = "\n".join(
        [
            "<!doctype html>",
            "<html><head><meta charset='utf-8'><title>Runtime Log Summary</title>",
            "<style>table {border-collapse: collapse;} td, th {border: 1px solid #ccc; padding: 4px;} th {background:#f5f5f5;}</style>",
            "</head><body>",
            "<h1>Runtime Log Summary</h1>",
            f"<p>total_events: {total_events} | hexdumps: {hexdumps} | hooks with errors: {len(errors)}</p>",
            "<table>",
            "<tr><th>hook</th><th>enter</th><th>leave</th><th>hexdump</th><th>error</th></tr>",
            *rows,
            "</table>",
            "<h2>Sample Strings</h2>",
            *string_blocks,
            "<h2>Sample Args/Ret</h2>",
            *args_blocks,
            "</body></html>",
        ]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html, encoding="utf-8")

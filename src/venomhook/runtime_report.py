from __future__ import annotations

import json
from collections import Counter, defaultdict
from html import escape
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


def write_markdown_summary(
    summary: dict[str, Any],
    path: Path,
    *,
    analyst_summary: str | None = None,
) -> None:
    """Write the rule-based runtime markdown report.

    Optional ``analyst_summary`` (Phase 5 ④) appends an "Analyst
    Summary" section at the end. Pass ``None`` (default) to keep the
    report identical to pre-Phase-5 output.
    """
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
    if analyst_summary:
        lines.extend(["", "## Analyst Summary", "", analyst_summary])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def write_html_summary(
    summary: dict[str, Any],
    path: Path,
    *,
    analyst_summary: str | None = None,
) -> None:
    hooks = summary.get("hooks", {})
    errors = summary.get("errors", {})
    total_events = summary.get("total_events", 0)
    hexdumps = summary.get("hexdumps", 0)
    strings = summary.get("strings", {})
    enter_samples = summary.get("enter_samples", {})
    ret_samples = summary.get("ret_samples", {})

    rows = []
    for hook, evs in hooks.items():
        hook_html = escape(str(hook), quote=True)
        enter = evs.get("enter", 0)
        leave = evs.get("leave", 0)
        hd = evs.get("hexdump", 0)
        err = errors.get(hook, 0)
        rows.append(
            f"<tr><td>{hook_html}</td><td>{enter}</td><td>{leave}</td><td>{hd}</td><td>{err}</td></tr>"
        )

    string_blocks = []
    for hook, samples in strings.items():
        hook_html = escape(str(hook), quote=True)
        samples_html = "; ".join(escape(str(sample), quote=True) for sample in samples)
        string_blocks.append(
            "<div><strong>{}</strong>: {}</div>".format(hook_html, samples_html)
        )
    args_blocks = []
    for hook, samples in enter_samples.items():
        hook_html = escape(str(hook), quote=True)
        samples_html = "; ".join(escape(str(sample), quote=True) for sample in samples)
        args_blocks.append("<div><strong>{}</strong> args: {}</div>".format(hook_html, samples_html))
    for hook, samples in ret_samples.items():
        hook_html = escape(str(hook), quote=True)
        samples_html = "; ".join(escape(str(sample), quote=True) for sample in samples)
        args_blocks.append("<div><strong>{}</strong> ret: {}</div>".format(hook_html, samples_html))

    analyst_block: list[str] = []
    if analyst_summary:
        # Render the markdown-ish analyst summary as a <pre> block; keeps
        # the layout simple and avoids parsing markdown inside the HTML
        # writer. Escapes user-derived content so a noisy LLM response
        # can't inject HTML.
        analyst_block = [
            "<h2>Analyst Summary</h2>",
            f"<pre>{escape(analyst_summary)}</pre>",
        ]

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
            *analyst_block,
            "</body></html>",
        ]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html, encoding="utf-8")

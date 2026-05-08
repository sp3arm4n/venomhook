"""Self-contained HTML rendering for ``AndroidAnalysis``.

Phase 6 / UX. CLI users running ``android-audit`` historically had only
JSON + console output to inspect findings, and PoC artifacts lived in a
separate flat bundle directory with no visual linkage back to the
finding they were generated from. This module fixes both gaps in one
artifact:

    * One HTML file with severity-colored finding cards.
    * Each card embeds the PoC artifacts that prove that specific
      finding (matched by ``(rule_id, component)``), so the operator
      can read the issue and its proof together.
    * Components / JNI bridges / native imports surfaced as auxiliary
      tables so the report is a complete picture of the run.

Design notes:
    * Single-file output. CSS is inlined; no external assets, no JS,
      no network — opens correctly from a thumb drive or air-gapped
      review machine.
    * Every user-derived string passes through ``html.escape`` so a
      malicious APK's component names / strings can't inject markup.
    * ``poc_bundle_dir`` is optional. When supplied, each PoC card
      links to its on-disk file with a path relative to the HTML
      output's parent directory, so reviewers can click through to the
      runnable script.

Pure rendering — no I/O happens until ``write_audit_html`` is called.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from html import escape
from pathlib import Path
from typing import Optional

from venomhook.android_pipeline import AndroidAnalysis
from venomhook.models import (
    AndroidAuditReport,
    AndroidComponent,
    JniBridge,
    ManifestFinding,
    PoCArtifact,
)


__all__ = [
    "render_audit_html",
    "write_audit_html",
]


_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


_CSS = """
:root {
  --bg: #0f1115;
  --card: #1a1d24;
  --card-muted: #161922;
  --border: #2a2f3a;
  --text: #e6e9ef;
  --text-muted: #97a0b0;
  --accent: #4ea1ff;
  --code-bg: #0a0c10;
  --sev-critical: #d63a3a;
  --sev-high: #e6753b;
  --sev-medium: #d9a44a;
  --sev-low: #4a8fd9;
  --sev-info: #6c7785;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  background: var(--bg);
  color: var(--text);
  line-height: 1.5;
}
.container { max-width: 1100px; margin: 0 auto; padding: 24px; }
header.report-head { padding: 24px 0; border-bottom: 1px solid var(--border); margin-bottom: 24px; }
header.report-head h1 { margin: 0 0 8px 0; font-size: 1.6em; }
header.report-head .subtitle { color: var(--text-muted); font-size: 0.95em; }
header.report-head dl { display: grid; grid-template-columns: max-content 1fr; gap: 4px 16px; margin: 16px 0 0 0; font-size: 0.92em; }
header.report-head dt { color: var(--text-muted); }
header.report-head dd { margin: 0; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; word-break: break-all; }

.severity-bar { display: flex; gap: 8px; margin: 16px 0 8px 0; flex-wrap: wrap; }
.sev-chip {
  display: inline-flex; align-items: baseline; gap: 6px;
  padding: 4px 10px; border-radius: 4px; font-size: 0.85em;
  background: var(--card-muted); border: 1px solid var(--border);
}
.sev-chip .count { font-weight: 700; font-size: 1.05em; }
.sev-chip.sev-critical { border-left: 3px solid var(--sev-critical); }
.sev-chip.sev-high { border-left: 3px solid var(--sev-high); }
.sev-chip.sev-medium { border-left: 3px solid var(--sev-medium); }
.sev-chip.sev-low { border-left: 3px solid var(--sev-low); }
.sev-chip.sev-info { border-left: 3px solid var(--sev-info); }

section { margin-top: 32px; }
section > h2 { font-size: 1.25em; margin: 0 0 12px 0; padding-bottom: 6px; border-bottom: 1px solid var(--border); }

.finding {
  background: var(--card); border: 1px solid var(--border); border-radius: 6px;
  margin-bottom: 16px; padding: 16px 18px;
  border-left-width: 4px; border-left-style: solid;
}
.finding.sev-critical { border-left-color: var(--sev-critical); }
.finding.sev-high { border-left-color: var(--sev-high); }
.finding.sev-medium { border-left-color: var(--sev-medium); }
.finding.sev-low { border-left-color: var(--sev-low); }
.finding.sev-info { border-left-color: var(--sev-info); }
.finding header { display: flex; flex-wrap: wrap; gap: 8px 12px; align-items: baseline; }
.finding .sev-tag {
  display: inline-block; padding: 2px 8px; border-radius: 3px;
  font-size: 0.75em; font-weight: 700; letter-spacing: 0.5px;
  text-transform: uppercase; color: #fff;
}
.finding.sev-critical .sev-tag { background: var(--sev-critical); }
.finding.sev-high .sev-tag { background: var(--sev-high); }
.finding.sev-medium .sev-tag { background: var(--sev-medium); }
.finding.sev-low .sev-tag { background: var(--sev-low); }
.finding.sev-info .sev-tag { background: var(--sev-info); }
.finding .rule-id { font-family: ui-monospace, monospace; color: var(--text-muted); font-size: 0.9em; }
.finding h3 { margin: 0; font-size: 1.05em; flex: 1 1 auto; }
.finding .component { font-family: ui-monospace, monospace; color: var(--accent); font-size: 0.85em; word-break: break-all; }
.finding .description { margin: 10px 0 0 0; font-size: 0.95em; }
.finding .meta { margin-top: 10px; font-size: 0.85em; color: var(--text-muted); }
.finding .meta span { margin-right: 12px; }

.pocs { margin-top: 14px; padding-top: 12px; border-top: 1px dashed var(--border); }
.pocs h4 { margin: 0 0 8px 0; font-size: 0.92em; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; }
details.poc { background: var(--card-muted); border: 1px solid var(--border); border-radius: 4px; margin-bottom: 8px; }
details.poc[open] { background: var(--card-muted); }
details.poc summary {
  cursor: pointer; padding: 8px 12px; font-size: 0.9em;
  display: flex; gap: 10px; align-items: baseline; flex-wrap: wrap;
}
details.poc summary::-webkit-details-marker { color: var(--text-muted); }
details.poc summary .kind {
  display: inline-block; padding: 1px 6px; border-radius: 3px;
  background: var(--bg); border: 1px solid var(--border);
  font-family: ui-monospace, monospace; font-size: 0.78em; text-transform: uppercase;
}
details.poc summary .title { flex: 1 1 auto; }
details.poc summary .file-link {
  font-family: ui-monospace, monospace; font-size: 0.8em;
  color: var(--text-muted); text-decoration: none;
}
details.poc summary .file-link:hover { color: var(--accent); }
details.poc .body { padding: 0 12px 12px 12px; font-size: 0.88em; }
details.poc .body p { margin: 8px 0; }
details.poc .body pre {
  background: var(--code-bg); border: 1px solid var(--border);
  border-radius: 3px; padding: 10px; overflow-x: auto;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 0.85em;
}

table.tbl {
  width: 100%; border-collapse: collapse; font-size: 0.88em;
  background: var(--card); border: 1px solid var(--border); border-radius: 4px;
  overflow: hidden;
}
table.tbl th, table.tbl td {
  padding: 8px 10px; text-align: left; border-bottom: 1px solid var(--border);
  vertical-align: top;
}
table.tbl th { background: var(--card-muted); color: var(--text-muted); font-weight: 600; font-size: 0.85em; text-transform: uppercase; letter-spacing: 0.4px; }
table.tbl tr:last-child td { border-bottom: none; }
table.tbl td.mono, table.tbl td.fqn { font-family: ui-monospace, monospace; word-break: break-all; }
table.tbl .yes { color: var(--sev-high); font-weight: 600; }
table.tbl .no { color: var(--text-muted); }

.warnings { background: var(--card-muted); border-left: 3px solid var(--sev-medium); padding: 10px 14px; margin-bottom: 16px; border-radius: 0 4px 4px 0; }
.warnings ul { margin: 6px 0 0 0; padding-left: 20px; }
.warnings li { font-size: 0.88em; }

footer { margin-top: 48px; padding: 16px 0; border-top: 1px solid var(--border); color: var(--text-muted); font-size: 0.82em; text-align: center; }
"""


@dataclass(frozen=True)
class _PocLink:
    """One PoC entry with optional file link relative to the HTML output."""

    artifact: PoCArtifact
    href: Optional[str]  # relative URL or None when no bundle dir is set


def _finding_key(rule_id: str, component: Optional[str]) -> tuple[str, Optional[str]]:
    return (rule_id, component)


def _group_pocs_by_finding(
    pocs: list[PoCArtifact],
    bundle_dir: Optional[Path],
    out_path: Optional[Path],
) -> dict[tuple[str, Optional[str]], list[_PocLink]]:
    """Index ``(rule_id, component) -> [PocLink]`` for cheap card lookup.

    When ``bundle_dir`` and ``out_path`` are both set, the link is the
    relative path from the HTML's directory to the PoC file using the
    canonical ``poc_export`` filename pattern.
    """
    from venomhook.poc_export import _filename_for  # local import to avoid cycle

    out: dict[tuple[str, Optional[str]], list[_PocLink]] = {}
    for idx, art in enumerate(pocs, 1):
        key = _finding_key(art.rule_id, art.component)
        href: Optional[str] = None
        if bundle_dir is not None and out_path is not None:
            try:
                rel = (bundle_dir / _filename_for(idx, art)).resolve().relative_to(
                    out_path.parent.resolve()
                )
                href = str(rel)
            except Exception:
                # Cross-volume / unrelated paths fall back to no link rather
                # than emitting an absolute file:// URL the operator may not
                # be able to follow.
                href = None
        out.setdefault(key, []).append(_PocLink(artifact=art, href=href))
    return out


def _severity_class(severity: str) -> str:
    s = severity.lower()
    if s not in _SEVERITY_ORDER:
        return "sev-info"
    return f"sev-{s}"


def _sev_sort_key(finding: ManifestFinding) -> tuple[int, str, str]:
    return (
        _SEVERITY_ORDER.get(finding.severity.lower(), 9),
        finding.rule_id,
        finding.component or "",
    )


def _render_summary_dl(analysis: AndroidAnalysis) -> str:
    apk = analysis.apk_meta
    app = analysis.app_meta
    rows: list[tuple[str, str]] = []
    if app:
        rows.append(("Package", escape(app.package_name)))
    rows.append(("APK", escape(apk.name)))
    rows.append(("SHA-256", escape(apk.hash)))
    if apk.abis:
        rows.append(("ABIs", ", ".join(escape(a) for a in apk.abis)))
    if analysis.selected_abi:
        rows.append(("Analyzed ABI", escape(analysis.selected_abi)))
    if app:
        rows.append(("Debuggable", "yes" if app.debuggable else "no"))
        rows.append(("Allow backup", "yes" if app.allow_backup else "no"))
    so = analysis.so_meta
    if so:
        rows.append(("Native lib", f"{escape(so.name)} ({escape(so.format)}/{escape(so.arch)})"))
        rows.append(("Native imports / exports", f"{len(so.imports)} / {len(so.exports)}"))
    if analysis.bridges:
        matched = sum(1 for b in analysis.bridges if b.matched_symbol)
        rows.append(("JNI bridges", f"{matched} matched / {len(analysis.bridges)} declared"))
    return "<dl>" + "".join(f"<dt>{k}</dt><dd>{v}</dd>" for k, v in rows) + "</dl>"


def _render_severity_bar(report: AndroidAuditReport) -> str:
    counts: dict[str, int] = {}
    for f in report.findings:
        s = f.severity.lower()
        counts[s] = counts.get(s, 0) + 1
    if not counts:
        return '<div class="severity-bar"><span class="sev-chip sev-info"><span class="count">0</span> findings</span></div>'
    chips = []
    for sev in ("critical", "high", "medium", "low", "info"):
        n = counts.get(sev, 0)
        if n == 0:
            continue
        chips.append(
            f'<span class="sev-chip sev-{sev}">'
            f'<span class="count">{n}</span> {sev}</span>'
        )
    chips.append(f'<span class="sev-chip"><span class="count">{len(report.findings)}</span> total</span>')
    return '<div class="severity-bar">' + "".join(chips) + "</div>"


_LANG_BY_KIND = {"adb": "shell", "shell": "shell", "frida": "javascript", "info": ""}


def _render_poc(link: _PocLink) -> str:
    a = link.artifact
    kind_label = escape(a.kind.upper())
    title = escape(a.title)
    file_link = ""
    if link.href is not None:
        file_link = (
            f'<a class="file-link" href="{escape(link.href, quote=True)}" '
            f'title="open the runnable artifact">{escape(Path(link.href).name)}</a>'
        )
    body_parts: list[str] = []
    if a.description:
        body_parts.append(f"<p>{escape(a.description)}</p>")
    if a.commands:
        cmd_text = "\n".join(a.commands)
        body_parts.append(f"<pre>{escape(cmd_text)}</pre>")
    if a.expected_evidence:
        body_parts.append(
            f"<p><strong>Expected:</strong> {escape(a.expected_evidence)}</p>"
        )
    if a.notes:
        body_parts.append(f"<p><strong>Notes:</strong> {escape(a.notes)}</p>")
    if a.references:
        body_parts.append(
            "<p><strong>Refs:</strong> "
            + ", ".join(escape(r) for r in a.references)
            + "</p>"
        )
    body_html = "".join(body_parts) or "<p><em>(no body recorded)</em></p>"
    return (
        f'<details class="poc">'
        f'<summary>'
        f'<span class="kind">{kind_label}</span>'
        f'<span class="title">{title}</span>'
        f'{file_link}'
        f'</summary>'
        f'<div class="body">{body_html}</div>'
        f'</details>'
    )


def _render_finding_card(
    finding: ManifestFinding,
    pocs: list[_PocLink],
) -> str:
    sev_cls = _severity_class(finding.severity)
    sev_label = escape(finding.severity.upper())
    rule_id = escape(finding.rule_id)
    title = escape(finding.title)
    comp_html = (
        f'<span class="component">{escape(finding.component)}</span>'
        if finding.component else ""
    )
    body_parts: list[str] = []
    if finding.detail:
        body_parts.append(f'<div class="description">{escape(finding.detail)}</div>')
    if finding.remediation:
        body_parts.append(
            '<div class="description"><strong>Remediation:</strong> '
            f'{escape(finding.remediation)}</div>'
        )
    desc = "".join(body_parts)
    refs = (
        '<div class="meta">'
        + " ".join(f'<span>{escape(r)}</span>' for r in finding.references)
        + "</div>"
        if finding.references else ""
    )
    poc_section = ""
    if pocs:
        items = "".join(_render_poc(p) for p in pocs)
        poc_section = (
            f'<div class="pocs">'
            f'<h4>Proof-of-Concept ({len(pocs)})</h4>'
            f'{items}'
            f"</div>"
        )
    else:
        poc_section = (
            '<div class="pocs">'
            '<h4>Proof-of-Concept (0)</h4>'
            '<p style="color: var(--text-muted); font-size: 0.85em; margin: 4px 0;">'
            'No PoC artifact was generated for this rule. Manual review required.'
            "</p></div>"
        )
    return (
        f'<article class="finding {sev_cls}">'
        f'<header>'
        f'<span class="sev-tag">{sev_label}</span>'
        f'<span class="rule-id">{rule_id}</span>'
        f'<h3>{title}</h3>'
        f'{comp_html}'
        f"</header>"
        f"{desc}"
        f"{refs}"
        f"{poc_section}"
        f"</article>"
    )


def _render_components_table(components: list[AndroidComponent]) -> str:
    if not components:
        return ""
    rows = []
    for c in components:
        exported_html = (
            '<span class="yes">yes</span>' if c.exported
            else '<span class="no">no</span>'
        )
        perm = escape(c.permission) if c.permission else "—"
        intents = (
            ", ".join(escape(a) for a in c.intent_actions[:3])
            + ("…" if len(c.intent_actions) > 3 else "")
        ) if c.intent_actions else "—"
        rows.append(
            f"<tr>"
            f"<td>{escape(c.type)}</td>"
            f'<td class="fqn">{escape(c.name)}</td>'
            f"<td>{exported_html}</td>"
            f"<td>{perm}</td>"
            f'<td class="mono">{intents}</td>'
            f"</tr>"
        )
    return (
        '<table class="tbl">'
        "<thead><tr><th>type</th><th>name</th><th>exported</th><th>permission</th><th>intent-filter actions</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody>"
        "</table>"
    )


def _render_bridges_table(bridges: list[JniBridge], limit: int = 50) -> str:
    if not bridges:
        return ""
    matched = [b for b in bridges if b.matched_symbol]
    unmatched = [b for b in bridges if not b.matched_symbol]
    ordered = matched + unmatched
    rows = []
    for b in ordered[:limit]:
        jm = b.java_method
        sym = escape(b.matched_symbol) if b.matched_symbol else (
            '<span class="no">unmatched</span>'
        )
        rows.append(
            f"<tr>"
            f'<td class="fqn">{escape(jm.class_fqn)}.{escape(jm.method_name)}</td>'
            f"<td>{len(jm.arg_types)}</td>"
            f'<td class="mono">{sym}</td>'
            f"</tr>"
        )
    note = ""
    if len(bridges) > limit:
        note = (
            f'<p style="color: var(--text-muted); font-size: 0.85em; margin: 6px 0 0 0;">'
            f"Showing {limit} of {len(bridges)} bridges "
            f"({len(matched)} matched first). Full list available in JSON.</p>"
        )
    return (
        '<table class="tbl">'
        "<thead><tr><th>java method</th><th>args</th><th>matched native symbol</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody>"
        "</table>"
        f"{note}"
    )


def _render_warnings(warnings: list[str]) -> str:
    if not warnings:
        return ""
    items = "".join(f"<li>{escape(w)}</li>" for w in warnings)
    return f'<div class="warnings"><strong>Warnings</strong><ul>{items}</ul></div>'


def render_audit_html(
    analysis: AndroidAnalysis,
    *,
    poc_bundle_dir: Optional[Path] = None,
    out_path: Optional[Path] = None,
    title: Optional[str] = None,
) -> str:
    """Render an :class:`AndroidAnalysis` as a self-contained HTML string.

    ``poc_bundle_dir`` and ``out_path`` are paired — when both are given,
    each PoC card links to its on-disk file using a path relative to
    ``out_path.parent``. With either missing, PoCs are still embedded in
    the cards but without a download link.
    """
    title_html = escape(title) if title else "VenomHook Audit Report"
    poc_index = _group_pocs_by_finding(
        list(analysis.pocs),
        Path(poc_bundle_dir) if poc_bundle_dir else None,
        Path(out_path) if out_path else None,
    )

    findings_html_parts: list[str] = []
    audit = analysis.audit_report
    if audit:
        sorted_findings = sorted(audit.findings, key=_sev_sort_key)
        for finding in sorted_findings:
            key = _finding_key(finding.rule_id, finding.component)
            pocs_for_this = poc_index.get(key, [])
            findings_html_parts.append(
                _render_finding_card(finding, pocs_for_this)
            )

    findings_section = (
        f'<section class="findings-section">'
        f"<h2>Findings ({len(audit.findings) if audit else 0})</h2>"
        f"{_render_severity_bar(audit) if audit else ''}"
        + ("".join(findings_html_parts) or
           '<p style="color: var(--text-muted);">No findings.</p>')
        + "</section>"
    )

    components_section = ""
    if analysis.app_meta and analysis.app_meta.components:
        components_section = (
            '<section class="components-section">'
            f"<h2>Components ({len(analysis.app_meta.components)})</h2>"
            f"{_render_components_table(analysis.app_meta.components)}"
            "</section>"
        )

    bridges_section = ""
    if analysis.bridges:
        matched_count = sum(1 for b in analysis.bridges if b.matched_symbol)
        bridges_section = (
            '<section class="bridges-section">'
            f"<h2>JNI Bridges ({matched_count} matched / {len(analysis.bridges)} declared)</h2>"
            f"{_render_bridges_table(analysis.bridges)}"
            "</section>"
        )

    warnings_html = _render_warnings(list(analysis.warnings))

    return (
        '<!doctype html>'
        '<html lang="en">'
        '<head>'
        '<meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{title_html}</title>"
        f"<style>{_CSS}</style>"
        "</head>"
        '<body><div class="container">'
        '<header class="report-head">'
        f"<h1>{title_html}</h1>"
        '<div class="subtitle">VenomHook android-audit report</div>'
        f"{_render_summary_dl(analysis)}"
        "</header>"
        f"{warnings_html}"
        f"{findings_section}"
        f"{components_section}"
        f"{bridges_section}"
        '<footer>Generated by venomhook · open this file in any browser · no JavaScript or external assets required.</footer>'
        "</div></body></html>"
    )


def write_audit_html(
    analysis: AndroidAnalysis,
    path: str | Path,
    *,
    poc_bundle_dir: Optional[str | Path] = None,
    title: Optional[str] = None,
) -> Path:
    """Render and write the HTML report. Returns the resolved output path."""
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    html = render_audit_html(
        analysis,
        poc_bundle_dir=Path(poc_bundle_dir) if poc_bundle_dir else None,
        out_path=out,
        title=title,
    )
    out.write_text(html, encoding="utf-8")
    return out

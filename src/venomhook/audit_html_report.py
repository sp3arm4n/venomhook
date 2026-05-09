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

from dataclasses import dataclass
from html import escape
from pathlib import Path
from typing import Optional

from venomhook.android_pipeline import AndroidAnalysis
from venomhook.models import (
    AndroidAuditReport,
    AndroidComponent,
    CodeAuditReport,
    CodeFinding,
    JniBridge,
    ManifestFinding,
    PoCArtifact,
)
from venomhook.native_strings import NativeStringHints


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
                href = rel.as_posix()
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
        rows.append(("패키지", escape(app.package_name)))
    rows.append(("APK 파일", escape(apk.name)))
    rows.append(("SHA-256", escape(apk.hash)))
    if apk.abis:
        rows.append(("ABI 목록", ", ".join(escape(a) for a in apk.abis)))
    if analysis.selected_abi:
        rows.append(("분석된 ABI", escape(analysis.selected_abi)))
    if app:
        rows.append(("디버깅 가능", "예" if app.debuggable else "아니오"))
        rows.append(("백업 허용", "예" if app.allow_backup else "아니오"))
    so = analysis.so_meta
    if so:
        rows.append(("네이티브 라이브러리", f"{escape(so.name)} ({escape(so.format)}/{escape(so.arch)})"))
        rows.append(("네이티브 imports / exports", f"{len(so.imports)} / {len(so.exports)}"))
    if analysis.bridges:
        matched = sum(1 for b in analysis.bridges if b.matched_symbol)
        rows.append(("JNI 브리지", f"{matched}개 매칭 / {len(analysis.bridges)}개 선언"))
    return "<dl>" + "".join(f"<dt>{k}</dt><dd>{v}</dd>" for k, v in rows) + "</dl>"


_SEVERITY_LABEL_KO = {
    "critical": "심각",
    "high": "높음",
    "medium": "중간",
    "low": "낮음",
    "info": "정보",
}


def _render_severity_bar(report: AndroidAuditReport) -> str:
    counts: dict[str, int] = {}
    for f in report.findings:
        s = f.severity.lower()
        counts[s] = counts.get(s, 0) + 1
    if not counts:
        return '<div class="severity-bar"><span class="sev-chip sev-info"><span class="count">0</span> 건</span></div>'
    chips = []
    for sev in ("critical", "high", "medium", "low", "info"):
        n = counts.get(sev, 0)
        if n == 0:
            continue
        label = _SEVERITY_LABEL_KO.get(sev, sev)
        chips.append(
            f'<span class="sev-chip sev-{sev}">'
            f'<span class="count">{n}</span> {label}</span>'
        )
    chips.append(f'<span class="sev-chip"><span class="count">{len(report.findings)}</span> 합계</span>')
    return '<div class="severity-bar">' + "".join(chips) + "</div>"


def _render_poc(link: _PocLink) -> str:
    a = link.artifact
    kind_label = escape(a.kind.upper())
    title = escape(a.title)
    file_link = ""
    if link.href is not None:
        file_link = (
            f'<a class="file-link" href="{escape(link.href, quote=True)}" '
            f'title="실행 가능 아티팩트 열기">{escape(Path(link.href).name)}</a>'
        )
    body_parts: list[str] = []
    if a.description:
        body_parts.append(f"<p>{escape(a.description)}</p>")
    if a.commands:
        cmd_text = "\n".join(a.commands)
        body_parts.append(f"<pre>{escape(cmd_text)}</pre>")
    if a.expected_evidence:
        body_parts.append(
            f"<p><strong>예상 결과:</strong> {escape(a.expected_evidence)}</p>"
        )
    if a.notes:
        body_parts.append(f"<p><strong>비고:</strong> {escape(a.notes)}</p>")
    if a.references:
        body_parts.append(
            "<p><strong>참고:</strong> "
            + ", ".join(escape(r) for r in a.references)
            + "</p>"
        )
    body_html = "".join(body_parts) or "<p><em>(내용이 기록되지 않았습니다)</em></p>"
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
    sev_label = escape(_SEVERITY_LABEL_KO.get(finding.severity.lower(), finding.severity).upper())
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
            '<div class="description"><strong>대응 방안:</strong> '
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
            f'<h4>개념 증명(PoC) {len(pocs)}건</h4>'
            f'{items}'
            f"</div>"
        )
    else:
        poc_section = (
            '<div class="pocs">'
            '<h4>개념 증명(PoC) 0건</h4>'
            '<p style="color: var(--text-muted); font-size: 0.85em; margin: 4px 0;">'
            '본 룰에는 자동 생성된 PoC 아티팩트가 없습니다. 수동 검토가 필요합니다.'
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


def _code_sev_sort_key(finding: CodeFinding) -> tuple[int, str, str, int]:
    return (
        _SEVERITY_ORDER.get(finding.severity.lower(), 9),
        finding.rule_id,
        finding.file,
        finding.line_no,
    )


def _render_code_finding_card(
    finding: CodeFinding,
    pocs: list[_PocLink],
) -> str:
    sev_cls = _severity_class(finding.severity)
    sev_label = escape(_SEVERITY_LABEL_KO.get(finding.severity.lower(), finding.severity).upper())
    rule_id = escape(finding.rule_id)
    title = escape(finding.title)
    location = ""
    if finding.file:
        loc = f"{finding.file}:{finding.line_no}" if finding.line_no else finding.file
        location = f'<span class="component">{escape(loc)}</span>'
    body_parts: list[str] = []
    if finding.detail:
        body_parts.append(f'<div class="description">{escape(finding.detail)}</div>')
    if finding.line_text:
        body_parts.append(
            '<div class="description"><strong>코드 단서:</strong> '
            f'<code>{escape(finding.line_text[:240])}</code></div>'
        )
    if finding.remediation:
        body_parts.append(
            '<div class="description"><strong>대응 방안:</strong> '
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
            f'<h4>개념 증명(PoC) {len(pocs)}건</h4>'
            f'{items}'
            f"</div>"
        )
    return (
        f'<article class="finding {sev_cls}">'
        f'<header>'
        f'<span class="sev-tag">{sev_label}</span>'
        f'<span class="rule-id">{rule_id}</span>'
        f'<h3>{title}</h3>'
        f'{location}'
        f"</header>"
        f"{desc}"
        f"{refs}"
        f"{poc_section}"
        f"</article>"
    )


def _render_code_findings_section(
    report: CodeAuditReport,
    poc_index: dict,
) -> str:
    """Render the Phase 7 code-audit section. Returns "" when no findings."""
    if not report or not report.findings:
        return ""
    sorted_findings = sorted(report.findings, key=_code_sev_sort_key)
    cards: list[str] = []
    for f in sorted_findings:
        # Code finding "component" for PoC matching is the class FQN.
        key = (f.rule_id, f.class_fqn or None)
        cards.append(_render_code_finding_card(f, poc_index.get(key, [])))

    counts = report.severity_counts
    sev_chips: list[str] = []
    for sev in ("critical", "high", "medium", "low", "info"):
        n = counts.get(sev, 0)
        if not n:
            continue
        label = _SEVERITY_LABEL_KO.get(sev, sev)
        sev_chips.append(
            f'<span class="sev-chip sev-{sev}">'
            f'<span class="count">{n}</span> {escape(label)}</span>'
        )
    sev_chips.append(
        f'<span class="sev-chip"><span class="count">{len(report.findings)}</span> 합계</span>'
    )
    sev_bar = f'<div class="severity-bar">{" ".join(sev_chips)}</div>'
    return (
        '<section class="findings-section">'
        f'<h2>코드 감사 ({len(report.findings)}건 / 스캔 {report.files_scanned}개 파일)</h2>'
        f'{sev_bar}'
        + "".join(cards)
        + "</section>"
    )


def _render_native_strings_section(hints: NativeStringHints) -> str:
    """Render the Phase 7-3 native string-hints section. Returns "" when empty."""
    if hints is None or hints.is_empty:
        return ""

    def _list_block(label: str, items: list[str]) -> str:
        if not items:
            return ""
        # Cap visible items in HTML even if data has up to 50; review can
        # consult JSON if needed.
        head = items[:20]
        more = (
            f'<div style="color: var(--text-muted); font-size: 0.82em;">'
            f'…외 {len(items) - len(head)}개 더 (전체는 JSON 보고서 참고)</div>'
            if len(items) > len(head) else ""
        )
        rows = "".join(
            f'<li><code>{escape(s[:200])}</code></li>' for s in head
        )
        return (
            '<div class="finding sev-info" style="margin-bottom: 12px;">'
            f'<header><h3>{escape(label)} ({len(items)}건)</h3></header>'
            f'<ul style="margin: 8px 0 0 20px;">{rows}</ul>'
            f'{more}'
            "</div>"
        )

    blocks = [
        _list_block("URL 임베디드", hints.urls),
        _list_block("IP 리터럴", hints.ip_endpoints),
        _list_block("민감 경로", hints.paths),
        _list_block("쉘/실행 단서", hints.shell_commands),
        _list_block("Crypto 알고리즘 단서", hints.crypto),
        _list_block("자격증명 키 힌트", hints.secret_hints),
        _list_block("SQL 단편", hints.sql),
        _list_block("디버그 / 자산 경로", hints.debug),
    ]
    return (
        '<section class="findings-section">'
        f'<h2>네이티브 라이브러리 문자열 단서 ({hints.total}건)</h2>'
        + "".join(blocks)
        + "</section>"
    )


def _render_components_table(components: list[AndroidComponent]) -> str:
    if not components:
        return ""
    type_korean = {
        "activity": "액티비티",
        "service": "서비스",
        "receiver": "리시버",
        "provider": "프로바이더",
    }
    rows = []
    for c in components:
        exported_html = (
            '<span class="yes">예</span>' if c.exported
            else '<span class="no">아니오</span>'
        )
        perm = escape(c.permission) if c.permission else "—"
        intents = (
            ", ".join(escape(a) for a in c.intent_actions[:3])
            + ("…" if len(c.intent_actions) > 3 else "")
        ) if c.intent_actions else "—"
        rows.append(
            f"<tr>"
            f"<td>{escape(type_korean.get(c.type, c.type))}</td>"
            f'<td class="fqn">{escape(c.name)}</td>'
            f"<td>{exported_html}</td>"
            f"<td>{perm}</td>"
            f'<td class="mono">{intents}</td>'
            f"</tr>"
        )
    return (
        '<table class="tbl">'
        "<thead><tr><th>종류</th><th>이름</th><th>외부 노출</th><th>권한</th><th>intent-filter 액션</th></tr></thead>"
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
            '<span class="no">미매칭</span>'
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
            f"전체 {len(bridges)}개 중 상위 {limit}개 표시 "
            f"({len(matched)}개 매칭 우선). 전체 목록은 JSON 결과에서 확인하세요.</p>"
        )
    return (
        '<table class="tbl">'
        "<thead><tr><th>Java 메서드</th><th>인자 수</th><th>매칭된 네이티브 심볼</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody>"
        "</table>"
        f"{note}"
    )


def _render_warnings(warnings: list[str]) -> str:
    if not warnings:
        return ""
    items = "".join(f"<li>{escape(w)}</li>" for w in warnings)
    return f'<div class="warnings"><strong>경고</strong><ul>{items}</ul></div>'


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
    title_html = escape(title) if title else "VenomHook 감사 보고서"
    poc_index = _group_pocs_by_finding(
        list(analysis.pocs),
        Path(poc_bundle_dir) if poc_bundle_dir else None,
        Path(out_path) if out_path else None,
    )

    findings_html_parts: list[str] = []
    audit = analysis.audit_report
    rendered_keys: set[tuple[str, Optional[str]]] = set()
    if audit:
        sorted_findings = sorted(audit.findings, key=_sev_sort_key)
        for finding in sorted_findings:
            key = _finding_key(finding.rule_id, finding.component)
            pocs_for_this = poc_index.get(key, [])
            rendered_keys.add(key)
            findings_html_parts.append(
                _render_finding_card(finding, pocs_for_this)
            )

    # 방어적 처리: (rule_id, component)으로 finding과 매칭되지 않은 PoC를
    # 보고서에서 누락시키지 않도록 별도 섹션으로 노출. poc_generator와
    # manifest_audit가 룰의 컴포넌트/앱-레벨 분류에서 의견이 갈릴 때 발동.
    # 운영자가 "PoC가 왜 없지"라고 의심하기보다 직접 확인할 수 있도록 표시.
    orphan_html = ""
    orphan_keys = [k for k in poc_index.keys() if k not in rendered_keys]
    if orphan_keys:
        orphan_html_parts: list[str] = [
            '<div class="warnings" style="margin-top: 16px;">'
            "<strong>매칭되지 않은 PoC 아티팩트</strong>"
            '<p style="margin: 6px 0 0 0; font-size: 0.88em;">'
            "(rule_id, component) 기준으로 어떤 finding과도 매칭되지 않은 "
            "PoC들입니다. 번들 누락 방지를 위해 별도 표시 — 룰이 컴포넌트별 "
            "finding을 생성해야 하는지 또는 PoC가 앱-레벨이어야 하는지 검토가 "
            "필요합니다."
            "</p></div>"
        ]
        for key in sorted(orphan_keys, key=lambda k: (k[0], k[1] or "")):
            for link in poc_index[key]:
                orphan_html_parts.append(_render_poc(link))
        orphan_html = "".join(orphan_html_parts)

    findings_section = (
        f'<section class="findings-section">'
        f"<h2>탐지된 취약점 ({len(audit.findings) if audit else 0}건)</h2>"
        f"{_render_severity_bar(audit) if audit else ''}"
        + ("".join(findings_html_parts) or
           '<p style="color: var(--text-muted);">탐지된 취약점이 없습니다.</p>')
        + orphan_html
        + "</section>"
    )

    code_findings_section = ""
    if analysis.code_audit_report:
        code_findings_section = _render_code_findings_section(
            analysis.code_audit_report, poc_index
        )

    native_strings_section = ""
    if analysis.native_string_hints is not None:
        native_strings_section = _render_native_strings_section(
            analysis.native_string_hints
        )

    components_section = ""
    if analysis.app_meta and analysis.app_meta.components:
        components_section = (
            '<section class="components-section">'
            f"<h2>컴포넌트 ({len(analysis.app_meta.components)}개)</h2>"
            f"{_render_components_table(analysis.app_meta.components)}"
            "</section>"
        )

    bridges_section = ""
    if analysis.bridges:
        matched_count = sum(1 for b in analysis.bridges if b.matched_symbol)
        bridges_section = (
            '<section class="bridges-section">'
            f"<h2>JNI 브리지 ({matched_count}개 매칭 / {len(analysis.bridges)}개 선언)</h2>"
            f"{_render_bridges_table(analysis.bridges)}"
            "</section>"
        )

    warnings_html = _render_warnings(list(analysis.warnings))

    return (
        '<!doctype html>'
        '<html lang="ko">'
        '<head>'
        '<meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{title_html}</title>"
        f"<style>{_CSS}</style>"
        "</head>"
        '<body><div class="container">'
        '<header class="report-head">'
        f"<h1>{title_html}</h1>"
        '<div class="subtitle">VenomHook android-audit 보고서</div>'
        f"{_render_summary_dl(analysis)}"
        "</header>"
        f"{warnings_html}"
        f"{findings_section}"
        f"{code_findings_section}"
        f"{native_strings_section}"
        f"{components_section}"
        f"{bridges_section}"
        '<footer>VenomHook이 생성한 자체 포함 보고서 · 모든 브라우저에서 바로 열림 · JavaScript / 외부 자산 불필요</footer>'
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

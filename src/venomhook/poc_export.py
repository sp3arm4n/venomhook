"""Export PoCArtifact bundles to runnable on-disk scripts.

Phase 3 / Unit 5. Turns the in-memory artifact list produced by
poc_generator.generate_pocs into a directory of ready-to-execute shell
scripts plus a README index, suitable for:

  - dropping into a CTF / pentest engagement folder
  - committing alongside the audit JSON for later replay
  - shipping to a separate testing host

Each adb/shell artifact becomes a single .sh file with a header comment
block (rule, severity, package, description, expected evidence, notes,
references) followed by the raw commands. The script is executable
(chmod 755) so the operator can run it directly:

    bash pocs/MANIFEST-001-1_attach-jdb-to-debuggable-process.sh

Frida-kind artifacts are written as .frida.js stubs; informational
artifacts as .md notes. Only adb/shell are emitted today (poc_generator
v1 does not produce other kinds), but the dispatch covers them so the
contract is stable.

Pure file I/O — no subprocess, no network. Safe to run in CI as a
post-audit step.
"""

from __future__ import annotations

import re
import stat
from pathlib import Path

from venomhook.models import PoCArtifact


__all__ = [
    "export_pocs",
    "render_sh",
    "render_index",
    "slugify",
]


_SLUG_RE = re.compile(r"[^a-z0-9]+")


def slugify(text: str, *, max_len: int = 60) -> str:
    """Lowercase, hyphen-joined slug suitable for a filename component."""
    s = _SLUG_RE.sub("-", text.lower()).strip("-")
    if len(s) > max_len:
        s = s[:max_len].rstrip("-")
    return s or "artifact"


def _filename_for(idx: int, artifact: PoCArtifact) -> str:
    """{rule_id}-{idx}_{slug}.{ext} — sortable and identifies kind via ext."""
    ext = {
        "adb": "sh",
        "shell": "sh",
        "frida": "frida.js",
        "info": "md",
    }.get(artifact.kind, "txt")
    slug = slugify(artifact.title)
    return f"{artifact.rule_id}-{idx}_{slug}.{ext}"


def _comment_block(artifact: PoCArtifact, prefix: str = "# ") -> list[str]:
    """Header comment block shared by sh/frida renderers (different prefixes)."""
    lines = [
        f"{prefix}venomhook PoC 아티팩트",
        f"{prefix}룰:        {artifact.rule_id}",
        f"{prefix}제목:      {artifact.title}",
        f"{prefix}심각도:    {artifact.severity}",
        f"{prefix}종류:      {artifact.kind}",
        f"{prefix}패키지:    {artifact.package_name}",
    ]
    if artifact.component:
        lines.append(f"{prefix}컴포넌트:  {artifact.component}")
    if artifact.description:
        lines.append(f"{prefix}")
        for ln in artifact.description.splitlines():
            lines.append(f"{prefix}{ln}")
    if artifact.expected_evidence:
        lines.append(f"{prefix}")
        lines.append(f"{prefix}예상 결과:")
        for ln in artifact.expected_evidence.splitlines():
            lines.append(f"{prefix}  {ln}")
    if artifact.notes:
        lines.append(f"{prefix}")
        lines.append(f"{prefix}비고:")
        for ln in artifact.notes.splitlines():
            lines.append(f"{prefix}  {ln}")
    if artifact.references:
        lines.append(f"{prefix}")
        lines.append(f"{prefix}참고: {', '.join(artifact.references)}")
    return lines


def render_sh(artifact: PoCArtifact) -> str:
    """Render an adb/shell artifact as a runnable POSIX shell script."""
    lines = ["#!/bin/sh", "# shellcheck disable=SC2086"]
    lines.extend(_comment_block(artifact, prefix="# "))
    lines.append("")
    lines.append("set -u")
    lines.append("")
    if not artifact.commands:
        lines.append("echo '본 아티팩트에 기록된 명령이 없습니다'")
    else:
        lines.extend(artifact.commands)
    return "\n".join(lines) + "\n"


def _render_frida(artifact: PoCArtifact) -> str:
    """Render a frida-kind artifact as a .frida.js stub."""
    lines = ["// venomhook PoC — Frida 스크립트"]
    lines.extend(_comment_block(artifact, prefix="// "))
    lines.append("")
    if not artifact.commands:
        lines.append("// (스크립트 본문이 기록되지 않았습니다)")
    else:
        lines.extend(artifact.commands)
    return "\n".join(lines) + "\n"


def _render_info(artifact: PoCArtifact) -> str:
    """Render an info-kind artifact as a markdown note (no executable parts)."""
    parts = [f"# {artifact.rule_id} — {artifact.title}", ""]
    parts.append(f"- **심각도:** {artifact.severity}")
    parts.append(f"- **패키지:** {artifact.package_name}")
    if artifact.component:
        parts.append(f"- **컴포넌트:** {artifact.component}")
    if artifact.references:
        parts.append(f"- **참고:** {', '.join(artifact.references)}")
    if artifact.description:
        parts.extend(["", artifact.description])
    if artifact.commands:
        parts.extend(["", "## 명령어", "", "```", *artifact.commands, "```"])
    if artifact.expected_evidence:
        parts.extend(["", "## 예상 결과", "", artifact.expected_evidence])
    if artifact.notes:
        parts.extend(["", "## 비고", "", artifact.notes])
    return "\n".join(parts) + "\n"


_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def render_index(artifacts: list[PoCArtifact], filenames: list[str]) -> str:
    """Markdown README listing every exported artifact, grouped by finding.

    Artifacts that share the same ``(rule_id, component)`` belong to the
    same parent finding; they are rendered under one heading so the
    operator can see at a glance which PoCs prove which finding instead
    of scanning a flat ordered list. Findings are ordered by severity
    (critical → info), then by rule_id, then by component.
    """
    lines = [
        "# venomhook PoC 번들",
        "",
        f"_아티팩트 {len(artifacts)}개_",
        "",
    ]

    # Group artifacts by (rule_id, component); preserve original index so
    # the {idx}_ prefix lookup stays correct.
    groups: dict[tuple[str, str | None], list[tuple[int, PoCArtifact, str]]] = {}
    for idx, (a, fn) in enumerate(zip(artifacts, filenames), 1):
        key = (a.rule_id, a.component)
        groups.setdefault(key, []).append((idx, a, fn))

    def _group_sort_key(item: tuple[tuple[str, str | None], list]) -> tuple:
        (rule_id, component), entries = item
        # Severity inherited from the first artifact in the group; PoC
        # artifacts in a single finding share the same severity.
        sev = entries[0][1].severity.lower()
        return (_SEV_ORDER.get(sev, 9), rule_id, component or "")

    if not groups:
        lines.append("_아티팩트가 없습니다._")
        return "\n".join(lines) + "\n"

    n_findings = len(groups)
    lines[2] = (
        f"_아티팩트 {len(artifacts)}개 (취약점 {n_findings}건 기준)_"
    )

    lines.append("## 목차")
    lines.append("")

    for (rule_id, component), entries in sorted(groups.items(), key=_group_sort_key):
        sev = entries[0][1].severity.upper()
        title = entries[0][1].title
        # The first artifact's title often duplicates a finding-level
        # description; downstream PoCs in the same group may have their
        # own per-recipe titles. Use the rule_id + component as the
        # canonical group label so it stays stable.
        comp_suffix = f" [`{component}`]" if component else ""
        lines.append(f"### [{sev}] {rule_id}{comp_suffix}")
        lines.append("")
        lines.append(f"_{title}_" if title else "")
        lines.append("")
        lines.append("| # | 종류 | 레시피 | 파일 |")
        lines.append("|---|------|--------|------|")
        for idx, a, fn in entries:
            lines.append(
                f"| {idx} | {a.kind} | {a.title} | "
                f"[`{fn}`](./{fn}) |"
            )
        lines.append("")

    lines.append(
        "각 .sh 파일은 자체 포함된 실행 가능 스크립트입니다. 실제 프로세스 / 단말 "
        "저장소를 건드리므로, 통제된 테스트 대상에서만 운영자의 명시적 동의 하에 "
        "실행하세요. 실행 전 헤더 주석을 반드시 확인합니다."
    )
    return "\n".join(lines) + "\n"


def export_pocs(artifacts: list[PoCArtifact], out_dir: str | Path) -> list[Path]:
    """Write every artifact to a file under ``out_dir`` and return the paths.

    Creates ``out_dir`` if missing. Existing files are overwritten. A
    README.md index is written last so it always reflects the current
    bundle. Shell scripts are made executable (mode 0o755).
    """
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    written: list[Path] = []
    filenames: list[str] = []

    for i, artifact in enumerate(artifacts, 1):
        fn = _filename_for(i, artifact)
        path = out / fn
        if artifact.kind in ("adb", "shell"):
            path.write_text(render_sh(artifact))
            path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        elif artifact.kind == "frida":
            path.write_text(_render_frida(artifact))
        elif artifact.kind == "info":
            path.write_text(_render_info(artifact))
        else:
            # Unknown kind — fall through to a plain text dump so nothing
            # is silently dropped.
            path.write_text(_render_info(artifact))
        written.append(path)
        filenames.append(fn)

    index_path = out / "README.md"
    index_path.write_text(render_index(artifacts, filenames))
    written.append(index_path)
    return written

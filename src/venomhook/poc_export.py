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
        f"{prefix}venomhook PoC artifact",
        f"{prefix}rule:        {artifact.rule_id}",
        f"{prefix}title:       {artifact.title}",
        f"{prefix}severity:    {artifact.severity}",
        f"{prefix}kind:        {artifact.kind}",
        f"{prefix}package:     {artifact.package_name}",
    ]
    if artifact.component:
        lines.append(f"{prefix}component:   {artifact.component}")
    if artifact.description:
        lines.append(f"{prefix}")
        for ln in artifact.description.splitlines():
            lines.append(f"{prefix}{ln}")
    if artifact.expected_evidence:
        lines.append(f"{prefix}")
        lines.append(f"{prefix}expected evidence:")
        for ln in artifact.expected_evidence.splitlines():
            lines.append(f"{prefix}  {ln}")
    if artifact.notes:
        lines.append(f"{prefix}")
        lines.append(f"{prefix}notes:")
        for ln in artifact.notes.splitlines():
            lines.append(f"{prefix}  {ln}")
    if artifact.references:
        lines.append(f"{prefix}")
        lines.append(f"{prefix}references: {', '.join(artifact.references)}")
    return lines


def render_sh(artifact: PoCArtifact) -> str:
    """Render an adb/shell artifact as a runnable POSIX shell script."""
    lines = ["#!/bin/sh", "# shellcheck disable=SC2086"]
    lines.extend(_comment_block(artifact, prefix="# "))
    lines.append("")
    lines.append("set -u")
    lines.append("")
    if not artifact.commands:
        lines.append("echo 'no commands recorded for this artifact'")
    else:
        lines.extend(artifact.commands)
    return "\n".join(lines) + "\n"


def _render_frida(artifact: PoCArtifact) -> str:
    """Render a frida-kind artifact as a .frida.js stub."""
    lines = ["// venomhook PoC — frida script"]
    lines.extend(_comment_block(artifact, prefix="// "))
    lines.append("")
    if not artifact.commands:
        lines.append("// (no script body recorded)")
    else:
        lines.extend(artifact.commands)
    return "\n".join(lines) + "\n"


def _render_info(artifact: PoCArtifact) -> str:
    """Render an info-kind artifact as a markdown note (no executable parts)."""
    parts = [f"# {artifact.rule_id} — {artifact.title}", ""]
    parts.append(f"- **severity:** {artifact.severity}")
    parts.append(f"- **package:** {artifact.package_name}")
    if artifact.component:
        parts.append(f"- **component:** {artifact.component}")
    if artifact.references:
        parts.append(f"- **references:** {', '.join(artifact.references)}")
    if artifact.description:
        parts.extend(["", artifact.description])
    if artifact.commands:
        parts.extend(["", "## Commands", "", "```", *artifact.commands, "```"])
    if artifact.expected_evidence:
        parts.extend(["", "## Expected evidence", "", artifact.expected_evidence])
    if artifact.notes:
        parts.extend(["", "## Notes", "", artifact.notes])
    return "\n".join(parts) + "\n"


def render_index(artifacts: list[PoCArtifact], filenames: list[str]) -> str:
    """Markdown README listing each exported artifact in order."""
    lines = [
        "# venomhook PoC bundle",
        "",
        f"_{len(artifacts)} artifact{'s' if len(artifacts) != 1 else ''}_",
        "",
        "| # | rule | severity | kind | file |",
        "|---|------|----------|------|------|",
    ]
    for i, (a, fn) in enumerate(zip(artifacts, filenames), 1):
        lines.append(
            f"| {i} | {a.rule_id} | {a.severity} | {a.kind} | "
            f"[`{fn}`](./{fn}) |"
        )
    lines.append("")
    lines.append(
        "Each .sh file is self-contained and runnable. Review the header "
        "comment before executing — recipes touch live processes / device "
        "storage and require operator consent on a controlled test target."
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

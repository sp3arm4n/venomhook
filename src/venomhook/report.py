from __future__ import annotations

from pathlib import Path
from typing import Iterable

from venomhook.models import HookSpec


def render_markdown(specs: Iterable[HookSpec]) -> str:
    rows = []
    for spec in specs:
        tags = ", ".join(spec.tags) if spec.tags else "-"
        name = spec.name or "-"
        sig = spec.sig or "-"
        rows.append(f"| {spec.module} | {spec.arch} | {hex(spec.offset)} | {name} | {tags} | {sig} |")

    table = "\n".join(
        [
            "| module | arch | offset | name | tags | sig |",
            "| --- | --- | --- | --- | --- | --- |",
            *rows,
        ]
    )
    return "\n".join(
        [
            "# HookSpec Summary",
            "",
            table,
            "",
            f"총 {len(rows)}개 엔트리",
        ]
    )


def write_markdown(specs: Iterable[HookSpec], path: Path) -> None:
    content = render_markdown(specs)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")

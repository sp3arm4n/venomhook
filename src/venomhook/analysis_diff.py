"""Diff two AndroidAnalysis records to surface what changed between runs.

Phase 4 / Unit 4. Sits on top of the analysis_cache layer: with two
cached analyses (e.g., v1.0 and v1.1 of the same APK, or yesterday's
and today's run of the same hash) the operator wants to know what
changed without re-reading the full payloads side by side.

Identity rules:
    finding identity     = (rule_id, component)
    poc identity         = (rule_id, kind, title, component)
    bridge identity      = (java_method)

Diff output is structured (``AnalysisDiff`` dataclass) for programmatic
use, plus a ``format_diff_text`` renderer for terminal display.

Pure data transformation — no I/O, no subprocess.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from venomhook.android_pipeline import AndroidAnalysis
from venomhook.models import ManifestFinding, PoCArtifact


__all__ = [
    "AnalysisDiff",
    "diff_analyses",
    "format_diff_text",
]


def _finding_key(f: ManifestFinding) -> tuple[str, Optional[str]]:
    return (f.rule_id, f.component)


def _poc_key(p: PoCArtifact) -> tuple[str, str, str, Optional[str]]:
    return (p.rule_id, p.kind, p.title, p.component)


@dataclass
class AnalysisDiff:
    """Structured comparison between two AndroidAnalysis snapshots.

    Both ``old`` and ``new`` references are kept so the renderer can
    surface contextual metadata (apk_name, hash, created-at if known).
    The lists carry the raw dataclass instances from the *new* analysis
    when describing additions, and from the *old* one when describing
    removals.
    """

    old_apk_hash: str
    new_apk_hash: str
    old_package: Optional[str]
    new_package: Optional[str]

    added_findings: list[ManifestFinding] = field(default_factory=list)
    removed_findings: list[ManifestFinding] = field(default_factory=list)
    unchanged_findings: list[ManifestFinding] = field(default_factory=list)

    added_pocs: list[PoCArtifact] = field(default_factory=list)
    removed_pocs: list[PoCArtifact] = field(default_factory=list)

    added_exports: list[str] = field(default_factory=list)
    removed_exports: list[str] = field(default_factory=list)

    added_bridges: list[str] = field(default_factory=list)   # java_method strings
    removed_bridges: list[str] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return any((
            self.added_findings, self.removed_findings,
            self.added_pocs, self.removed_pocs,
            self.added_exports, self.removed_exports,
            self.added_bridges, self.removed_bridges,
            self.old_apk_hash != self.new_apk_hash,
            self.old_package != self.new_package,
        ))

    def to_dict(self) -> dict[str, Any]:
        return {
            "old_apk_hash": self.old_apk_hash,
            "new_apk_hash": self.new_apk_hash,
            "old_package": self.old_package,
            "new_package": self.new_package,
            "added_findings": [f.to_dict() for f in self.added_findings],
            "removed_findings": [f.to_dict() for f in self.removed_findings],
            "unchanged_findings": [f.to_dict() for f in self.unchanged_findings],
            "added_pocs": [p.to_dict() for p in self.added_pocs],
            "removed_pocs": [p.to_dict() for p in self.removed_pocs],
            "added_exports": list(self.added_exports),
            "removed_exports": list(self.removed_exports),
            "added_bridges": list(self.added_bridges),
            "removed_bridges": list(self.removed_bridges),
        }


def diff_analyses(old: AndroidAnalysis, new: AndroidAnalysis) -> AnalysisDiff:
    """Return the structured difference of ``new`` minus ``old``.

    Both arguments must be AndroidAnalysis. Sections that are absent in
    one side (e.g., audit_report None because apktool was unavailable)
    are treated as empty for comparison purposes — additions/removals
    against an empty side surface as full lists.
    """
    old_findings = old.audit_report.findings if old.audit_report else []
    new_findings = new.audit_report.findings if new.audit_report else []
    old_keys = {_finding_key(f): f for f in old_findings}
    new_keys = {_finding_key(f): f for f in new_findings}

    added_findings = [new_keys[k] for k in new_keys if k not in old_keys]
    removed_findings = [old_keys[k] for k in old_keys if k not in new_keys]
    unchanged_findings = [new_keys[k] for k in new_keys if k in old_keys]

    old_poc_keys = {_poc_key(p): p for p in old.pocs}
    new_poc_keys = {_poc_key(p): p for p in new.pocs}
    added_pocs = [new_poc_keys[k] for k in new_poc_keys if k not in old_poc_keys]
    removed_pocs = [old_poc_keys[k] for k in old_poc_keys if k not in new_poc_keys]

    old_exports = set(old.so_meta.exports) if old.so_meta else set()
    new_exports = set(new.so_meta.exports) if new.so_meta else set()
    added_exports = sorted(new_exports - old_exports)
    removed_exports = sorted(old_exports - new_exports)

    def _bridge_id(b) -> str:
        m = b.java_method
        return f"{m.class_fqn}.{m.method_name}"

    old_bridges = {_bridge_id(b) for b in old.bridges}
    new_bridges = {_bridge_id(b) for b in new.bridges}
    added_bridges = sorted(new_bridges - old_bridges)
    removed_bridges = sorted(old_bridges - new_bridges)

    return AnalysisDiff(
        old_apk_hash=old.apk_meta.hash,
        new_apk_hash=new.apk_meta.hash,
        old_package=old.app_meta.package_name if old.app_meta else None,
        new_package=new.app_meta.package_name if new.app_meta else None,
        added_findings=added_findings,
        removed_findings=removed_findings,
        unchanged_findings=unchanged_findings,
        added_pocs=added_pocs,
        removed_pocs=removed_pocs,
        added_exports=added_exports,
        removed_exports=removed_exports,
        added_bridges=added_bridges,
        removed_bridges=removed_bridges,
    )


def format_diff_text(diff: AnalysisDiff) -> str:
    """Terminal-friendly rendering of an AnalysisDiff."""
    lines: list[str] = []
    lines.append(
        f"AndroidAnalysis diff — {diff.old_apk_hash[:24]}... -> "
        f"{diff.new_apk_hash[:24]}..."
    )
    if diff.old_package != diff.new_package:
        lines.append(f"  package: {diff.old_package} -> {diff.new_package}")
    elif diff.new_package:
        lines.append(f"  package: {diff.new_package}")

    if not diff.has_changes:
        lines.append("  (no changes)")
        return "\n".join(lines) + "\n"

    def _section(title: str, items: list, render):
        if not items:
            return
        lines.append("")
        lines.append(f"{title} ({len(items)})")
        for it in items:
            lines.append(f"  {render(it)}")

    _section(
        "+ Findings added", diff.added_findings,
        lambda f: f"[{f.severity.upper()}] {f.rule_id} {f.title}"
                   + (f" [{f.component}]" if f.component else ""),
    )
    _section(
        "- Findings removed", diff.removed_findings,
        lambda f: f"[{f.severity.upper()}] {f.rule_id} {f.title}"
                   + (f" [{f.component}]" if f.component else ""),
    )
    _section(
        "+ PoCs added", diff.added_pocs,
        lambda p: f"[{p.severity.upper()}] {p.rule_id} ({p.kind}) {p.title}",
    )
    _section(
        "- PoCs removed", diff.removed_pocs,
        lambda p: f"[{p.severity.upper()}] {p.rule_id} ({p.kind}) {p.title}",
    )
    _section("+ Exports added", diff.added_exports, lambda s: s)
    _section("- Exports removed", diff.removed_exports, lambda s: s)
    _section("+ JNI bridges added", diff.added_bridges, lambda s: s)
    _section("- JNI bridges removed", diff.removed_bridges, lambda s: s)

    return "\n".join(lines) + "\n"

"""Rule-to-category taxonomy for cross-rule grouping.

Phase 9-3 introduces a single source of truth that maps every audit
rule (MANIFEST-* / CODE-* and, in future phases, PE-* / PE-IMP-*) to
the higher-level category framework appropriate to its platform —
OWASP MASVS for Android, CWE Top 25 / Microsoft Security Baseline
for Windows when Phase 8 lands.

The HTML report (and any other consumer that wants to group findings
beyond severity sort) reads ``CATEGORY_BY_RULE`` and the helper
``categorize_findings`` to bucket findings under their category.

The mapping is intentionally narrow and additive — when a rule has
no taxonomy entry the helper returns ``None`` and the HTML omits the
unclassified rule from the category overview rather than guessing.
This keeps the audit report honest about coverage of the framework
even when rule_ids don't yet have a stable mapping.

Data only — no rendering logic. Pure-Python.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional


__all__ = [
    "Category",
    "CATEGORY_BY_RULE",
    "category_for",
    "categorize_findings",
    "CategoryGroup",
]


@dataclass(frozen=True)
class Category:
    """A taxonomy bucket — e.g. ``MASVS-NETWORK-1``.

    ``key`` is the canonical short identifier used as a stable map
    key (HTML anchor targets, JSON serialisation). ``label`` is the
    human-readable form for headers. ``framework`` lets the renderer
    group multiple categories under their parent (MASVS, CWE, etc.)
    when the report contains rules from multiple frameworks.
    """

    key: str
    label: str
    framework: str


# OWASP MASVS v2 buckets we map Android rules into. MASVS uses dotted
# control IDs internally (MASVS-NETWORK-1) but for display we use the
# short bucket name ("Network Communication"), keeping the dotted ID
# inside ``key`` for stable referencing.
_MASVS_NETWORK_1 = Category(
    "MASVS-NETWORK-1", "Network Communication (TLS / cleartext)", "MASVS",
)
_MASVS_PLATFORM_1 = Category(
    "MASVS-PLATFORM-1", "Platform Interaction (IPC / exported components)", "MASVS",
)
_MASVS_PLATFORM_2 = Category(
    "MASVS-PLATFORM-2", "Platform Interaction (WebView / debug)", "MASVS",
)
_MASVS_STORAGE_1 = Category(
    "MASVS-STORAGE-1", "Storage of Sensitive Data", "MASVS",
)
_MASVS_CRYPTO_1 = Category(
    "MASVS-CRYPTO-1", "Cryptographic Primitives", "MASVS",
)
_MASVS_PRIVACY_1 = Category(
    "MASVS-PRIVACY-1", "User Data Handling (permissions)", "MASVS",
)
_MASVS_PRIVACY_2 = Category(
    "MASVS-PRIVACY-2", "User Data Handling (logs / leaks)", "MASVS",
)
_MASVS_ARCH_9 = Category(
    "MASVS-ARCH-9", "Architecture / SDK level", "MASVS",
)
_MASVS_RESILIENCE_1 = Category(
    "MASVS-RESILIENCE-1", "Anti-tamper / Anti-debug posture", "MASVS",
)


# Rule → category map. Only Android rules today; PE-* / PE-IMP-* will
# add CWE entries when Phase 8 lands.
CATEGORY_BY_RULE: dict[str, Category] = {
    # Manifest rules
    "MANIFEST-001": _MASVS_RESILIENCE_1,    # debuggable=true
    "MANIFEST-002": _MASVS_NETWORK_1,       # cleartext (explicit / NSC base / NSC domain / implicit)
    "MANIFEST-003": _MASVS_STORAGE_1,       # allowBackup
    "MANIFEST-004": _MASVS_PLATFORM_1,      # exported component without permission
    "MANIFEST-005": _MASVS_PLATFORM_1,      # exported provider
    "MANIFEST-006": _MASVS_PLATFORM_1,      # grantUriPermissions
    "MANIFEST-007": _MASVS_PRIVACY_1,       # dangerous permissions
    "MANIFEST-008": _MASVS_ARCH_9,          # min_sdk too low
    "MANIFEST-009": _MASVS_ARCH_9,          # target_sdk too low
    "MANIFEST-010": _MASVS_NETWORK_1,       # NSC user-cert trust
    # Code rules
    "CODE-001": _MASVS_NETWORK_1,           # hardcoded http://
    "CODE-002": _MASVS_PLATFORM_2,          # WebView setJavaScriptEnabled / addJavascriptInterface
    "CODE-003": _MASVS_CRYPTO_1,            # weak cipher / MD5 / SHA1
    "CODE-004": _MASVS_PRIVACY_2,           # credentials in logs
    "CODE-005": _MASVS_STORAGE_1,           # external storage usage
    "CODE-006": _MASVS_STORAGE_1,           # MODE_WORLD_READABLE / WRITEABLE
}


def category_for(rule_id: str) -> Optional[Category]:
    """Return the taxonomy bucket for ``rule_id`` or ``None`` when
    the rule has no mapping yet.

    Callers should treat ``None`` as "uncategorized" rather than
    aborting — the rule still appears in the standard severity-sorted
    findings list, just without a category aggregate.
    """
    return CATEGORY_BY_RULE.get(rule_id)


@dataclass
class CategoryGroup:
    """One bucket of findings sharing a category, ordered by severity.

    ``finding_refs`` is a list of ``(rule_id, severity)`` tuples in
    canonical severity order, suitable for the HTML overview pane
    (which only needs to count and link, not render full cards).
    """

    category: Category
    finding_refs: list[tuple[str, str]]

    @property
    def count(self) -> int:
        return len(self.finding_refs)


_SEV_SORT = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def categorize_findings(
    findings: Iterable[object],
) -> list[CategoryGroup]:
    """Group findings by their ``rule_id``'s category.

    ``findings`` is iterable over any object with ``rule_id`` and
    ``severity`` attributes (ManifestFinding, CodeFinding, future
    PEFinding, etc.) — duck-typing avoids a dependency cycle on
    models.

    Output is ordered by category key, with each group's
    ``finding_refs`` ordered by severity rank (critical first).
    Uncategorized rules are omitted; callers wanting them must look
    at the raw ``findings`` list.
    """
    buckets: dict[str, CategoryGroup] = {}
    for f in findings:
        rule_id = getattr(f, "rule_id", None)
        sev = getattr(f, "severity", "info")
        if not rule_id:
            continue
        cat = category_for(rule_id)
        if cat is None:
            continue
        if cat.key not in buckets:
            buckets[cat.key] = CategoryGroup(category=cat, finding_refs=[])
        buckets[cat.key].finding_refs.append((rule_id, sev))

    for group in buckets.values():
        group.finding_refs.sort(key=lambda r: (_SEV_SORT.get(r[1], 99), r[0]))

    return [buckets[k] for k in sorted(buckets)]

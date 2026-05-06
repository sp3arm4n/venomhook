"""Manifest vulnerability audit — pure-Python rule engine over AndroidAppMeta.

Phase 2 / PR #11. Operates exclusively on data already extracted by
apk_decoder (PR #8) — no external tools, no subprocess, no network.
Each rule is a stateless function that takes an AndroidAppMeta and emits
zero-or-more ManifestFinding records. ``audit_manifest()`` runs the full
rule registry and returns an AndroidAuditReport.

The ruleset targets common AndroidManifest misconfigurations referenced by
OWASP MASVS (Mobile Application Security Verification Standard) and the
Android Application Security Cheat Sheet. Severity uses a 5-level scale
(critical / high / medium / low / info) so callers (CI gates, report
renderers) can apply uniform thresholds.

This module is intentionally additive: PoC generation, dynamic verification,
and DEX-level rules (e.g., implicit pending intents from smali analysis)
are out of scope for v1 and belong to Phase 3+.
"""

from __future__ import annotations

from typing import Callable

from venomhook.models import (
    AndroidAppMeta,
    AndroidAuditReport,
    ManifestFinding,
)


__all__ = [
    "audit_manifest",
    "format_audit_summary",
    "RULES",
    "DANGEROUS_PERMISSIONS",
    "MIN_RECOMMENDED_MIN_SDK",
    "MIN_RECOMMENDED_TARGET_SDK",
    # severity constants
    "SEV_CRITICAL",
    "SEV_HIGH",
    "SEV_MEDIUM",
    "SEV_LOW",
    "SEV_INFO",
]


# ---------- severity & SDK thresholds ----------


SEV_CRITICAL = "critical"
SEV_HIGH = "high"
SEV_MEDIUM = "medium"
SEV_LOW = "low"
SEV_INFO = "info"


MIN_RECOMMENDED_MIN_SDK = 23     # Android 6.0 — runtime permissions enforced
MIN_RECOMMENDED_TARGET_SDK = 30  # Android 11 — modern security defaults

# Android version inflection points that flip default attribute values.
TARGET_SDK_CLEARTEXT_DEFAULT_FALSE = 28  # API 28+ defaults usesCleartextTraffic to false
TARGET_SDK_ALLOW_BACKUP_DEFAULT_FALSE = 31  # API 31+ defaults allowBackup to false


# Android-defined dangerous permission groups (subset of those most often
# audited). Apps requesting these need runtime grant + user rationale on
# API 23+. The list is conservative; protectionLevel signature/normal perms
# are NOT included.
DANGEROUS_PERMISSIONS: frozenset[str] = frozenset({
    # SMS
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.RECEIVE_MMS",
    "android.permission.RECEIVE_WAP_PUSH",
    # Contacts / Calendar
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.GET_ACCOUNTS",
    "android.permission.READ_CALENDAR",
    "android.permission.WRITE_CALENDAR",
    # Phone & call log
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.CALL_PHONE",
    "android.permission.ANSWER_PHONE_CALLS",
    "android.permission.ADD_VOICEMAIL",
    "android.permission.USE_SIP",
    # Microphone & camera
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    # Location
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    # Storage (legacy — partly superseded by Scoped Storage)
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    # Sensors / Activity
    "android.permission.BODY_SENSORS",
    "android.permission.ACTIVITY_RECOGNITION",
})


# ---------- individual rules ----------


def _check_debuggable(meta: AndroidAppMeta) -> list[ManifestFinding]:
    if not meta.debuggable:
        return []
    return [ManifestFinding(
        rule_id="MANIFEST-001",
        title="Debuggable Application",
        severity=SEV_HIGH,
        detail=(
            "Application is marked android:debuggable=true. Anyone with adb access "
            "can attach a debugger, dump memory, and bypass anti-tamper logic."
        ),
        remediation=(
            "Remove android:debuggable or set it to false in production builds. "
            "Rely on build variant configuration so debug builds carry the flag and "
            "release builds don't."
        ),
        references=["OWASP MASVS-RESILIENCE-1", "CWE-489"],
    )]


def _check_cleartext_traffic(meta: AndroidAppMeta) -> list[ManifestFinding]:
    explicit = meta.uses_cleartext_traffic
    target = meta.target_sdk
    triggered = False
    detail = ""

    if explicit is True:
        triggered = True
        detail = (
            "android:usesCleartextTraffic=true is set explicitly. HTTP traffic is "
            "permitted, exposing the app to MITM interception and modification."
        )
    elif (
        explicit is None
        and target is not None
        and target < TARGET_SDK_CLEARTEXT_DEFAULT_FALSE
        and meta.network_security_config is None
    ):
        triggered = True
        detail = (
            f"targetSdk={target} (<28) and neither usesCleartextTraffic nor a "
            "Network Security Config is specified; the platform default permits HTTP."
        )

    if not triggered:
        return []
    return [ManifestFinding(
        rule_id="MANIFEST-002",
        title="Cleartext Traffic Permitted",
        severity=SEV_HIGH,
        detail=detail,
        remediation=(
            "Set android:usesCleartextTraffic=false and serve all traffic over HTTPS. "
            "Define a Network Security Config (res/xml/network_security_config.xml) "
            "for narrow exceptions if absolutely required."
        ),
        references=["OWASP MASVS-NETWORK-1", "CWE-319"],
    )]


def _check_allow_backup(meta: AndroidAppMeta) -> list[ManifestFinding]:
    explicit = meta.allow_backup
    target = meta.target_sdk

    if explicit is False:
        return []  # explicitly disabled — safe
    if explicit is True:
        detail = (
            "android:allowBackup=true is set explicitly. App data is included in "
            "adb backup and cloud backup, exposing SharedPreferences/databases on "
            "rooted or USB-debug devices."
        )
    elif explicit is None and (target is None or target < TARGET_SDK_ALLOW_BACKUP_DEFAULT_FALSE):
        detail = (
            f"allowBackup is unset and targetSdk={target if target else 'unspecified'} "
            f"(<{TARGET_SDK_ALLOW_BACKUP_DEFAULT_FALSE}); the platform default is true."
        )
    else:
        return []

    return [ManifestFinding(
        rule_id="MANIFEST-003",
        title="Allow Backup Enabled",
        severity=SEV_MEDIUM,
        detail=detail,
        remediation=(
            "Set android:allowBackup=false, or define android:fullBackupContent / "
            "android:dataExtractionRules to exclude sensitive paths (databases, "
            "credential stores, encryption keys)."
        ),
        references=["OWASP MASVS-STORAGE-2", "CWE-922"],
    )]


def _check_exported_no_permission(meta: AndroidAppMeta) -> list[ManifestFinding]:
    findings: list[ManifestFinding] = []
    for c in meta.components:
        # Providers are covered by their own rule (MANIFEST-005); skip here to
        # avoid double-counting. Same component still gets dedicated provider
        # finding below.
        if c.type == "provider":
            continue
        if c.exported and c.intent_actions and not c.permission:
            findings.append(ManifestFinding(
                rule_id="MANIFEST-004",
                title=f"Exported {c.type} without permission",
                severity=SEV_HIGH,
                component=c.name,
                detail=(
                    f"{c.type} '{c.name}' is android:exported=true with intent-filter "
                    f"actions {c.intent_actions} and no android:permission. Any installed "
                    "app can invoke it directly."
                ),
                remediation=(
                    "Add android:permission with at least signature-level protection, "
                    "or set android:exported=false if external invocation is unintended. "
                    "On API 31+ the exported attribute MUST be explicit when intent-filter "
                    "is present."
                ),
                references=["OWASP MASVS-PLATFORM-1", "CWE-926"],
            ))
    return findings


def _check_exported_provider(meta: AndroidAppMeta) -> list[ManifestFinding]:
    findings: list[ManifestFinding] = []
    for c in meta.components:
        if c.type != "provider" or not c.exported:
            continue
        # An exported provider WITHOUT permission is critical; with permission,
        # still high (third-party signing keys can be obtained).
        severity = SEV_HIGH if c.permission else SEV_HIGH
        findings.append(ManifestFinding(
            rule_id="MANIFEST-005",
            title="Exported content provider",
            severity=severity,
            component=c.name,
            detail=(
                f"Content provider '{c.name}' is exported. Other apps can issue "
                f"queries / inserts / updates / deletes against it"
                + (
                    f" (currently guarded by permission '{c.permission}')."
                    if c.permission else " without authentication."
                )
            ),
            remediation=(
                "Set android:exported=false unless cross-app data sharing is "
                "intentional. For intentional sharing, use signature-level "
                "permissions and validate ALL incoming URIs server-side to "
                "prevent path traversal."
            ),
            references=["OWASP MASVS-PLATFORM-1", "CWE-926"],
        ))
    return findings


def _check_provider_grant_uri(meta: AndroidAppMeta) -> list[ManifestFinding]:
    findings: list[ManifestFinding] = []
    for c in meta.components:
        if c.type != "provider" or not c.grant_uri_permissions:
            continue
        findings.append(ManifestFinding(
            rule_id="MANIFEST-006",
            title="Provider with grantUriPermissions",
            severity=SEV_MEDIUM,
            component=c.name,
            detail=(
                f"Provider '{c.name}' declares android:grantUriPermissions=true. "
                "Combined with weak URI validation this enables path traversal "
                "or unauthorized URI access (CWE-22)."
            ),
            remediation=(
                "Restrict <grant-uri-permission> to specific path patterns. "
                "Validate URI authority + path on every incoming call; reject "
                "URIs containing '..' or absolute external paths."
            ),
            references=["OWASP MASVS-PLATFORM-1", "CWE-22"],
        ))
    return findings


def _check_dangerous_permissions(meta: AndroidAppMeta) -> list[ManifestFinding]:
    risky = sorted(p for p in meta.permissions if p in DANGEROUS_PERMISSIONS)
    if not risky:
        return []
    return [ManifestFinding(
        rule_id="MANIFEST-007",
        title=f"Dangerous permission surface ({len(risky)} permissions)",
        severity=SEV_INFO,
        detail=(
            f"App requests {len(risky)} dangerous permission(s): {', '.join(risky)}. "
            "Each grants access to sensitive user data and must be justified."
        ),
        remediation=(
            "Review necessity per permission. Prefer scoped APIs (Storage Access "
            "Framework, MediaStore, FusedLocationProvider with COARSE) over broader "
            "ones. Implement runtime permission requests with rationale dialogs."
        ),
        references=["OWASP MASVS-PRIVACY-1"],
    )]


def _check_min_sdk(meta: AndroidAppMeta) -> list[ManifestFinding]:
    if meta.min_sdk is None or meta.min_sdk >= MIN_RECOMMENDED_MIN_SDK:
        return []
    return [ManifestFinding(
        rule_id="MANIFEST-008",
        title="Outdated minSdkVersion",
        severity=SEV_MEDIUM,
        detail=(
            f"minSdkVersion={meta.min_sdk} is below {MIN_RECOMMENDED_MIN_SDK} "
            f"(Android 6.0). Runtime permissions, SafetyNet attestation, and "
            f"hardware-backed Keystore are not enforced on these devices."
        ),
        remediation=(
            f"Raise minSdkVersion to at least {MIN_RECOMMENDED_MIN_SDK}, ideally 26+. "
            "Older API levels also lack TLS 1.2 by default."
        ),
        references=["OWASP MASVS-ARCH-9"],
    )]


def _check_target_sdk(meta: AndroidAppMeta) -> list[ManifestFinding]:
    if meta.target_sdk is None or meta.target_sdk >= MIN_RECOMMENDED_TARGET_SDK:
        return []
    return [ManifestFinding(
        rule_id="MANIFEST-009",
        title="Outdated targetSdkVersion",
        severity=SEV_MEDIUM,
        detail=(
            f"targetSdkVersion={meta.target_sdk} is below {MIN_RECOMMENDED_TARGET_SDK}. "
            "App misses recent security/privacy enforcements: scoped storage (29), "
            "package visibility (30), foreground-service types (31), explicit "
            "exported attribute (31)."
        ),
        remediation=(
            f"Raise targetSdkVersion to a recent Android version "
            f"(33+ recommended; Google Play requires 33+ for new submissions)."
        ),
        references=["OWASP MASVS-ARCH-9"],
    )]


# Rule registry. Order is the canonical order of findings in the report.
RULES: list[Callable[[AndroidAppMeta], list[ManifestFinding]]] = [
    _check_debuggable,
    _check_cleartext_traffic,
    _check_allow_backup,
    _check_exported_no_permission,
    _check_exported_provider,
    _check_provider_grant_uri,
    _check_dangerous_permissions,
    _check_min_sdk,
    _check_target_sdk,
]


# ---------- entry points ----------


def audit_manifest(meta: AndroidAppMeta) -> AndroidAuditReport:
    """Run all manifest audit rules and return an AndroidAuditReport.

    Pure function over AndroidAppMeta; no I/O, no side effects. Safe to call
    repeatedly (e.g., in CI gates) — same input always produces the same
    findings.
    """
    findings: list[ManifestFinding] = []
    for rule in RULES:
        findings.extend(rule(meta))
    return AndroidAuditReport(
        package_name=meta.package_name,
        findings=findings,
    )


def format_audit_summary(report: AndroidAuditReport) -> str:
    """Compact terminal-friendly summary of an audit report.

    One header line + one line per non-empty severity, then per-finding
    bullet lines. Suitable for stdout from a CLI or inclusion in a report.
    """
    counts = report.severity_counts
    total = sum(counts.values())
    lines = [
        f"AndroidManifest audit — {report.package_name or '<no package>'} "
        f"({total} finding{'s' if total != 1 else ''})"
    ]
    for sev in (SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM, SEV_LOW, SEV_INFO):
        n = counts.get(sev, 0)
        if n:
            lines.append(f"  {sev}: {n}")
    if total == 0:
        return lines[0] + "\n  (no findings)"
    lines.append("")
    for f in report.findings:
        component_part = f" [{f.component}]" if f.component else ""
        lines.append(f"  [{f.severity.upper()}] {f.rule_id} {f.title}{component_part}")
    return "\n".join(lines)

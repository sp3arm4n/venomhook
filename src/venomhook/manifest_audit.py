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
    AndroidComponent,
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
TARGET_SDK_PROVIDER_EXPORTED_DEFAULT_FALSE = 17  # API 17+ providers default exported=false


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


def _is_effectively_exported(component: AndroidComponent, target_sdk: int | None) -> bool:
    """Apply Android's exported defaults when android:exported is absent."""
    if component.exported:
        return True
    if component.exported_declared:
        return False
    if component.type == "provider":
        return target_sdk is None or target_sdk < TARGET_SDK_PROVIDER_EXPORTED_DEFAULT_FALSE
    return bool(component.intent_actions)


def _check_debuggable(meta: AndroidAppMeta) -> list[ManifestFinding]:
    if not meta.debuggable:
        return []
    return [ManifestFinding(
        rule_id="MANIFEST-001",
        title="디버깅 가능 애플리케이션",
        severity=SEV_HIGH,
        detail=(
            "애플리케이션에 android:debuggable=true가 설정되어 있습니다. adb 접근 "
            "권한이 있는 누구나 디버거를 부착해 메모리를 덤프하거나 변조 방지 "
            "로직을 우회할 수 있습니다."
        ),
        remediation=(
            "프로덕션 빌드에서는 android:debuggable 속성을 제거하거나 false로 "
            "설정하세요. 빌드 variant 구성을 통해 debug 빌드만 해당 플래그를 "
            "갖고 release 빌드에는 적용되지 않도록 하는 것이 권장됩니다."
        ),
        references=["OWASP MASVS-RESILIENCE-1", "CWE-489"],
    )]


_M002_REMEDIATION = (
    "android:usesCleartextTraffic=false로 설정하고 모든 트래픽을 HTTPS로 "
    "전송하세요. 부득이한 예외가 필요한 경우 Network Security Config "
    "(res/xml/network_security_config.xml)에 좁게 정의합니다."
)
_M002_REFERENCES = ["OWASP MASVS-NETWORK-1", "CWE-319"]


def _check_cleartext_traffic(meta: AndroidAppMeta) -> list[ManifestFinding]:
    findings: list[ManifestFinding] = []
    explicit = meta.uses_cleartext_traffic
    target = meta.target_sdk
    nsc = meta.nsc

    if explicit is True:
        findings.append(ManifestFinding(
            rule_id="MANIFEST-002",
            title="평문(HTTP) 트래픽 허용 — 명시적 플래그",
            severity=SEV_HIGH,
            detail=(
                "android:usesCleartextTraffic=true가 명시적으로 설정되어 있습니다. "
                "HTTP 평문 트래픽이 허용되어 MITM 가로채기와 변조 위협에 노출됩니다."
            ),
            remediation=_M002_REMEDIATION,
            references=list(_M002_REFERENCES),
        ))

    if nsc is not None and nsc.base_cleartext_permitted is True:
        findings.append(ManifestFinding(
            rule_id="MANIFEST-002",
            title="평문(HTTP) 트래픽 허용 — NSC base-config",
            severity=SEV_HIGH,
            detail=(
                "Network Security Config의 <base-config>에 "
                "cleartextTrafficPermitted=true가 설정되어 있습니다. API 28+ "
                "기본값(거부)을 명시적으로 뒤집어 도메인 설정으로 좁히지 않은 "
                "모든 호스트에 대해 HTTP 통신을 허용합니다."
            ),
            remediation=_M002_REMEDIATION,
            references=list(_M002_REFERENCES),
        ))

    if nsc is not None and nsc.cleartext_domains:
        domains_preview = ", ".join(nsc.cleartext_domains[:5])
        more = (
            f" (외 {len(nsc.cleartext_domains) - 5}개 더)"
            if len(nsc.cleartext_domains) > 5 else ""
        )
        findings.append(ManifestFinding(
            rule_id="MANIFEST-002",
            title=f"평문(HTTP) 트래픽 허용 — 도메인 한정 ({len(nsc.cleartext_domains)}개)",
            severity=SEV_MEDIUM,
            detail=(
                "Network Security Config가 특정 도메인에 한해 "
                f"cleartextTrafficPermitted=true를 선언합니다: {domains_preview}{more}. "
                "의도된 예외일 수 있으나, 해당 도메인 트래픽은 MITM에 노출되며 "
                "DNS 스푸핑이나 단말 프록시 환경에서 그대로 가로채집니다."
            ),
            remediation=(
                "각 도메인의 HTTP 사용 사유를 재확인하고, HTTPS 전환 가능 여부를 "
                "검토하세요. 불가피하다면 가능한 좁은 path/subdomain으로 한정하고, "
                "민감 데이터가 해당 채널을 통과하지 않도록 코드 경로를 분리하세요."
            ),
            references=list(_M002_REFERENCES),
        ))

    # Implicit branch: only fire when no policy at all is declared. A
    # network_security_config reference (parsed or not) signals the
    # developer took responsibility and is audited via the NSC branches
    # above; don't double-flag here.
    if (
        not findings
        and explicit is None
        and target is not None
        and target < TARGET_SDK_CLEARTEXT_DEFAULT_FALSE
        and meta.network_security_config is None
    ):
        findings.append(ManifestFinding(
            rule_id="MANIFEST-002",
            title="평문(HTTP) 트래픽 허용 — 묵시적 기본값",
            severity=SEV_HIGH,
            detail=(
                f"targetSdk={target} (<28)이며 usesCleartextTraffic이나 Network "
                "Security Config 모두 지정되지 않았습니다. 플랫폼 기본값이 HTTP를 "
                "허용합니다."
            ),
            remediation=_M002_REMEDIATION,
            references=list(_M002_REFERENCES),
        ))

    return findings


def _check_allow_backup(meta: AndroidAppMeta) -> list[ManifestFinding]:
    explicit = meta.allow_backup
    target = meta.target_sdk

    if explicit is False:
        return []  # 명시적 비활성화 — 안전
    if explicit is True:
        detail = (
            "android:allowBackup=true가 명시적으로 설정되어 있습니다. 앱 데이터가 "
            "adb backup과 클라우드 백업에 포함되어, 루팅 또는 USB 디버그 환경에서 "
            "SharedPreferences/데이터베이스가 추출될 수 있습니다."
        )
    elif explicit is None and (target is None or target < TARGET_SDK_ALLOW_BACKUP_DEFAULT_FALSE):
        detail = (
            f"allowBackup 속성이 미지정이고 targetSdk={target if target else '미지정'} "
            f"(<{TARGET_SDK_ALLOW_BACKUP_DEFAULT_FALSE})이라 플랫폼 기본값이 "
            "true로 적용됩니다."
        )
    else:
        return []

    return [ManifestFinding(
        rule_id="MANIFEST-003",
        title="앱 백업 허용",
        severity=SEV_MEDIUM,
        detail=detail,
        remediation=(
            "android:allowBackup=false로 설정하거나 android:fullBackupContent / "
            "android:dataExtractionRules를 정의해 민감 경로(데이터베이스, 자격증명 "
            "저장소, 암호화 키)를 제외하세요."
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
        if _is_effectively_exported(c, meta.target_sdk) and c.intent_actions and not c.permission:
            export_state = (
                "android:exported=true로 명시"
                if c.exported_declared
                else "android:exported 속성 부재로 묵시적 export"
            )
            type_korean = {
                "activity": "액티비티",
                "service": "서비스",
                "receiver": "리시버",
                "provider": "프로바이더",
            }.get(c.type, c.type)
            findings.append(ManifestFinding(
                rule_id="MANIFEST-004",
                title=f"권한 없는 외부 노출 {type_korean}",
                severity=SEV_HIGH,
                component=c.name,
                detail=(
                    f"{type_korean} '{c.name}'이 {export_state} 상태이며 "
                    f"intent-filter actions {c.intent_actions} 보유, android:permission "
                    "미설정입니다. 설치된 어떤 앱이든 직접 호출 가능합니다."
                ),
                remediation=(
                    "최소 signature 수준의 android:permission을 추가하거나, 외부 "
                    "호출이 의도된 것이 아니라면 android:exported=false로 설정하세요. "
                    "API 31+에서는 intent-filter가 있을 때 exported 속성을 반드시 "
                    "명시해야 합니다."
                ),
                references=["OWASP MASVS-PLATFORM-1", "CWE-926"],
            ))
    return findings


def _check_exported_provider(meta: AndroidAppMeta) -> list[ManifestFinding]:
    findings: list[ManifestFinding] = []
    for c in meta.components:
        if c.type != "provider" or not _is_effectively_exported(c, meta.target_sdk):
            continue
        export_state = (
            "명시적 export"
            if c.exported_declared
            else "targetSdk < 17 또는 미지정으로 인한 묵시적 export"
        )
        # 권한 없는 exported provider는 critical, 권한 있어도 high
        # (서드파티 signing 키 획득 가능성).
        severity = SEV_HIGH if c.permission else SEV_HIGH
        findings.append(ManifestFinding(
            rule_id="MANIFEST-005",
            title="외부 노출 Content Provider",
            severity=severity,
            component=c.name,
            detail=(
                f"콘텐츠 프로바이더 '{c.name}'이 {export_state} 상태입니다. 다른 "
                "앱이 query / insert / update / delete를 호출할 수 있습니다"
                + (
                    f" (현재 '{c.permission}' 권한으로 보호됨)."
                    if c.permission else " (인증 보호 없음)."
                )
            ),
            remediation=(
                "앱 간 데이터 공유가 의도된 것이 아니라면 android:exported=false로 "
                "설정하세요. 의도된 공유라면 signature 수준 권한을 사용하고, 들어오는 "
                "모든 URI를 서버 측에서 검증해 path traversal을 차단해야 합니다."
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
            title="grantUriPermissions=true 프로바이더",
            severity=SEV_MEDIUM,
            component=c.name,
            detail=(
                f"프로바이더 '{c.name}'에 android:grantUriPermissions=true가 "
                "선언되어 있습니다. URI 검증이 약한 경우 path traversal이나 "
                "비인가 URI 접근으로 이어질 수 있습니다 (CWE-22)."
            ),
            remediation=(
                "<grant-uri-permission>을 구체적인 path pattern으로 제한하세요. "
                "들어오는 모든 호출에서 URI authority와 path를 검증하고, '..' "
                "또는 외부 절대 경로가 포함된 URI는 거부해야 합니다."
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
        title=f"위험 권한 노출 면적 ({len(risky)}개)",
        severity=SEV_INFO,
        detail=(
            f"앱이 위험 권한 {len(risky)}개를 요청합니다: {', '.join(risky)}. "
            "각각 민감한 사용자 데이터에 접근하므로 필요성이 정당화되어야 합니다."
        ),
        remediation=(
            "권한별 필요성을 재검토하세요. 광범위한 권한 대신 scoped API "
            "(Storage Access Framework, MediaStore, COARSE 위치를 사용하는 "
            "FusedLocationProvider 등)를 우선 사용하고, 런타임 권한 요청 시 "
            "사유 설명 다이얼로그를 함께 제공하세요."
        ),
        references=["OWASP MASVS-PRIVACY-1"],
    )]


def _check_min_sdk(meta: AndroidAppMeta) -> list[ManifestFinding]:
    if meta.min_sdk is None or meta.min_sdk >= MIN_RECOMMENDED_MIN_SDK:
        return []
    return [ManifestFinding(
        rule_id="MANIFEST-008",
        title="구버전 minSdkVersion",
        severity=SEV_MEDIUM,
        detail=(
            f"minSdkVersion={meta.min_sdk}이 권장 하한 {MIN_RECOMMENDED_MIN_SDK} "
            "(Android 6.0) 미만입니다. 해당 단말에서는 런타임 권한, SafetyNet "
            "어테스테이션, 하드웨어 기반 Keystore가 강제되지 않습니다."
        ),
        remediation=(
            f"minSdkVersion을 최소 {MIN_RECOMMENDED_MIN_SDK} 이상(권장 26+)으로 "
            "올리세요. 구버전은 TLS 1.2도 기본 지원하지 않습니다."
        ),
        references=["OWASP MASVS-ARCH-9"],
    )]


def _check_target_sdk(meta: AndroidAppMeta) -> list[ManifestFinding]:
    if meta.target_sdk is None or meta.target_sdk >= MIN_RECOMMENDED_TARGET_SDK:
        return []
    return [ManifestFinding(
        rule_id="MANIFEST-009",
        title="구버전 targetSdkVersion",
        severity=SEV_MEDIUM,
        detail=(
            f"targetSdkVersion={meta.target_sdk}이 권장 하한 "
            f"{MIN_RECOMMENDED_TARGET_SDK} 미만입니다. 최근 보안/프라이버시 "
            "강제사항(scoped storage(29), package visibility(30), foreground-"
            "service types(31), exported 속성 명시(31))이 적용되지 않습니다."
        ),
        remediation=(
            f"targetSdkVersion을 최신 Android 버전(33+ 권장; Google Play 신규 "
            "제출 요구사항)으로 올리세요."
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
        f"AndroidManifest 감사 — {report.package_name or '<패키지명 없음>'} "
        f"(취약점 {total}건)"
    ]
    for sev in (SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM, SEV_LOW, SEV_INFO):
        n = counts.get(sev, 0)
        if n:
            lines.append(f"  {sev}: {n}")
    if total == 0:
        return lines[0] + "\n  (탐지된 취약점 없음)"
    lines.append("")
    for f in report.findings:
        component_part = f" [{f.component}]" if f.component else ""
        lines.append(f"  [{f.severity.upper()}] {f.rule_id} {f.title}{component_part}")
    return "\n".join(lines)

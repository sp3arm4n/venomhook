"""Tier-1 fallback code audit over apktool's smali output.

Phase 10-4. apktool always produces ``smali/`` + ``smali_classes*/``
directories alongside the AndroidManifest.xml, regardless of how
heavily the APK is obfuscated or packed. jadx may time out, OOM, or
fail to decompile certain DEX layouts entirely — when that happens
we used to lose the entire code-audit signal. This module reuses the
same rule IDs as :mod:`code_audit` but matches against smali bytecode
text instead of decompiled Java, so the operator gets *some* findings
even on the worst-case APKs (Bangcle / AppGuard / OLLVM / VMP).

Coverage today
--------------

Four of the six CODE-* rules port cleanly to smali pattern matching:

  CODE-001  ``const-string`` containing ``http://`` literals
  CODE-003  ``const-string`` carrying weak crypto algorithm names
            (DES / 3DES / RC4 / MD5 / SHA-1) that feed into Cipher /
            MessageDigest calls
  CODE-005  invokes to ``Landroid/os/Environment;->getExternalStorage*``
            or ``Landroid/content/Context;->getExternal*``
  CODE-006  references to MODE_WORLD_READABLE (0x1) / MODE_WORLD_WRITEABLE
            (0x2) constants on Context.openFileOutput / openSharedPrefs

CODE-002 (WebView setJavaScriptEnabled) and CODE-004 (credentials in logs)
remain Java-tier only — smali patterns for these are noisy and would
add too many false positives. The .java tier (code_audit) is the
authoritative source for those two.

Precision
---------

The smali tier is intentionally **conservative** — same rule IDs and
severities, but evidence_tier="smali" labels each finding so HTML /
JSON consumers can show "이 발견은 smali 기반" tooltips. When both
tiers fire on the same (rule_id, class) pair, the pipeline keeps the
Java-tier finding (richer line text); the smali duplicate is dropped.

Pure-Python; no external dependencies. Skips third-party prefixes
that the Java tier already filters (Kotlin stdlib, AndroidX, Google
SDK, common ads / analytics) so a 200K-file smali tree like KakaoTalk
finishes in under a minute rather than five.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional

from venomhook.code_audit import (
    DEFAULT_THIRD_PARTY_PREFIXES,
    _strip_line_comment,  # quote-aware to match code_audit conventions
)
from venomhook.models import (
    AndroidAppMeta,
    CodeAuditReport,
    CodeFinding,
)


__all__ = [
    "audit_smali",
    "iter_smali_dirs",
    "iter_smali_files",
    "SMALI_RULES",
]


# Per-rule patterns. Each entry: (rule_id, severity, title, regex, detail).
# Regexes are applied per-line; the file iterator strips // comments first
# to avoid commented-out matches.
_HTTP_URL_RE = re.compile(
    r'const-string[^"]*"\s*(http://[^\s"\\]+)\s*"',
    re.IGNORECASE,
)

# Weak crypto names appear as JVM-style strings inside const-string.
# Smali shows them with their literal quoted form. We require the
# token to be a complete word (boundary) so "ANDES" doesn't fire.
_WEAK_CRYPTO_RE = re.compile(
    r'const-string[^"]*"\s*('
    r'(?:DES|DES3|3DES|RC4|RC2)(?:/[\w/]*)?|'
    r'MD5|MD2|SHA-1|SHA1'
    r')\s*"',
    re.IGNORECASE,
)

# CODE-005 — external storage APIs. Smali invokes look like:
#   invoke-static {}, Landroid/os/Environment;->getExternalStorageDirectory()...
#   invoke-virtual {p0}, Landroid/content/Context;->getExternalFilesDir(...)
_EXT_STORAGE_RE = re.compile(
    r'invoke-(?:static|virtual|direct|super)[^,]*,\s*'
    r'L(?:'
    r'android/os/Environment;->getExternalStorage(?:Directory|State|Public)'
    r'|'
    r'android/content/Context;->getExternal(?:FilesDir|CacheDir|MediaDirs)'
    r')'
)

# CODE-006 — MODE_WORLD_* file/preference modes. Smali references these
# either as field reads or as numeric mode constants (0x1 / 0x2) passed
# into Context.openFileOutput / getSharedPreferences.
_MODE_WORLD_RE = re.compile(
    r'(?:'
    r'sget\s+\w+,\s*Landroid/content/Context;->MODE_WORLD_(?:READABLE|WRITEABLE)'
    r'|'
    r'->openFileOutput\([^)]*\)Ljava/io/FileOutputStream;'
    r'.*MODE_WORLD'
    r')',
    re.IGNORECASE,
)
_MODE_WORLD_CONST_RE = re.compile(
    r'\bconst(?:/\w+)?\s+(?P<reg>[vp]\d+),\s*(?P<value>0x[12]|[12])\b',
    re.IGNORECASE,
)
_CONTEXT_MODE_CALL_RE = re.compile(
    r'invoke-(?:virtual|interface|direct|super)[^{]*\{(?P<regs>[^}]*)\},\s*'
    r'Landroid/content/Context;->'
    r'(?P<method>openFileOutput|getSharedPreferences)\('
)
_MODE_VALUE_NAMES = {
    "0x1": "MODE_WORLD_READABLE",
    "1": "MODE_WORLD_READABLE",
    "0x2": "MODE_WORLD_WRITEABLE",
    "2": "MODE_WORLD_WRITEABLE",
}


@dataclass(frozen=True)
class _Rule:
    rule_id: str
    severity: str
    title: str
    regex: re.Pattern
    detail_template: str
    remediation: str
    references: tuple[str, ...]


SMALI_RULES: tuple[_Rule, ...] = (
    _Rule(
        rule_id="CODE-001",
        severity="medium",
        title="평문 HTTP 엔드포인트 (smali tier)",
        regex=_HTTP_URL_RE,
        detail_template=(
            "smali 코드에 http:// URL 리터럴이 const-string으로 박혀 있습니다 "
            "({matched}). MITM 가로채기 / 변조 위험. .java 디컴파일이 부분/"
            "실패한 환경에서 본 smali tier가 같은 위험을 잡습니다."
        ),
        remediation=(
            "HTTPS로 마이그레이션하고, network_security_config.xml로 cleartext "
            "허용 호스트를 명시적으로 제한하세요."
        ),
        references=(
            "OWASP MASVS-NETWORK-1",
            "CWE-319",
        ),
    ),
    _Rule(
        rule_id="CODE-003",
        severity="high",
        title="약한 crypto / 해시 알고리즘 (smali tier)",
        regex=_WEAK_CRYPTO_RE,
        detail_template=(
            "smali에 약한 알고리즘 이름이 const-string으로 박혀 있습니다 "
            "({matched}). Cipher / MessageDigest.getInstance에 그대로 전달되면 "
            "충돌 / 무결성 우회 가능."
        ),
        remediation=(
            "AES/GCM (또는 ChaCha20-Poly1305), SHA-256 / SHA-512로 교체하세요. "
            "메시지 인증이 필요하면 HMAC-SHA256를 함께 적용."
        ),
        references=(
            "OWASP MASVS-CRYPTO-1",
            "CWE-327",
        ),
    ),
    _Rule(
        rule_id="CODE-005",
        severity="medium",
        title="외부 저장소 사용 (smali tier)",
        regex=_EXT_STORAGE_RE,
        detail_template=(
            "smali 코드가 외부 저장소 API를 호출합니다 ({matched}). 외부 "
            "저장소는 다른 앱에서 직접 읽고 쓸 수 있어 민감 데이터 저장에 "
            "부적합합니다."
        ),
        remediation=(
            "내부 저장소(Context.getFilesDir 등) 또는 EncryptedSharedPreferences"
            "/EncryptedFile (androidx.security)로 옮기세요."
        ),
        references=(
            "OWASP MASVS-STORAGE-1",
            "CWE-922",
        ),
    ),
    _Rule(
        rule_id="CODE-006",
        severity="high",
        title="MODE_WORLD_READABLE / WRITEABLE (smali tier)",
        regex=_MODE_WORLD_RE,
        detail_template=(
            "smali에 Context.MODE_WORLD_* 모드가 참조됩니다 ({matched}). "
            "Android 7+에서 deprecated이며, 다른 앱이 해당 파일을 직접 읽을 수 "
            "있어 자격증명 / 토큰 누출 위험."
        ),
        remediation=(
            "MODE_PRIVATE(0)로 변경하거나 EncryptedSharedPreferences "
            "(androidx.security)로 교체하세요."
        ),
        references=(
            "OWASP MASVS-STORAGE-1",
            "CWE-732",
        ),
    ),
)
_RULE_BY_ID = {rule.rule_id: rule for rule in SMALI_RULES}


# ---------- file iteration ----------


def iter_smali_dirs(apktool_out: str | Path) -> list[Path]:
    """Return the smali / smali_classes*/ subdirectories under an apktool
    output directory, sorted lex so the result is deterministic.
    """
    root = Path(apktool_out)
    if not root.is_dir():
        return []
    out: list[Path] = []
    for entry in sorted(root.iterdir()):
        if entry.is_dir() and entry.name.startswith("smali"):
            out.append(entry)
    return out


def _is_third_party(rel: Path, app_package: Optional[str]) -> bool:
    """Mirror code_audit's skip list — match by leading path segments
    against DEFAULT_THIRD_PARTY_PREFIXES. The app_package override lets
    a known first-party path that *happens* to share a prefix slip
    through (e.g., com.kakao.* must not be skipped just because the
    prefix 'com' is present).
    """
    parts = rel.parts
    if app_package:
        # Convert package to path segments and accept anything starting
        # with the same segments as first-party.
        pkg_parts = tuple(app_package.split("."))
        if parts[: len(pkg_parts)] == pkg_parts:
            return False
    # Use the same prefix list as the Java tier
    for prefix in DEFAULT_THIRD_PARTY_PREFIXES:
        prefix_parts = tuple(prefix.split("/"))
        if parts[: len(prefix_parts)] == prefix_parts:
            return True
    return False


def iter_smali_files(
    apktool_out: str | Path,
    app_meta: Optional[AndroidAppMeta] = None,
) -> Iterator[tuple[Path, Path]]:
    """Yield ``(absolute_path, relative_path_from_smali_root)`` for every
    .smali file across every smali_classes*/ directory under
    ``apktool_out``, with third-party paths skipped.
    """
    app_package = app_meta.package_name if app_meta else None
    for smali_root in iter_smali_dirs(apktool_out):
        for p in smali_root.rglob("*.smali"):
            rel = p.relative_to(smali_root)
            if _is_third_party(rel, app_package):
                continue
            yield p, rel


# ---------- audit ----------


def _smali_class_fqn(rel: Path) -> str:
    """foo/bar/Baz.smali -> foo.bar.Baz"""
    parts = list(rel.parts)
    if not parts:
        return ""
    parts[-1] = parts[-1].removesuffix(".smali")
    return ".".join(parts)


def _finding_for_rule(
    rule: _Rule,
    *,
    rel: Path,
    line_no: int,
    line: str,
    class_fqn: str,
    matched: str,
) -> CodeFinding:
    return CodeFinding(
        rule_id=rule.rule_id,
        title=rule.title,
        severity=rule.severity,
        file=str(rel),
        line_no=line_no,
        line_text=line.strip()[:300],
        class_fqn=class_fqn,
        detail=rule.detail_template.format(matched=matched.strip()),
        remediation=rule.remediation,
        references=list(rule.references),
        evidence_tier="smali",
    )


def audit_smali(
    apktool_out: str | Path,
    app_meta: Optional[AndroidAppMeta] = None,
    *,
    max_findings_per_rule: int = 200,
) -> CodeAuditReport:
    """Run the smali-tier rules and return a :class:`CodeAuditReport`.

    ``max_findings_per_rule`` caps each rule's output so a 200K-file
    smali tree doesn't drown the report — operators reading the cap
    line in the report can re-run with a higher cap or post-filter
    the JSON.
    """
    findings: list[CodeFinding] = []
    files_scanned = 0
    counts_per_rule: dict[str, int] = {r.rule_id: 0 for r in SMALI_RULES}

    for abs_path, rel in iter_smali_files(apktool_out, app_meta):
        files_scanned += 1
        try:
            text = abs_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        class_fqn = _smali_class_fqn(rel)
        mode_world_regs: dict[str, tuple[int, str]] = {}
        for line_no, raw_line in enumerate(text.splitlines(), 1):
            line = _strip_line_comment(raw_line)
            if not line:
                continue
            const_match = _MODE_WORLD_CONST_RE.search(line)
            if const_match:
                value = const_match.group("value").lower()
                mode_world_regs[const_match.group("reg")] = (
                    line_no,
                    _MODE_VALUE_NAMES[value],
                )

            call_match = _CONTEXT_MODE_CALL_RE.search(line)
            if call_match and counts_per_rule["CODE-006"] < max_findings_per_rule:
                regs = [r.strip() for r in call_match.group("regs").split(",")]
                for reg in regs:
                    prior = mode_world_regs.get(reg)
                    if not prior:
                        continue
                    const_line_no, mode_name = prior
                    if line_no - const_line_no > 5:
                        continue
                    rule = _RULE_BY_ID["CODE-006"]
                    findings.append(_finding_for_rule(
                        rule,
                        rel=rel,
                        line_no=line_no,
                        line=line,
                        class_fqn=class_fqn,
                        matched=mode_name,
                    ))
                    counts_per_rule["CODE-006"] += 1
                    break

            for rule in SMALI_RULES:
                if counts_per_rule[rule.rule_id] >= max_findings_per_rule:
                    continue
                m = rule.regex.search(line)
                if not m:
                    continue
                matched = m.group(1) if m.groups() else m.group(0)
                findings.append(_finding_for_rule(
                    rule,
                    rel=rel,
                    line_no=line_no,
                    line=line,
                    class_fqn=class_fqn,
                    matched=matched,
                ))
                counts_per_rule[rule.rule_id] += 1

    package_name = app_meta.package_name if app_meta else ""
    return CodeAuditReport(
        package_name=package_name,
        findings=findings,
        files_scanned=files_scanned,
    )


def merge_code_reports(
    java_report: Optional[CodeAuditReport],
    smali_report: Optional[CodeAuditReport],
) -> Optional[CodeAuditReport]:
    """Combine .java and smali findings, preferring .java on overlap.

    Two findings are considered the same when their (rule_id, class_fqn)
    match — the .java tier wins because its evidence (line text) is
    more readable. The smali tier covers the gap when jadx had no
    output for a given class.

    Either argument can be None; result is the other (or None when both
    are None). When both are present, the smali tier's files_scanned is
    added to the result for completeness, and partial flag is OR'd.
    """
    if java_report is None and smali_report is None:
        return None
    if java_report is None:
        return smali_report
    if smali_report is None:
        return java_report

    seen: set[tuple[str, str]] = {
        (f.rule_id, f.class_fqn) for f in java_report.findings
    }
    merged: list[CodeFinding] = list(java_report.findings)
    for f in smali_report.findings:
        key = (f.rule_id, f.class_fqn)
        if key in seen:
            continue
        merged.append(f)
        seen.add(key)

    return CodeAuditReport(
        package_name=java_report.package_name or smali_report.package_name,
        findings=merged,
        files_scanned=java_report.files_scanned + smali_report.files_scanned,
        partial=bool(java_report.partial or smali_report.partial),
    )

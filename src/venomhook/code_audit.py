"""Code-level static audit over jadx-decompiled Java sources.

Phase 7. Operates on the ``sources/`` directory jadx leaves behind in the
android-audit working dir. Each rule is a stateless callable that walks
the file tree and emits zero-or-more CodeFinding records. ``audit_code``
runs the registry and returns a CodeAuditReport.

Why this layer exists
---------------------

manifest_audit covers configuration-level posture (debuggable, exported,
NSC). It misses the things pentesters actually need to confirm with
code: hardcoded http://, WebView javascript-enabled, Cipher.getInstance
with weak modes, plaintext credential logs, external-storage writes of
sensitive files. These are visible in jadx output as plain Java text
patterns; a tiny grep-based engine surfaces them deterministically
without needing a parser.

Trade-offs
----------

Pure regex/text matching, no AST. False positives are possible (a
``http://`` inside a comment, or in a vendored library). The ruleset
mitigates this two ways:

  - Every rule strips comment-only lines (``//`` or block-comment
    interior) before matching.
  - Path filtering: only the application's own package tree is scanned
    by default. Third-party SDKs (``android.support``, ``com.google.``,
    ``androidx.``, ``kotlin.``, ``okhttp3.``, etc.) are skipped — they
    are out of scope for "what the app's developer wrote".

The path filter is configurable via ``audit_code(..., extra_skip=...)``
for unusual layouts. The package allowlist is automatically derived from
the application's own ``package_name`` when an AndroidAppMeta is given.

Dependencies: stdlib only. ``re`` for matching, ``pathlib`` for the
walk. No subprocess, no network.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Optional

from venomhook.models import (
    AndroidAppMeta,
    CodeAuditReport,
    CodeFinding,
)


__all__ = [
    "audit_code",
    "iter_app_java_files",
    "RULES",
    "DEFAULT_THIRD_PARTY_PREFIXES",
]


# Severity constants mirror manifest_audit so reports can merge buckets.
SEV_CRITICAL = "critical"
SEV_HIGH = "high"
SEV_MEDIUM = "medium"
SEV_LOW = "low"
SEV_INFO = "info"


# Top-level packages that are nearly always third-party / framework code.
# Pentesters care about app-authored code, so skipping these dramatically
# cuts noise without changing detection coverage.
DEFAULT_THIRD_PARTY_PREFIXES: frozenset[str] = frozenset({
    "android",
    "androidx",
    "com/google",
    "com/android/internal",
    "com/squareup",
    "okhttp3",
    "okio",
    "retrofit2",
    "kotlin",
    "kotlinx",
    "org/apache",
    "org/jetbrains",
    "org/json",
    "io/reactivex",
    "javax",
    "j$/util",
    # Logging / instrumentation frameworks: doc/version URLs in their
    # constants pollute CODE-001 with non-actionable hits. Verified on
    # F-Droid against logback in May 2026; same shape applies to the
    # rest below.
    "ch/qos/logback",
    "org/slf4j",
    "org/apache/log4j",
    "org/apache/logging",
    "ch/qos",
    # Kotlin HTTP / coroutines / ktor — third-party network plumbing.
    "io/ktor",
    "io/grpc",
    "io/netty",
})


# A rule is a callable taking (java_files, meta) and returning findings.
# Walking the file tree once per rule is cheap (sample APKs decompile to
# under 5k files) and keeps each rule's regex isolated for readability.
RuleFn = Callable[[list[Path], Optional[AndroidAppMeta], Path], list[CodeFinding]]


# ---------- file walking ----------


def _package_to_path_prefix(pkg: str) -> str:
    """``com.example.app`` -> ``com/example/app`` (no leading or trailing slash)."""
    return pkg.replace(".", "/")


def iter_app_java_files(
    sources_dir: Path,
    *,
    app_package: Optional[str] = None,
    extra_skip: Iterable[str] = (),
) -> list[Path]:
    """Return every ``.java`` file under ``sources_dir`` that's worth auditing.

    Filtering rules:
      - Files under any path prefix in ``DEFAULT_THIRD_PARTY_PREFIXES`` or
        ``extra_skip`` are dropped (matches by relative-to-sources_dir
        path component, so it survives jadx's ``sources/com/...`` layout).
      - When ``app_package`` is given, files under that package's path
        are kept *even if* they would otherwise match a third-party
        prefix (defensive: an app whose package is genuinely
        ``com.google.foo`` should not be filtered).

    Returns an empty list if ``sources_dir`` doesn't exist or is empty.
    Order is filesystem-iteration order (not sorted) so callers wanting
    deterministic output should sort.
    """
    if not sources_dir.is_dir():
        return []

    skip_prefixes = tuple(DEFAULT_THIRD_PARTY_PREFIXES) + tuple(extra_skip)
    keep_prefix = _package_to_path_prefix(app_package) if app_package else None

    out: list[Path] = []
    for path in sources_dir.rglob("*.java"):
        rel = path.relative_to(sources_dir).as_posix()
        if keep_prefix and rel.startswith(keep_prefix + "/"):
            out.append(path)
            continue
        if any(rel.startswith(prefix + "/") for prefix in skip_prefixes):
            continue
        out.append(path)
    return sorted(out)


def _class_fqn_for(path: Path, sources_dir: Path) -> str:
    """Heuristic class FQN from path: ``com/x/Foo.java`` -> ``com.x.Foo``.

    Returns empty string when the file sits at the root of sources_dir
    (no package).
    """
    rel = path.relative_to(sources_dir).as_posix()
    if "/" not in rel:
        return ""
    return rel[:-5].replace("/", ".")  # strip ``.java`` and dir-sep


# ---------- text helpers ----------


def _strip_line_comment(line: str) -> str:
    """Drop trailing ``//...`` while preserving ``//`` inside string literals.

    A naive regex would mangle ``"http://x"`` -> ``"http:`` because the
    URL's ``//`` looks like a comment start. Walk char-by-char tracking
    quote state instead.
    """
    i = 0
    in_str: Optional[str] = None
    out: list[str] = []
    while i < len(line):
        c = line[i]
        if in_str is not None:
            out.append(c)
            if c == "\\" and i + 1 < len(line):
                out.append(line[i + 1])
                i += 2
                continue
            if c == in_str:
                in_str = None
            i += 1
            continue
        if c == '"' or c == "'":
            in_str = c
            out.append(c)
            i += 1
            continue
        if c == "/" and i + 1 < len(line) and line[i + 1] == "/":
            break
        out.append(c)
        i += 1
    return "".join(out)


def _stripped_lines(text: str) -> list[tuple[int, str]]:
    """Yield (1-based line_no, comment-stripped line) pairs.

    Block comments (``/* ... */``) are tracked statefully so multi-line
    comments don't leak. Line comments (``//``) are stripped per-line by
    a quote-aware walker (``http://`` inside a string literal is
    preserved). Empty lines are kept so line numbers stay aligned.
    """
    out: list[tuple[int, str]] = []
    in_block = False
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw
        if in_block:
            end = line.find("*/")
            if end < 0:
                out.append((i, ""))
                continue
            line = line[end + 2:]
            in_block = False
        while True:
            start = line.find("/*")
            if start < 0:
                break
            end = line.find("*/", start + 2)
            if end < 0:
                line = line[:start]
                in_block = True
                break
            line = line[:start] + line[end + 2:]
        line = _strip_line_comment(line)
        out.append((i, line))
    return out


# ---------- rule: CODE-001 hardcoded HTTP ----------


_HTTP_URL_RE = re.compile(r"\bhttp://[A-Za-z0-9._\-/:]+")


def _check_hardcoded_http(
    files: list[Path], meta: Optional[AndroidAppMeta], sources_dir: Path
) -> list[CodeFinding]:
    findings: list[CodeFinding] = []
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line_no, line in _stripped_lines(text):
            m = _HTTP_URL_RE.search(line)
            if not m:
                continue
            findings.append(CodeFinding(
                rule_id="CODE-001",
                title="평문 HTTP URL 하드코딩",
                severity=SEV_HIGH,
                file=path.relative_to(sources_dir).as_posix(),
                line_no=line_no,
                line_text=line.strip()[:200],
                class_fqn=_class_fqn_for(path, sources_dir),
                detail=(
                    "소스에 http:// URL이 하드코딩되어 있습니다. 코드가 HTTPS로 "
                    "전환되지 않은 채 평문 채널을 사용하는 흔적입니다 — TLS 미적용 "
                    "엔드포인트가 아직 살아있다면 MITM 가로채기·변조에 그대로 노출됩니다. "
                    f"발견: {m.group(0)}"
                ),
                remediation=(
                    "HTTPS로 교체하고, 부득이한 경우에만 Network Security Config로 "
                    "특정 도메인에 한정하세요. 코드 상수로 빌드 variant마다 다른 "
                    "URL을 두는 패턴은 release 빌드에 평문 URL이 남기 쉬우니 "
                    "BuildConfig 또는 외부 설정으로 분리하세요."
                ),
                references=["OWASP MASVS-NETWORK-1", "CWE-319"],
            ))
    return findings


# ---------- rule: CODE-002 WebView JavaScript enabled / interface ----------


_JS_ENABLED_RE = re.compile(r"\.setJavaScriptEnabled\s*\(\s*true\s*\)")
_JS_INTERFACE_RE = re.compile(r"\.addJavascriptInterface\s*\(")


def _check_webview_javascript(
    files: list[Path], meta: Optional[AndroidAppMeta], sources_dir: Path
) -> list[CodeFinding]:
    findings: list[CodeFinding] = []
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line_no, line in _stripped_lines(text):
            if _JS_ENABLED_RE.search(line):
                findings.append(CodeFinding(
                    rule_id="CODE-002",
                    title="WebView JavaScript 활성화",
                    severity=SEV_MEDIUM,
                    file=path.relative_to(sources_dir).as_posix(),
                    line_no=line_no,
                    line_text=line.strip()[:200],
                    class_fqn=_class_fqn_for(path, sources_dir),
                    detail=(
                        "WebView에 setJavaScriptEnabled(true)이 호출되어 자바스크립트 "
                        "실행이 활성화되었습니다. 로드되는 콘텐츠 출처가 신뢰되지 "
                        "않으면 (예: cleartext URL, 사용자 입력 기반 URL, 파일 URI) "
                        "임의 스크립트 실행 → addJavascriptInterface과 결합 시 임의 "
                        "Java 메서드 호출까지 이어집니다."
                    ),
                    remediation=(
                        "필요한 화면에서만 활성화하고 (loadUrl 직전), 외부 URL은 "
                        "WebViewClient.shouldOverrideUrlLoading에서 도메인 화이트리스트로 "
                        "제한하세요. addJavascriptInterface가 함께 쓰인다면 노출 메서드를 "
                        "최소화하고 @JavascriptInterface가 붙은 메서드의 입력 검증을 "
                        "별도 점검하세요."
                    ),
                    references=["OWASP MASVS-CODE-2", "CWE-79"],
                ))
            if _JS_INTERFACE_RE.search(line):
                findings.append(CodeFinding(
                    rule_id="CODE-002",
                    title="WebView addJavascriptInterface 노출",
                    severity=SEV_HIGH,
                    file=path.relative_to(sources_dir).as_posix(),
                    line_no=line_no,
                    line_text=line.strip()[:200],
                    class_fqn=_class_fqn_for(path, sources_dir),
                    detail=(
                        "addJavascriptInterface로 자바 객체가 WebView 자바스크립트 "
                        "컨텍스트에 노출되었습니다. WebView가 신뢰되지 않는 콘텐츠를 "
                        "로드하면 노출된 Java 메서드를 임의 호출할 수 있습니다 — "
                        "가장 잘 알려진 RCE 클래스 중 하나입니다."
                    ),
                    remediation=(
                        "노출 클래스의 메서드는 모두 @JavascriptInterface로 명시 "
                        "지정하고 입력 검증을 강화하세요. 가능하면 인터페이스 자체를 "
                        "제거하고 postMessage / evaluateJavascript로 대체합니다. "
                        "WebView에 외부 URL을 절대 로드하지 않도록 도메인 제한을 "
                        "병행하세요."
                    ),
                    references=["OWASP MASVS-CODE-2", "CWE-749"],
                ))
    return findings


# ---------- registry & entry point ----------


RULES: list[RuleFn] = [
    _check_hardcoded_http,
    _check_webview_javascript,
]


def audit_code(
    sources_dir: Path | str,
    meta: Optional[AndroidAppMeta] = None,
    *,
    extra_skip: Iterable[str] = (),
) -> CodeAuditReport:
    """Walk decompiled Java sources and run every rule.

    Pure function — no I/O outside reading the .java files. Idempotent
    on repeat calls. Returns an empty report (with files_scanned=0) when
    the sources directory doesn't exist; callers that care about the
    distinction between "no findings" and "no scan" can check that.
    """
    src = Path(sources_dir)
    files = iter_app_java_files(
        src,
        app_package=meta.package_name if meta else None,
        extra_skip=extra_skip,
    )
    findings: list[CodeFinding] = []
    for rule in RULES:
        findings.extend(rule(files, meta, src))
    return CodeAuditReport(
        package_name=meta.package_name if meta else "",
        findings=findings,
        files_scanned=len(files),
    )

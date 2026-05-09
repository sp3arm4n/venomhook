#!/usr/bin/env python3
"""
codex-handoff: 문서 사실관계 검증용 번들러.

문서(보고서, README, audit HTML 등)에서 검증 가능한 주장을 추출하고,
각 주장의 추정 출처 코드/설정 파일을 매핑해 단일 마크다운으로 패키징한다.

사용:
    python .claude/skills/codex-handoff/scripts/doc_verify.py \
        --doc README.md \
        --out outputs/codex-doc-verify.md
"""

from __future__ import annotations

import argparse
import datetime as dt
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

sys.path.insert(0, str(Path(__file__).parent))
from _common import (  # noqa: E402
    estimate_tokens,
    find_repo_root,
    fmt_size,
    is_ignored,
    load_gitignore_patterns,
    mask_secrets,
    safe_read,
)


# ---------------------------------------------------------------------------
# 주장 추출
# ---------------------------------------------------------------------------

# 정확도보다 재현율 우선. false positive는 사람이 거른다.
# 파일 확장자처럼 보이는 'venomhook.png' 류는 module이 아니라 file-path/asset로 다룬다.
_NON_MODULE_TAILS = re.compile(
    r"\.(?:png|jpg|jpeg|svg|gif|css|js|html|md|json|toml|yaml|yml|sh|ps1|so|dll|apk|exe)$",
    re.IGNORECASE,
)

PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("file-path", re.compile(r"`?(?:src|tools|tests|docs|sample|setup|ghidra_scripts)/[^\s`)\"'<>]+`?")),
    # venomhook.foo.bar 형태이지만 파일 확장자가 끝이면 제외 (extract_claims에서 추가 필터)
    ("module", re.compile(r"\bvenomhook(?:\.[A-Za-z_][A-Za-z0-9_]*)+\b")),
    ("function", re.compile(r"`?[a-z_][a-z0-9_]{2,}\([^)]*\)`?")),
    ("classname", re.compile(r"\b(?:[A-Z][a-z0-9]+){2,}\b")),
    ("cli", re.compile(r"`venomhook\s+[a-z][a-z0-9\-]*[^`]*`")),
    ("rule-id", re.compile(r"\b(?:MANIFEST-\d{3}|HOOK-\d{3}|SIG-\d{3})\b")),
    ("cve", re.compile(r"\bCVE-\d{4}-\d{4,7}\b")),
    ("cwe", re.compile(r"\bCWE-\d{1,4}\b")),
    ("number-claim", re.compile(r"\b\d+\s*(?:종|개|건|회|줄|byte|bytes|KB|MB|GB|초|분)\b")),
    ("hash-len", re.compile(r"\b(?:SHA-?(?:1|256|512)|MD5|RVA|ABI|JNI)\b")),
]


@dataclass
class Claim:
    kind: str
    text: str  # 원문 그대로
    line: int  # 1-based 문서 라인 번호
    sources: list[str]  # 추정 출처 파일들 (리포 상대 경로)
    snippet: str = ""  # 출처에서 발췌한 텍스트


def extract_claims(doc_text: str) -> list[Claim]:
    out: list[Claim] = []
    seen: set[tuple[str, str]] = set()
    for lineno, line in enumerate(doc_text.splitlines(), start=1):
        for kind, pat in PATTERNS:
            for m in pat.finditer(line):
                t = m.group(0).strip("`")
                key = (kind, t)
                if key in seen:
                    continue
                # 사소한 노이즈 거르기
                if kind == "function" and len(t) < 6:
                    continue
                if kind == "classname" and t in {
                    "False",
                    "True",
                    "None",
                    "PostScript",
                    "JavaScript",
                    "TypeScript",
                    "VenomHook",
                }:
                    continue
                if kind == "module" and _NON_MODULE_TAILS.search(t):
                    # venomhook.png 같은 자산 경로는 module이 아님
                    continue
                seen.add(key)
                out.append(Claim(kind=kind, text=t, line=lineno, sources=[]))
    return out


# ---------------------------------------------------------------------------
# 출처 매핑
# ---------------------------------------------------------------------------


def index_repo(repo: Path, ignore: list[str]) -> list[Path]:
    """리포 안의 검색 대상 파일 목록 (텍스트성 파일만)."""
    exts = {
        ".py",
        ".md",
        ".toml",
        ".yaml",
        ".yml",
        ".json",
        ".sh",
        ".ps1",
        ".js",
        ".html",
    }
    files: list[Path] = []
    for p in repo.rglob("*"):
        if not p.is_file():
            continue
        rel = str(p.relative_to(repo))
        if is_ignored(rel, ignore):
            continue
        if p.suffix.lower() not in exts:
            continue
        files.append(p)
    return files


def map_sources(
    claim: Claim, files: list[Path], repo: Path, *, exclude_doc: Path | None = None
) -> None:
    """해당 주장 텍스트가 어떤 파일에 등장하는지 단순 grep.

    검증 대상 문서 자기 자신은 출처에서 제외해야 한다 (자기참조는 "출처 매칭"이 아니다).
    """
    needle = claim.text
    if claim.kind == "module":
        # venomhook.foo.bar → src/venomhook/foo/bar.py
        rel = Path("src", *needle.split(".")) .with_suffix(".py")
        cand = repo / rel
        if cand.exists():
            claim.sources.append(str(rel))
            claim.snippet = safe_read(cand)[:600]
            return
    # 일반 grep
    if claim.kind == "function":
        needle = needle.split("(", 1)[0]
    if len(needle) < 4:
        return
    excluded_resolved = exclude_doc.resolve() if exclude_doc else None
    for f in files:
        try:
            if excluded_resolved and f.resolve() == excluded_resolved:
                continue
            text = f.read_text(errors="ignore")
        except OSError:
            continue
        if needle in text:
            claim.sources.append(str(f.relative_to(repo)))
            if not claim.snippet:
                idx = text.find(needle)
                start = max(0, idx - 120)
                end = min(len(text), idx + 240)
                claim.snippet = text[start:end]
            if len(claim.sources) >= 4:
                break


# ---------------------------------------------------------------------------
# 렌더링
# ---------------------------------------------------------------------------


def render(
    *,
    doc_path: Path,
    doc_text: str,
    claims: list[Claim],
    repo: Path,
) -> str:
    out: list[str] = []
    add = out.append
    timestamp = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    add("# Codex Document Verification Bundle")
    add("")
    add(f"_생성: {timestamp}_  _doc: `{doc_path}`_  _repo: `{repo}`_")
    add("")
    add("---")
    add("")

    # 1. 검증 대상 문서
    add("## 1. 검증 대상 문서")
    add("")
    add(f"`{doc_path}` ({len(doc_text)} chars, {doc_text.count(chr(10))+1} lines)")
    add("")
    if len(doc_text) <= 8_000:
        add("```markdown")
        add(doc_text.rstrip())
        add("```")
    else:
        add("_문서가 길어 발췌만 표시합니다 (앞 4,000자):_")
        add("")
        add("```markdown")
        add(doc_text[:4_000].rstrip() + "\n...(생략)")
        add("```")
    add("")

    # 2. 추출된 주장
    matched = [c for c in claims if c.sources]
    unmatched = [c for c in claims if not c.sources]

    add(f"## 2. 추출된 주장 (출처 매칭됨, {len(matched)}건)")
    add("")
    if not matched:
        add("_매칭된 주장이 없습니다._")
    for i, c in enumerate(matched, start=1):
        add(f"### 주장 #{i} [{c.kind}] (문서 line {c.line})")
        add(f"- 텍스트: `{c.text}`")
        add(f"- 추정 출처: {', '.join(f'`{s}`' for s in c.sources)}")
        if c.snippet:
            add("- 코드 발췌:")
            add("")
            add("```")
            add(c.snippet.rstrip())
            add("```")
        add("")

    # 3. 출처 미발견
    add(f"## 3. 출처를 찾지 못한 주장 ({len(unmatched)}건)")
    add("")
    if not unmatched:
        add("_모든 주장이 출처와 매칭되었습니다._")
    else:
        for i, c in enumerate(unmatched, start=1):
            add(f"- [{c.kind}] line {c.line}: `{c.text}`")
    add("")

    # 4. Codex 검증 프롬프트
    add("## 4. Codex 검증 프롬프트")
    add("")
    add("```")
    add(_doc_prompt())
    add("```")
    add("")
    return "\n".join(out)


def _doc_prompt() -> str:
    return (
        "당신은 venomhook 보안 컨설팅 산출물의 사실관계를 점검하는 리뷰어입니다.\n"
        "위 1번 문서의 내용 중에서 2번에 추출된 주장 각각에 대해, 추정 출처(코드/스펙)와 일치하는지\n"
        "검증해 주세요. 출처를 못 찾은 3번 항목은 모르면 모른다고 답하세요.\n"
        "\n"
        "각 주장에 대해:\n"
        "  - 일치: 코드/스펙이 문서의 진술을 뒷받침하는가?  (예/아니오/부분일치)\n"
        "  - 근거: 어떤 라인·상수·함수가 근거가 되는가? (출처에서 인용)\n"
        "  - 위험: 잘못된 진술이라면 어떤 오해를 일으킬 수 있는가?\n"
        "\n"
        "응답 형식:\n"
        "  ## 일치 (Confirmed)\n"
        "  ## 부분 일치 (Partial)\n"
        "  ## 불일치 (Contradicted)\n"
        "  ## 판정 불가 (Unknown)\n"
        "\n"
        "특히 venomhook 산출물 특성상 다음 항목은 보수적으로 보세요:\n"
        "  - 룰 ID (MANIFEST-XXX 등)와 실제 룰 정의의 동기화\n"
        "  - CLI 명령 시그니처와 cli.py의 argparse 정의\n"
        "  - 수치 (룰 개수, 지원 ABI 수 등)와 코드 내 카운트\n"
    )


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def main() -> int:
    p = argparse.ArgumentParser(description="venomhook doc 사실관계 검증 번들러")
    p.add_argument("--doc", required=True, help="검증할 문서 (md/txt/html)")
    p.add_argument("--out", required=True, help="출력 마크다운 경로")
    p.add_argument("--repo", default="", help="리포 루트 (기본: 자동 탐지)")
    p.add_argument("--no-mask", action="store_true", help="비밀 패턴 마스킹 비활성화")
    args = p.parse_args()

    repo = Path(args.repo) if args.repo else find_repo_root()
    doc_path = Path(args.doc)
    if not doc_path.exists():
        raise SystemExit(f"문서를 찾을 수 없습니다: {doc_path}")
    doc_text = doc_path.read_text(errors="ignore")

    ignore = load_gitignore_patterns(repo)
    files = index_repo(repo, ignore)

    claims = extract_claims(doc_text)
    for c in claims:
        map_sources(c, files, repo, exclude_doc=doc_path)

    rendered = render(doc_path=doc_path, doc_text=doc_text, claims=claims, repo=repo)
    rendered, redacted_count = mask_secrets(rendered, enabled=not args.no_mask)

    out_path = Path(args.out).expanduser()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(rendered, encoding="utf-8")

    n_tokens = estimate_tokens(rendered)
    n_bytes = len(rendered.encode("utf-8"))
    print(f"[codex-handoff/doc] wrote: {out_path}")
    print(f"[codex-handoff/doc] size: {fmt_size(n_bytes)} (~{n_tokens} tokens, ±20%)")
    print(
        f"[codex-handoff/doc] claims: {len(claims)} "
        f"(matched: {sum(1 for c in claims if c.sources)})"
    )
    if redacted_count:
        print(f"[codex-handoff/doc] redacted: {redacted_count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

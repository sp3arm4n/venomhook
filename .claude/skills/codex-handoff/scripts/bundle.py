#!/usr/bin/env python3
"""
codex-handoff: 코드 변경 검증용 최소 컨텍스트 번들러.

목적: Claude로 venomhook을 수정한 직후, 변경된 부분만 함수 단위로 잘라
Codex(또는 외부 리뷰어 LLM)에 그대로 붙여넣을 수 있는 단일 마크다운을 생성한다.

사용:
    python .claude/skills/codex-handoff/scripts/bundle.py \
        --intent-file outputs/intent-20260509.md \
        --out outputs/codex-bundle.md

상세 옵션은 --help 참고.
"""

from __future__ import annotations

import argparse
import datetime as dt
import sys
from pathlib import Path
from typing import Iterable

# 같은 디렉터리의 _common 모듈을 임포트할 수 있게 한다.
sys.path.insert(0, str(Path(__file__).parent))
from _common import (  # noqa: E402
    DEFAULT_EXCLUDES,
    FileChange,
    Slice,
    collect_local_imports,
    collect_python_slices,
    estimate_tokens,
    find_repo_root,
    fmt_size,
    git_available,
    is_ignored,
    load_gitignore_patterns,
    mask_secrets,
    module_to_path,
    parse_unified_diff,
    run_git,
    safe_read,
)

TOP_PKG = "venomhook"
SRC_LAYOUT = Path("src")  # `src/venomhook/...` 레이아웃


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="venomhook code-review 핸드오프 번들러"
    )
    p.add_argument("--ref", default="HEAD", help="diff 기준 git ref (기본 HEAD)")
    p.add_argument(
        "--staged", action="store_true", help="staged 변경만 (--ref 무시)"
    )
    p.add_argument(
        "--files",
        default="",
        help="git diff를 무시하고 명시한 파일들만 포함 (콤마 구분, 리포 상대 경로)",
    )
    p.add_argument(
        "--include-related",
        action="store_true",
        help="import 1-hop 인접 파일의 본문까지 포함",
    )
    p.add_argument(
        "--related-depth",
        type=int,
        default=1,
        help="import 그래프 확장 깊이 (기본 1; 2 이상은 토큰 폭증 주의)",
    )
    p.add_argument(
        "--no-funcs-only",
        action="store_true",
        help="변경된 파일을 함수 단위로 자르지 않고 통째로 포함",
    )
    p.add_argument(
        "--max-bytes",
        type=int,
        default=300_000,
        help="번들 본문 최대 바이트 (초과 시 잘라내고 경고)",
    )
    p.add_argument(
        "--intent-file",
        default="",
        help="작업 의도/리스크/검증 포인트가 담긴 마크다운",
    )
    p.add_argument(
        "--out",
        required=True,
        help="출력 마크다운 파일 경로",
    )
    p.add_argument(
        "--no-mask", action="store_true", help="비밀 패턴 마스킹 비활성화"
    )
    p.add_argument(
        "--repo",
        default="",
        help="리포 루트 (기본: 현재 디렉터리에서 자동 탐지)",
    )
    return p.parse_args()


# ---------------------------------------------------------------------------
# diff 수집
# ---------------------------------------------------------------------------


def collect_diff(
    repo: Path, ref: str, staged: bool, files_arg: str
) -> tuple[str, list[FileChange]]:
    if files_arg:
        # git diff 우회: 명시된 파일을 모두 'M' 변경처럼 취급, diff_text 비움
        changes = []
        for p in [s.strip() for s in files_arg.split(",") if s.strip()]:
            changes.append(FileChange(path=p, status="M"))
        return "", changes

    if not git_available():
        raise SystemExit("git을 찾을 수 없습니다. --files로 명시해주세요.")

    if staged:
        diff = run_git(repo, "diff", "--cached", "--unified=3")
    else:
        diff = run_git(repo, "diff", ref, "--unified=3")
    changes = parse_unified_diff(diff)
    return diff, changes


# ---------------------------------------------------------------------------
# 슬라이스
# ---------------------------------------------------------------------------


def slice_changed_files(
    repo: Path, changes: list[FileChange], funcs_only: bool
) -> dict[str, list[Slice]]:
    """변경된 각 파일에 대해 슬라이스 목록을 만든다."""
    result: dict[str, list[Slice]] = {}
    for ch in changes:
        rel = ch.path
        if ch.status == "D":
            result[rel] = []  # 삭제된 파일은 본문 없음
            continue
        path = repo / rel
        if not path.exists():
            result[rel] = []
            continue
        text = safe_read(path)
        if not rel.endswith(".py") or not funcs_only:
            # Python이 아니면 통째 1슬라이스
            result[rel] = [
                Slice(
                    kind="raw",
                    qualname=Path(rel).name,
                    lineno=1,
                    end_lineno=text.count("\n") + 1,
                    text=text,
                )
            ]
            continue
        slices = collect_python_slices(
            text, changed_lines=ch.new_lines if ch.new_lines else None
        )
        if not slices:
            # AST는 멀쩡한데 변경 라인이 함수 밖이면 모듈 전체 추가
            slices = [
                Slice(
                    kind="raw",
                    qualname=Path(rel).name,
                    lineno=1,
                    end_lineno=text.count("\n") + 1,
                    text=text,
                )
            ]
        result[rel] = slices
    return result


# ---------------------------------------------------------------------------
# import 그래프 인접 파일
# ---------------------------------------------------------------------------


def find_related_files(
    repo: Path, changed_paths: Iterable[str], depth: int
) -> list[str]:
    seen: set[str] = set(changed_paths)
    frontier: list[str] = list(changed_paths)
    src_root = repo / SRC_LAYOUT
    for _ in range(max(0, depth)):
        next_frontier: list[str] = []
        for rel in frontier:
            p = repo / rel
            if not p.exists() or not rel.endswith(".py"):
                continue
            text = safe_read(p)
            for mod in collect_local_imports(text, TOP_PKG):
                tgt = module_to_path(mod, src_root)
                if tgt is None:
                    continue
                rel_t = str(tgt.relative_to(repo))
                if rel_t in seen:
                    continue
                seen.add(rel_t)
                next_frontier.append(rel_t)
        frontier = next_frontier
        if not frontier:
            break
    # 변경된 파일 자체는 제외하고 인접만 반환
    return sorted(seen - set(changed_paths))


# ---------------------------------------------------------------------------
# 마크다운 렌더링
# ---------------------------------------------------------------------------


def render_bundle(
    *,
    repo: Path,
    intent_md: str,
    changes: list[FileChange],
    sliced: dict[str, list[Slice]],
    diff_text: str,
    related_files: list[str],
    related_bodies: dict[str, str],
    head_sha: str,
    branch: str,
    redacted_count: int,
    truncation_note: str,
) -> str:
    out: list[str] = []
    add = out.append

    timestamp = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    add(f"# Codex Verification Bundle — venomhook")
    add("")
    add(f"_생성: {timestamp}_  ")
    add(f"_branch: `{branch}`  HEAD: `{head_sha[:12]}`_")
    if redacted_count:
        add(f"_REDACTED: {redacted_count} 항목 자동 마스킹됨_")
    if truncation_note:
        add(f"_⚠ {truncation_note}_")
    add("")
    add("---")
    add("")

    # 1. 작업 맥락
    add("## 1. 작업 맥락")
    if intent_md.strip():
        add(intent_md.strip())
    else:
        add(
            "_intent 파일이 없습니다. Codex가 변경 의도를 추측해야 합니다._\n"
            "_다음 양식을 채워 다시 호출하세요:_\n\n"
            "```\n"
            "### 변경 의도\n"
            "- ...\n\n"
            "### 리스크 가설\n"
            "- ...\n\n"
            "### 검증 포인트\n"
            "- [ ] ...\n"
            "```"
        )
    add("")

    # 2. 변경된 파일 (함수 단위 슬라이스)
    add("## 2. 변경된 파일 (함수 단위 슬라이스)")
    add("")
    if not changes:
        add("_변경 파일이 없습니다._")
    for ch in changes:
        slices = sliced.get(ch.path, [])
        names = [s.qualname for s in slices if s.kind in ("function", "class", "method")]
        line = f"### `{ch.path}` ({ch.status})"
        if names:
            line += f" — changed: {', '.join(f'`{n}`' for n in names)}"
        add(line)
        add("")
        if ch.status == "D":
            add("_파일이 삭제되었습니다._")
            add("")
            continue
        if not slices:
            add("_본문 없음 (또는 비-Python 파일)._")
            continue
        for s in slices:
            add(f"```python")
            add(s.header_line())
            add(s.text.rstrip())
            add("```")
            add("")

    # 3. Unified diff
    add("## 3. Unified diff (라인 단위)")
    add("")
    if diff_text.strip():
        add("```diff")
        add(diff_text.rstrip())
        add("```")
    else:
        add("_diff 없음 (--files 모드 또는 변경 없음)._")
    add("")

    # 4. 영향 가능성 있는 인접 파일
    add("## 4. 영향 가능성 있는 인접 파일 (import 1-hop)")
    add("")
    if not related_files:
        add("_없음._")
    else:
        for rel in related_files:
            body = related_bodies.get(rel)
            if body is None:
                add(f"- `{rel}` _(경로만; 본문 보려면 --include-related)_")
            else:
                add(f"<details><summary><code>{rel}</code></summary>")
                add("")
                add("```python")
                add(body.rstrip())
                add("```")
                add("")
                add("</details>")
    add("")

    # 5. 메타데이터
    add("## 5. 메타데이터")
    add("")
    add(f"- repo: `{repo}`")
    add(f"- branch: `{branch}`")
    add(f"- HEAD: `{head_sha}`")
    add(f"- changed file count: {len(changes)}")
    add(f"- related file count: {len(related_files)}")
    add("")

    # 6. Codex 검증 프롬프트
    add("## 6. Codex 검증 프롬프트")
    add("")
    add("아래를 Codex에 그대로 붙여넣어 주세요. 위 1~5 섹션이 컨텍스트로 함께 전달됩니다.")
    add("")
    add("```")
    add(_codex_prompt())
    add("```")
    add("")

    return "\n".join(out)


def _codex_prompt() -> str:
    return (
        "당신은 venomhook 프로젝트(네이티브 바이너리/Android APK 정적 분석 + Frida hook 자동화)의\n"
        "코드 리뷰어입니다. 위에 첨부된 번들은 Claude가 방금 적용한 변경의 최소 컨텍스트입니다.\n"
        "\n"
        "다음 순서로 검토하세요:\n"
        "  1) 1번 '작업 맥락' 섹션의 변경 의도와 실제 코드(2,3번)가 일치하는지 확인.\n"
        "  2) 1번 '리스크 가설'을 실제 코드에서 찾아보고, 각 가설에 대해 [확인됨/문제없음/추가검토]로 답.\n"
        "  3) 1번 '검증 포인트' 체크리스트 각 항목에 대해 [통과/실패/판단보류] + 근거 라인 인용.\n"
        "  4) 가설 외의 잠재 버그/회귀: 변경된 함수의 호출자(4번 인접 파일 목록)와의 인터페이스 정합성,\n"
        "     예외 처리, 입력 경계, 동시성 이슈, 보안 함의(특히 PoC 생성·Frida 스크립트 생성 경로)를 점검.\n"
        "  5) 마무리: 머지 전에 반드시 고쳐야 할 항목(BLOCK)과 권장 개선(NIT)을 분리하여 결론.\n"
        "\n"
        "응답 형식:\n"
        "  ## 의도 일치성\n"
        "  ## 리스크 가설 검증\n"
        "  ## 검증 포인트 체크리스트\n"
        "  ## 추가 발견\n"
        "  ## 결론 (BLOCK / NIT)\n"
        "\n"
        "근거를 인용할 때는 `파일경로:함수명` 또는 unified diff의 hunk 헤더를 사용해 주세요.\n"
    )


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def main() -> int:
    args = parse_args()
    repo = Path(args.repo) if args.repo else find_repo_root()

    diff_text, changes = collect_diff(
        repo=repo, ref=args.ref, staged=args.staged, files_arg=args.files
    )

    # gitignore 필터
    ignore = load_gitignore_patterns(repo)
    changes = [c for c in changes if not is_ignored(c.path, ignore)]

    if not changes:
        print("[codex-handoff] 변경된 파일이 없습니다.", file=sys.stderr)

    # 슬라이스
    sliced = slice_changed_files(repo, changes, funcs_only=not args.no_funcs_only)

    # 관련 파일 (import 1-hop)
    related = find_related_files(
        repo,
        [c.path for c in changes if not c.path.startswith(("docs/", "README"))],
        depth=args.related_depth,
    )
    # gitignore 필터 한 번 더
    related = [r for r in related if not is_ignored(r, ignore)]

    related_bodies: dict[str, str] = {}
    if args.include_related:
        for rel in related:
            p = repo / rel
            if p.exists():
                related_bodies[rel] = safe_read(p)

    # intent 파일
    intent_md = ""
    if args.intent_file:
        ip = Path(args.intent_file)
        if ip.exists():
            intent_md = ip.read_text(errors="ignore")
        else:
            print(f"[codex-handoff] intent 파일 없음: {ip}", file=sys.stderr)

    # git 메타
    head_sha = ""
    branch = ""
    try:
        head_sha = run_git(repo, "rev-parse", "HEAD").strip()
        branch = run_git(repo, "rev-parse", "--abbrev-ref", "HEAD").strip()
    except Exception:
        pass

    rendered = render_bundle(
        repo=repo,
        intent_md=intent_md,
        changes=changes,
        sliced=sliced,
        diff_text=diff_text,
        related_files=related,
        related_bodies=related_bodies,
        head_sha=head_sha,
        branch=branch,
        redacted_count=0,
        truncation_note="",
    )

    # 마스킹
    rendered, redacted_count = mask_secrets(rendered, enabled=not args.no_mask)

    # 사이즈 상한
    truncation_note = ""
    if len(rendered.encode("utf-8")) > args.max_bytes:
        head_lines = rendered.splitlines()
        # 자르기: 본문을 절단하되 1번 섹션과 6번 프롬프트는 보존
        header_idx = 0
        prompt_idx = 0
        for i, ln in enumerate(head_lines):
            if ln.startswith("## 1."):
                header_idx = i
            if ln.startswith("## 6."):
                prompt_idx = i
                break
        prefix = "\n".join(head_lines[:header_idx])
        intent_part = "\n".join(head_lines[header_idx:prompt_idx])
        suffix = "\n".join(head_lines[prompt_idx:])
        # 가운데 부분만 byte 상한에 맞춰 자른다
        budget = args.max_bytes - len(prefix.encode()) - len(suffix.encode()) - 200
        body_bytes = intent_part.encode("utf-8")
        if budget < 1000:
            budget = 1000
        if len(body_bytes) > budget:
            body_bytes = body_bytes[:budget]
            truncation_note = (
                f"본문 일부 잘림 (max-bytes={args.max_bytes}). 더 많은 컨텍스트가 필요하면 "
                "--max-bytes를 늘리거나 변경 범위를 좁혀 다시 호출하세요."
            )
        rendered = (
            prefix
            + "\n"
            + body_bytes.decode("utf-8", errors="replace")
            + "\n\n_⚠ "
            + truncation_note
            + "_\n\n"
            + suffix
        )

    # 헤더에 redacted/truncation 반영을 위해 다시 한 번 헤더 라인 갱신 (간단 치환)
    rendered = rendered.replace(
        "_REDACTED: 0 항목 자동 마스킹됨_",
        f"_REDACTED: {redacted_count} 항목 자동 마스킹됨_",
    )
    if redacted_count and "REDACTED:" not in rendered.split("---")[0]:
        rendered = rendered.replace(
            "_branch: ",
            f"_REDACTED: {redacted_count} 항목 자동 마스킹됨_  \n_branch: ",
            1,
        )

    # 출력
    out_path = Path(args.out).expanduser()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(rendered, encoding="utf-8")

    # 요약 표시
    n_tokens = estimate_tokens(rendered)
    n_bytes = len(rendered.encode("utf-8"))
    print(f"[codex-handoff] wrote: {out_path}")
    print(f"[codex-handoff] size: {fmt_size(n_bytes)} (~{n_tokens} tokens, ±20%)")
    print(f"[codex-handoff] changed files: {len(changes)}, related: {len(related)}")
    if redacted_count:
        print(f"[codex-handoff] redacted: {redacted_count}")
    if truncation_note:
        print(f"[codex-handoff] WARN: {truncation_note}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

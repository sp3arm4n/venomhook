"""
codex-handoff 공통 유틸리티.

이 모듈은 bundle.py / doc_verify.py 가 함께 쓰는 헬퍼를 모아둔다.
가능한 한 표준 라이브러리만 쓴다 (tiktoken은 선택적).
"""

from __future__ import annotations

import ast
import fnmatch
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

# ---------------------------------------------------------------------------
# 경로 / git 헬퍼
# ---------------------------------------------------------------------------


def find_repo_root(start: Path | None = None) -> Path:
    """가장 가까운 .git 디렉터리를 찾아 리포 루트를 반환."""
    p = (start or Path.cwd()).resolve()
    for candidate in [p, *p.parents]:
        if (candidate / ".git").exists():
            return candidate
    raise RuntimeError(f"git 리포 루트를 찾을 수 없습니다: {p}")


def run_git(repo: Path, *args: str) -> str:
    """git 명령 실행. 실패 시 stderr 그대로 RuntimeError."""
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"git {' '.join(args)} 실패: {proc.stderr.strip() or proc.stdout.strip()}"
        )
    return proc.stdout


def git_available() -> bool:
    try:
        subprocess.run(["git", "--version"], check=True, capture_output=True)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# .gitignore 존중 (단순 구현)
# ---------------------------------------------------------------------------

DEFAULT_EXCLUDES = (
    ".git/",
    "__pycache__/",
    ".pytest_cache/",
    "venv/",
    ".venv/",
    "node_modules/",
    "build/",
    "dist/",
    ".DS_Store",
)


def load_gitignore_patterns(repo: Path) -> list[str]:
    patterns: list[str] = []
    gi = repo / ".gitignore"
    if gi.exists():
        for line in gi.read_text(errors="ignore").splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            patterns.append(s)
    return patterns


def is_ignored(rel_path: str, patterns: Iterable[str]) -> bool:
    """매우 단순한 .gitignore 매칭. 정확하지 않지만 보안/캐시류는 잘 거른다."""
    parts = rel_path.split("/")
    for pat in [*patterns, *DEFAULT_EXCLUDES]:
        if pat.endswith("/"):
            stripped = pat.rstrip("/")
            if stripped in parts:
                return True
            if fnmatch.fnmatch(rel_path, stripped + "/*"):
                return True
        if fnmatch.fnmatch(rel_path, pat):
            return True
        if fnmatch.fnmatch(parts[-1], pat):
            return True
    return False


# ---------------------------------------------------------------------------
# AST 기반 함수 슬라이스
# ---------------------------------------------------------------------------


@dataclass
class Slice:
    """파일에서 추출한 한 조각 (함수, 클래스, 모듈 머리 등)."""

    kind: str  # "module-head" | "function" | "class" | "method"
    qualname: str  # 예: "ClassA.method_b"
    lineno: int  # 1-based 시작 라인
    end_lineno: int
    text: str

    def header_line(self) -> str:
        return f"# {self.kind}: {self.qualname} (lines {self.lineno}-{self.end_lineno})"


def collect_python_slices(
    source: str, changed_lines: set[int] | None = None
) -> list[Slice]:
    """
    파이썬 소스에서 변경된 라인을 포함하는 함수/클래스만 슬라이스.

    - changed_lines가 None이면 모듈 전체 슬라이스 (각 top-level def/class별로 자른다).
    - 모듈 최상단 import / 상수 / dataclass 헤더는 항상 'module-head' 슬라이스로 포함.
    - 변경된 라인이 메서드 안에 있으면 그 메서드만 잘라 'method'로 추출.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        # 파싱 실패하면 통째로 반환
        return [
            Slice(
                kind="raw",
                qualname="<unparseable>",
                lineno=1,
                end_lineno=source.count("\n") + 1,
                text=source,
            )
        ]

    lines = source.splitlines(keepends=True)
    slices: list[Slice] = []

    # 1) module-head: 최상단 import/상수
    head_end = _module_head_end(tree)
    if head_end > 0:
        slices.append(
            Slice(
                kind="module-head",
                qualname="<module>",
                lineno=1,
                end_lineno=head_end,
                text="".join(lines[:head_end]),
            )
        )

    # 2) 변경된 top-level 상수 (헤드에서 빠진 큰 할당)
    slices.extend(collect_top_level_constants(source, changed_lines))

    # 3) top-level def / class
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if _node_overlaps(node, changed_lines):
                slices.append(_make_slice("function", node.name, node, lines))
        elif isinstance(node, ast.ClassDef):
            class_changed = _node_overlaps(node, changed_lines)
            if class_changed:
                methods_changed = []
                for sub in node.body:
                    if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        if _node_overlaps(sub, changed_lines):
                            methods_changed.append(sub)
                if methods_changed and changed_lines is not None:
                    # 클래스 시그니처 한 줄 + 변경된 메서드만
                    header_line = lines[node.lineno - 1]
                    body_text = "".join(
                        "".join(lines[m.lineno - 1 : (m.end_lineno or m.lineno)])
                        for m in methods_changed
                    )
                    slices.append(
                        Slice(
                            kind="class",
                            qualname=node.name,
                            lineno=node.lineno,
                            end_lineno=node.end_lineno or node.lineno,
                            text=header_line + body_text,
                        )
                    )
                else:
                    # 헤더 자체에만 변경 (예: 베이스 클래스 변경) → 전체 추출
                    slices.append(_make_slice("class", node.name, node, lines))

    return slices


def _node_overlaps(node: ast.AST, changed_lines: set[int] | None) -> bool:
    if changed_lines is None:
        return True
    start = getattr(node, "lineno", 0)
    end = getattr(node, "end_lineno", start) or start
    return any(start <= ln <= end for ln in changed_lines)


def _make_slice(kind: str, name: str, node: ast.AST, lines: list[str]) -> Slice:
    start = getattr(node, "lineno", 1)
    end = getattr(node, "end_lineno", start) or start
    return Slice(
        kind=kind,
        qualname=name,
        lineno=start,
        end_lineno=end,
        text="".join(lines[start - 1 : end]),
    )


def _module_head_end(tree: ast.Module, *, max_lines: int = 60) -> int:
    """
    최상단 import/docstring/dunder 할당이 끝나는 라인을 찾는다 (1-based 끝 라인).

    헤드는 '참조 해석에 필요한 가벼운 머리말'이어야 한다. 거대한 top-level 상수
    (예: ``_CSS = \"\"\"...수백 줄...\"\"\"``)가 헤드에 흡수되면 슬라이스 효과가 사라진다.
    그래서 다음 규칙을 적용한다:

    - import / from-import / 모듈 docstring 은 항상 포함
    - 짧은(<= 5줄) 단순 할당은 포함 (`__all__`, `__version__`, dunder 변수, 작은 상수 튜플)
    - 그보다 큰 할당은 별도 슬라이스로 다뤄야 하므로 헤드에서 종료
    - 전체 헤드가 ``max_lines`` 를 넘기 시작하면 거기서 종료
    """
    head_end = 0
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            head_end = node.end_lineno or head_end
        elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
            # 모듈 docstring
            head_end = node.end_lineno or head_end
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            start = getattr(node, "lineno", 1)
            end = getattr(node, "end_lineno", start) or start
            span = end - start + 1
            # 5줄 이하의 짧은 할당만 헤드에 포함
            if span <= 5:
                head_end = end
            else:
                break
        else:
            break
        if head_end >= max_lines:
            break
    return head_end


def collect_top_level_constants(
    source: str, changed_lines: set[int] | None
) -> list[Slice]:
    """
    변경 라인을 포함하는 top-level 상수/긴 할당을 별도 슬라이스로 뽑는다.

    module-head 휴리스틱에서 빠진 큰 상수(예: ``_CSS = '''..'''``)에 변경이 있으면
    그것만 따로 추출한다. 변경 없는 큰 상수는 무시 — 토큰 절감의 핵심.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    lines = source.splitlines(keepends=True)
    out: list[Slice] = []
    head_end = _module_head_end(tree)
    for node in tree.body:
        start = getattr(node, "lineno", 1)
        end = getattr(node, "end_lineno", start) or start
        if end <= head_end:
            continue
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            if not _node_overlaps(node, changed_lines):
                continue
            name = "<assign>"
            if isinstance(node, ast.Assign) and node.targets:
                first = node.targets[0]
                if isinstance(first, ast.Name):
                    name = first.id
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                name = node.target.id
            out.append(
                Slice(
                    kind="constant",
                    qualname=name,
                    lineno=start,
                    end_lineno=end,
                    text="".join(lines[start - 1 : end]),
                )
            )
    return out


# ---------------------------------------------------------------------------
# import 그래프 (1-hop)
# ---------------------------------------------------------------------------


def collect_local_imports(source: str, top_pkg: str) -> set[str]:
    """`venomhook.X` 패턴만 추적한다. 외부 라이브러리는 무시."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return set()
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == top_pkg or alias.name.startswith(top_pkg + "."):
                    out.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if mod == top_pkg or mod.startswith(top_pkg + "."):
                out.add(mod)
    return out


def module_to_path(module: str, src_root: Path) -> Path | None:
    """`venomhook.foo.bar` → `src_root/venomhook/foo/bar.py` 또는 패키지 __init__."""
    rel = Path(*module.split("."))
    py = src_root / rel.with_suffix(".py")
    if py.exists():
        return py
    init = src_root / rel / "__init__.py"
    if init.exists():
        return init
    return None


# ---------------------------------------------------------------------------
# 토큰 추정
# ---------------------------------------------------------------------------


def estimate_tokens(text: str) -> int:
    """tiktoken이 있으면 그것을, 없으면 chars/4 휴리스틱을 사용."""
    try:
        import tiktoken  # type: ignore

        enc = tiktoken.get_encoding("cl100k_base")
        return len(enc.encode(text))
    except Exception:
        return max(1, len(text) // 4)


# ---------------------------------------------------------------------------
# 비밀 마스킹
# ---------------------------------------------------------------------------

# 보안 컨설팅 산출물에서 마스킹은 "보수적" 이어야 한다.
# false positive(예: 긴 함수명 가려짐)는 Codex가 코드를 못 읽게 만들어 검증 자체를 망친다.
# false negative(진짜 토큰이 가려지지 않음)는 사용자가 사후 grep으로 잡아낼 수 있다.
# 따라서 명시적인 시크릿 형태 패턴만 잡고, 일반 영숫자 시퀀스는 건드리지 않는다.
SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("aws-secret-key", re.compile(r"\b[A-Za-z0-9/+=]{40}\b(?=\s*['\"]\s*[,}\)])")),
    (
        "bearer-token",
        re.compile(r"(?i)Authorization\s*:\s*Bearer\s+[A-Za-z0-9._\-]+"),
    ),
    (
        "kv-secret",
        # 키워드 기반: 변수명 또는 키 이름이 비밀스러운 경우
        re.compile(
            r"(?i)\b(api[_\-]?key|secret|password|passwd|access[_\-]?token|"
            r"bearer[_\-]?token|private[_\-]?key)\b"
            r"\s*[:=]\s*['\"][^'\"]{8,}['\"]"
        ),
    ),
    (
        "github-pat",
        re.compile(r"\bghp_[A-Za-z0-9]{36}\b|\bghs_[A-Za-z0-9]{36}\b"),
    ),
    (
        "slack-token",
        re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}\b"),
    ),
    # 16진수 hash가 따옴표 안에 있고 충분히 길면 (40+) 마스킹 — SHA1/SHA256 토큰 의심
    (
        "hex-hash-quoted",
        re.compile(r"['\"][a-fA-F0-9]{40,}['\"]"),
    ),
]


def mask_secrets(text: str, *, enabled: bool = True) -> tuple[str, int]:
    """비밀스러운 패턴을 ◼◼◼로 치환. (마스킹된_텍스트, 카운트) 반환."""
    if not enabled:
        return text, 0
    count = 0

    def _sub(m: re.Match[str]) -> str:
        nonlocal count
        count += 1
        return "◼◼◼REDACTED◼◼◼"

    out = text
    for _, pat in SECRET_PATTERNS:
        out = pat.sub(_sub, out)
    return out, count


# ---------------------------------------------------------------------------
# diff 파서 (변경 라인 추출)
# ---------------------------------------------------------------------------


@dataclass
class FileChange:
    path: str  # 리포 루트 기준 상대 경로 (post-image 기준)
    status: str  # "M" | "A" | "D" | "R" 등
    new_lines: set[int] = field(default_factory=set)  # 추가/수정된 post-image 라인 번호
    diff_text: str = ""


_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def parse_unified_diff(diff: str) -> list[FileChange]:
    changes: list[FileChange] = []
    cur: FileChange | None = None
    new_lineno = 0
    in_hunk = False
    buf: list[str] = []
    cur_status = "M"

    def flush():
        nonlocal buf
        if cur is not None:
            cur.diff_text = "".join(buf)
        buf = []

    for raw in diff.splitlines(keepends=True):
        if raw.startswith("diff --git "):
            flush()
            buf = [raw]
            cur = None
            in_hunk = False
            cur_status = "M"
            continue
        if raw.startswith("new file mode"):
            cur_status = "A"
            buf.append(raw)
            continue
        if raw.startswith("deleted file mode"):
            cur_status = "D"
            buf.append(raw)
            continue
        if raw.startswith("rename "):
            cur_status = "R"
            buf.append(raw)
            continue
        if raw.startswith("+++ "):
            buf.append(raw)
            target = raw[4:].strip()
            if target == "/dev/null":
                # 삭제된 파일. cur는 다음 --- 줄에서 만들어졌어야 하는데 안전하게 처리
                continue
            # "b/path" 또는 "path"
            path = target[2:] if target.startswith("b/") else target
            cur = FileChange(path=path, status=cur_status)
            changes.append(cur)
            in_hunk = False
            continue
        if raw.startswith("--- "):
            buf.append(raw)
            continue
        if raw.startswith("@@"):
            buf.append(raw)
            m = _HUNK_RE.match(raw)
            if m and cur is not None:
                new_lineno = int(m.group(1))
                in_hunk = True
            continue
        if in_hunk and cur is not None:
            buf.append(raw)
            if raw.startswith("+") and not raw.startswith("+++"):
                cur.new_lines.add(new_lineno)
                new_lineno += 1
            elif raw.startswith("-") and not raw.startswith("---"):
                pass  # 삭제 라인은 post-image 라인 번호 증가 없음
            else:
                # context 라인
                new_lineno += 1
        else:
            buf.append(raw)
    flush()
    # 빈 changes 제거
    return [c for c in changes if c.path]


# ---------------------------------------------------------------------------
# 안전한 파일 읽기
# ---------------------------------------------------------------------------


def safe_read(path: Path, max_bytes: int = 2_000_000) -> str:
    try:
        data = path.read_bytes()
    except OSError as e:
        return f"<<read error: {e}>>"
    if len(data) > max_bytes:
        return data[:max_bytes].decode("utf-8", errors="replace") + "\n<<truncated>>\n"
    return data.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# 라인 카운트
# ---------------------------------------------------------------------------


def fmt_size(n_bytes: int) -> str:
    if n_bytes < 1024:
        return f"{n_bytes}B"
    if n_bytes < 1024 * 1024:
        return f"{n_bytes/1024:.1f}KB"
    return f"{n_bytes/1024/1024:.1f}MB"

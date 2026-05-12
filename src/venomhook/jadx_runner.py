"""jadx-cli wrapper — DEX→Java decompilation and `native` method extraction.

VenomHook's Phase 2 Android workflow uses jadx to recover Java context for
native analysis. This module provides three building blocks:

  1. `find_jadx` — locate the jadx-cli binary (PATH or VENOMHOOK_JADX env var)
  2. `run_jadx` — invoke it with reasonable defaults (`--no-res --no-imports`
     `--no-debug-info`) for fast, code-only output
  3. `extract_native_methods` — walk the output tree and emit one
     `JavaNativeMethod` record per `native` declaration found

The JNI bridge module (PR #7) consumes the extracted records to predict
`Java_<pkg>_<class>_<method>` C symbols and align them with Ghidra-recovered
.so functions.

jadx is an *optional* dependency. When unavailable the public functions raise
`JadxNotFoundError` with installation guidance — the higher-level Android
pipeline (PR #9) is expected to graceful-fallback to native-only analysis.

Pure-Python; only depends on `models.JavaNativeMethod`.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from venomhook.models import JavaNativeMethod


__all__ = [
    "JadxError",
    "JadxNotFoundError",
    "JadxRunError",
    "JadxConfig",
    "JadxResult",
    "find_jadx",
    "run_jadx",
    "extract_native_methods",
    "decompile_apk",
    "JADX_ENV_VAR",
]


JADX_ENV_VAR = "VENOMHOOK_JADX"
_JADX_CANDIDATES = ("jadx", "jadx-cli")


# ---------- exceptions ----------


class JadxError(RuntimeError):
    """Base class for jadx-related failures."""


class JadxNotFoundError(JadxError):
    """jadx-cli could not be located on PATH or via env var."""


class JadxRunError(JadxError):
    """jadx invocation returned a non-zero exit code, timed out, or could not be started."""


# ---------- config / result ----------


@dataclass
class JadxConfig:
    """Tunable jadx invocation parameters.

    Defaults aim for fast Java-only decompilation suitable for native-bridge
    correlation. Resources / imports / debug info are skipped because we only
    need method declarations and string literals.
    """

    jadx_path: Optional[str] = None  # explicit binary path; None = auto-detect
    no_res: bool = True              # --no-res
    no_imports: bool = True          # --no-imports
    no_debug_info: bool = True       # --no-debug-info
    show_bad_code: bool = False      # --show-bad-code (emits broken decompilations)
    threads: Optional[int] = None    # -j N (None = jadx default of 4)
    timeout_sec: int = 600
    extra_args: list[str] = field(default_factory=list)
    # Phase 10-5: -m simple skips deobfuscation passes and uses the
    # linear (goto-style) IR translation. Output Java is uglier but the
    # rule patterns we run on it (const-string + method invocations)
    # are unaffected. On KakaoTalk-scale APKs this can cut wall-clock
    # by 30-50% — at the cost of harder-to-read .java for any manual
    # follow-up. When False (default) jadx picks "auto" mode.
    fast_mode: bool = False


@dataclass
class JadxResult:
    """Outcome of a jadx invocation."""

    apk_path: str
    output_dir: str
    returncode: int
    java_files: int               # number of .java files generated
    stdout_tail: str = ""         # last 4KB of stdout
    stderr_tail: str = ""         # last 4KB of stderr
    # Phase 10-3: True when jadx hit the configured timeout but had
    # already produced .java sources on disk. Callers (android_pipeline)
    # treat the partial output as audit-grade input, with a warning on
    # the audit report. Stays False on successful runs.
    partial: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "apk_path": self.apk_path,
            "output_dir": self.output_dir,
            "returncode": self.returncode,
            "java_files": self.java_files,
            "stdout_tail": self.stdout_tail,
            "stderr_tail": self.stderr_tail,
            "partial": self.partial,
        }


# ---------- jadx discovery ----------


def find_jadx(env_var: str = JADX_ENV_VAR) -> str:
    """Locate the jadx-cli binary.

    Resolution order:
      1. ``$VENOMHOOK_JADX`` (overridable env var) — must point to an executable file
      2. ``jadx`` on PATH
      3. ``jadx-cli`` on PATH

    Raises ``JadxNotFoundError`` if none resolve.
    """
    explicit = os.environ.get(env_var)
    if explicit:
        path = Path(explicit)
        # X_OK is unreliable on Windows (exec bit isn't part of NTFS perms),
        # so trust is_file() and let the actual subprocess.run surface a real
        # PermissionError/ENOEXEC if the user pointed at something unrunnable.
        if path.is_file() and (os.name == "nt" or os.access(explicit, os.X_OK)):
            return explicit
        raise JadxNotFoundError(
            f"{env_var}={explicit!r} is set but does not point to an executable file"
        )
    for cand in _JADX_CANDIDATES:
        found = shutil.which(cand)
        if found:
            return found
    raise JadxNotFoundError(
        "jadx-cli not found. Install jadx (https://github.com/skylot/jadx) and "
        f"either add it to PATH or set {env_var}=/path/to/jadx."
    )


# ---------- subprocess invocation ----------


def run_jadx(
    apk_path: str | Path,
    output_dir: str | Path,
    config: Optional[JadxConfig] = None,
) -> JadxResult:
    """Invoke jadx-cli on ``apk_path``, writing decompiled Java to ``output_dir``.

    Creates ``output_dir`` if missing. Doesn't pre-clean — jadx itself overwrites
    in-place and forcing a clean slate would surprise callers managing the dir.

    jadx exits non-zero on partial decompile errors yet still produces output;
    we treat that as success when at least one ``.java`` file was generated.
    Total failure (no output) is propagated as ``JadxRunError``.

    Raises:
      - ``JadxNotFoundError`` if jadx is not on PATH/env
      - ``JadxRunError`` for missing input, timeout, or hard failure
    """
    cfg = config or JadxConfig()
    apk = Path(apk_path).resolve()
    out = Path(output_dir).resolve()

    if not apk.exists():
        raise JadxRunError(f"APK not found: {apk}")
    if not apk.is_file():
        raise JadxRunError(f"not a regular file: {apk}")
    out.mkdir(parents=True, exist_ok=True)

    binary = cfg.jadx_path or find_jadx()

    cmd: list[str] = [binary, "-d", str(out)]
    if cfg.no_res:
        cmd.append("--no-res")
    if cfg.no_imports:
        cmd.append("--no-imports")
    if cfg.no_debug_info:
        cmd.append("--no-debug-info")
    if cfg.show_bad_code:
        cmd.append("--show-bad-code")
    if cfg.threads is not None and cfg.threads > 0:
        cmd.extend(["-j", str(cfg.threads)])
    if cfg.fast_mode:
        # `-m simple` switches off the structure-restoring passes — the
        # rule engine doesn't care because it matches against literal
        # const-strings and method calls, not control-flow shape.
        cmd.extend(["-m", "simple"])
    cmd.extend(cfg.extra_args)
    cmd.append(str(apk))

    timed_out = False
    timeout_stdout = ""
    timeout_stderr = ""
    try:
        completed = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            # Pin UTF-8 so jadx's i18n diagnostics don't crash decoding
            # under Windows cp949/cp1252 or non-UTF-8 POSIX locales.
            encoding="utf-8",
            errors="replace",
            timeout=cfg.timeout_sec,
        )
    except subprocess.TimeoutExpired as e:
        # Phase 10-3: graceful timeout. KakaoTalk-scale APKs hit the
        # configured ceiling but jadx has typically already written
        # tens of thousands of .java files by then. Raising here used
        # to discard that work entirely; instead we mark the result
        # ``partial=True`` and return it so audit_code can still run.
        timed_out = True
        # TimeoutExpired's stdout/stderr are bytes when the call was
        # text=True with a timeout (Python quirk); coerce safely.
        raw_out = e.stdout or b""
        raw_err = e.stderr or b""
        if isinstance(raw_out, bytes):
            timeout_stdout = raw_out.decode("utf-8", errors="replace")
        else:
            timeout_stdout = raw_out
        if isinstance(raw_err, bytes):
            timeout_stderr = raw_err.decode("utf-8", errors="replace")
        else:
            timeout_stderr = raw_err
        completed = None  # for the static type narrower
    except FileNotFoundError as e:
        raise JadxNotFoundError(
            f"could not exec jadx binary at {binary!r}: {e}"
        ) from e
    except OSError as e:
        raise JadxRunError(
            f"could not exec jadx binary at {binary!r}: {e}"
        ) from e

    java_files = sum(1 for _ in out.rglob("*.java"))

    if timed_out:
        # Disk has whatever jadx managed to write before the kill. If
        # the count is non-zero, surface partial=True so the pipeline
        # uses it. Still raise when nothing was produced — there is
        # nothing for downstream code_audit to inspect.
        if java_files == 0:
            raise JadxRunError(
                f"jadx timed out after {cfg.timeout_sec}s on {apk}"
            )
        return JadxResult(
            apk_path=str(apk),
            output_dir=str(out),
            returncode=-1,
            java_files=java_files,
            stdout_tail=timeout_stdout[-4096:],
            stderr_tail=timeout_stderr[-4096:] or (
                f"jadx timed out after {cfg.timeout_sec}s — "
                f"{java_files} partial .java files retained"
            ),
            partial=True,
        )

    stdout_tail = (completed.stdout or "")[-4096:]
    stderr_tail = (completed.stderr or "")[-4096:]

    if completed.returncode != 0 and java_files == 0:
        tail = stderr_tail or stdout_tail
        raise JadxRunError(
            f"jadx failed (exit={completed.returncode}, no .java produced): {tail}"
        )

    return JadxResult(
        apk_path=str(apk),
        output_dir=str(out),
        returncode=completed.returncode,
        java_files=java_files,
        stdout_tail=stdout_tail,
        stderr_tail=stderr_tail,
        partial=False,
    )


# ---------- native method extraction ----------


# Java method modifiers (`native` is one of them — we filter post-match).
_MODIFIER = (
    r"(?:public|private|protected|static|final|synchronized|"
    r"abstract|strictfp|native|default)"
)

# Match `... native ...` method declarations terminated by `;`.
# The leading `(?:{_MODIFIER}\s+)+` requires at least one Java modifier token;
# we then verify `native` appears in the captured group. Generic type
# parameters `<T>` between modifiers and return type are accepted.
_NATIVE_METHOD_RE = re.compile(
    rf"""
    (?P<modifiers>(?:{_MODIFIER}\s+)+)
    (?:<[^>]+>\s+)?                          # optional generic type params
    (?P<return>[\w.<>\[\]\s,]+?)             # return type (lazy, allows generics)
    \s+
    (?P<name>\w+)
    \s*\(
    (?P<params>[^)]*)
    \)
    \s*
    (?:throws\s+[\w.\s,]+)?
    \s*;
    """,
    re.VERBOSE | re.DOTALL,
)

_PACKAGE_RE = re.compile(r"^\s*package\s+([\w.]+)\s*;", re.MULTILINE)
_TOP_CLASS_RE = re.compile(
    r"\b(?:public|private|protected|abstract|final|static|sealed|non-sealed)\s+"
    r"(?:.*?\s+)?(?:class|interface|enum|@interface\s|record)\s+(\w+)",
    re.DOTALL,
)
_FALLBACK_CLASS_RE = re.compile(r"\b(?:class|interface|enum|record)\s+(\w+)")
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_LINE_COMMENT_RE = re.compile(r"//[^\n]*")
_STRING_LITERAL_RE = re.compile(r'"(?:\\.|[^"\\])*"')
_ANNOTATION_RE = re.compile(r"@\w+(?:\([^)]*\))?")


def _strip_noise(text: str) -> str:
    """Remove comments, string literals, and annotations.

    String literals are replaced with empty quotes (rather than fully removed)
    to preserve code structure. Annotations are stripped entirely so the
    method-declaration regex doesn't have to accommodate arbitrary annotation
    expressions.
    """
    text = _BLOCK_COMMENT_RE.sub("", text)
    text = _LINE_COMMENT_RE.sub("", text)
    text = _STRING_LITERAL_RE.sub('""', text)
    text = _ANNOTATION_RE.sub("", text)
    return text


def _split_params(params_text: str) -> list[str]:
    """Split a Java parameter list on top-level commas, returning type strings.

    Correctly handles generics (`Map<String, String>`) and arrays (`byte[]`),
    drops `final` and annotations, and converts varargs `Foo...` to `Foo[]`.
    """
    if not params_text or not params_text.strip():
        return []

    parts: list[str] = []
    depth = 0
    current: list[str] = []
    for ch in params_text:
        if ch in "<[":
            depth += 1
            current.append(ch)
        elif ch in ">]":
            depth -= 1
            current.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
    if current:
        parts.append("".join(current).strip())

    types: list[str] = []
    for raw in parts:
        if not raw:
            continue
        # Drop annotations and `final` qualifier (already pre-stripped at
        # file level, but params can carry them per-arg).
        raw = _ANNOTATION_RE.sub("", raw).strip()
        raw = re.sub(r"^\s*final\s+", "", raw)
        # Last whitespace-separated token is the variable name (or absent
        # if the source was malformed). Everything before is the type.
        tokens = raw.rsplit(None, 1)
        type_text = tokens[0] if len(tokens) == 2 else tokens[0]
        type_text = type_text.strip()
        # Convert varargs `Foo...` to `Foo[]`
        type_text = re.sub(r"\.\.\.\s*$", "[]", type_text)
        if type_text:
            types.append(type_text)
    return types


def _parse_class_fqn(text: str, fallback: str) -> str:
    """Best-effort fully-qualified class name from a .java file's text.

    Falls back to the file stem if the top-level type declaration cannot be
    located (e.g., jadx emitted a fragment).
    """
    pkg_match = _PACKAGE_RE.search(text)
    cls_match = _TOP_CLASS_RE.search(text) or _FALLBACK_CLASS_RE.search(text)
    cls = cls_match.group(1) if cls_match else fallback
    if pkg_match:
        return f"{pkg_match.group(1)}.{cls}"
    return cls


def _extract_from_text(
    text: str, source_file: Optional[str], fallback_class: str
) -> list[JavaNativeMethod]:
    cleaned = _strip_noise(text)
    fqn = _parse_class_fqn(cleaned, fallback_class)

    results: list[JavaNativeMethod] = []
    for m in _NATIVE_METHOD_RE.finditer(cleaned):
        modifiers = m.group("modifiers")
        if not re.search(r"\bnative\b", modifiers):
            continue
        is_static = bool(re.search(r"\bstatic\b", modifiers))
        return_type = re.sub(r"\s+", " ", m.group("return")).strip()
        method_name = m.group("name")
        # Filter out keyword-reserved names that would never be a method
        # (defensive — shouldn't happen on real jadx output).
        if method_name in {"return", "if", "while", "for", "switch", "catch"}:
            continue
        arg_types = _split_params(m.group("params"))
        results.append(
            JavaNativeMethod(
                class_fqn=fqn,
                method_name=method_name,
                return_type=return_type,
                arg_types=arg_types,
                is_static=is_static,
                source_file=source_file,
            )
        )
    return results


def extract_native_methods(java_root: str | Path) -> list[JavaNativeMethod]:
    """Walk a jadx output tree and return every `native` method declaration.

    `java_root` is typically the ``output_dir`` of a previous ``run_jadx`` call
    (jadx writes Java sources under ``<output_dir>/sources/...`` by default,
    but rglob handles either layout).

    Files that fail to read (encoding errors, permissions) are skipped rather
    than aborting — jadx output frequently contains a few unparseable artifacts
    and they shouldn't block correlation. Order is determined by sorted rglob;
    results within a file follow source declaration order.
    """
    root = Path(java_root)
    if not root.exists():
        raise JadxError(f"java root not found: {root}")
    if not root.is_dir():
        raise JadxError(f"not a directory: {root}")

    findings: list[JavaNativeMethod] = []
    for java_file in sorted(root.rglob("*.java")):
        try:
            text = java_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(java_file.relative_to(root))
        fallback = java_file.stem
        findings.extend(_extract_from_text(text, rel, fallback))
    return findings


def decompile_apk(
    apk_path: str | Path,
    output_dir: str | Path,
    config: Optional[JadxConfig] = None,
) -> tuple[JadxResult, list[JavaNativeMethod]]:
    """Convenience: run jadx and extract native methods in one call.

    Returns ``(jadx_result, native_methods)``. On invocation failure, propagates
    ``JadxNotFoundError`` / ``JadxRunError`` without producing partial extraction.
    """
    result = run_jadx(apk_path, output_dir, config=config)
    natives = extract_native_methods(result.output_dir)
    return result, natives

"""Cross-platform stub-executable helper for subprocess tests.

Many tests fake apktool/jadx/ghidra by writing a tiny shell script and
passing it as the binary path to subprocess.run. That works on POSIX but
fails on Windows ("WinError 193: %1 is not a valid Win32 application")
because Windows has no sh interpreter.

This helper produces a stub binary whose behavior is described
declaratively (parse one ``-o``/``-d`` style flag, mkdir some paths under
it, write some files, exit with a code, optionally print to stderr). On
POSIX it returns an executable Python script with a shebang. On Windows
it returns a ``.cmd`` shim that delegates to the same Python script via
``sys.executable``. Either way, callers just pass the returned Path to
subprocess.run as argv[0] and the production code path is exercised
unchanged.
"""

from __future__ import annotations

import json
import os
import stat as _stat
import sys
from pathlib import Path
from typing import Mapping, Sequence


_PY_TEMPLATE = '''\
#!{shebang_python}
"""Auto-generated stub executable. Do not edit by hand."""
import json, os, sys
from pathlib import Path

SPEC = json.loads({spec_json!r})


def main(argv):
    out_flag = SPEC.get("out_flag")
    out_dir = None
    args = list(argv)
    while args:
        a = args.pop(0)
        if out_flag and a == out_flag and args:
            out_dir = Path(args.pop(0))
            break
    if out_dir is not None:
        out_dir.mkdir(parents=True, exist_ok=True)
        for rel in SPEC.get("mkdirs", []):
            (out_dir / rel).mkdir(parents=True, exist_ok=True)
        for rel, content in SPEC.get("files", {{}}).items():
            target = out_dir / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
    stderr_text = SPEC.get("stderr_text") or ""
    if stderr_text:
        sys.stderr.write(stderr_text)
    return int(SPEC.get("exit_code", 0))


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
'''


def make_stub_executable(
    path: Path | str,
    *,
    out_flag: str | None = None,
    files: Mapping[str, str] | None = None,
    mkdirs: Sequence[str] = (),
    exit_code: int = 0,
    stderr_text: str = "",
) -> Path:
    """Write a cross-platform stub executable.

    ``path`` is treated as the *base* path; the suffix is normalized to
    ``.py`` for the Python implementation, and on Windows a sibling ``.cmd``
    shim is also written and returned. The returned path can be handed
    directly to ``subprocess.run`` (or to ``apktool_path``/``jadx_path``
    style configuration) on either platform.
    """
    base = Path(path)
    py_path = base.with_suffix(".py")
    spec = {
        "out_flag": out_flag,
        "files": dict(files or {}),
        "mkdirs": list(mkdirs),
        "exit_code": int(exit_code),
        "stderr_text": stderr_text,
    }
    body = _PY_TEMPLATE.format(
        shebang_python=sys.executable.replace("\\", "/"),
        spec_json=json.dumps(spec),
    )
    py_path.write_text(body, encoding="utf-8")

    if os.name == "nt":
        cmd_path = base.with_suffix(".cmd")
        cmd_path.write_text(
            "@echo off\r\n"
            f'"{sys.executable}" "{py_path}" %*\r\n'
            "exit /b %ERRORLEVEL%\r\n",
            encoding="utf-8",
        )
        return cmd_path

    py_path.chmod(py_path.stat().st_mode | _stat.S_IXUSR | _stat.S_IXGRP | _stat.S_IXOTH)
    return py_path

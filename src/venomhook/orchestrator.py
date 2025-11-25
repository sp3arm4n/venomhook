from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Iterable, List, Sequence


def build_frida_command(
    target: str,
    script: Path,
    *,
    frida_path: str = "frida",
    attach: bool = False,
    no_pause: bool = True,
    extra_args: Sequence[str] | None = None,
) -> List[str]:
    cmd: List[str] = [frida_path]
    if attach:
        cmd += ["-p", target]
    else:
        cmd += ["-f", target]
    cmd += ["-l", str(script)]
    if no_pause:
        cmd.append("--no-pause")
    if extra_args:
        cmd.extend(extra_args)
    return cmd


def run_frida(
    target: str,
    script: Path,
    *,
    frida_path: str = "frida",
    attach: bool = False,
    no_pause: bool = True,
    extra_args: Sequence[str] | None = None,
    log_file: Path | None = None,
    dry_run: bool = False,
) -> str:
    cmd = build_frida_command(
        target=target,
        script=script,
        frida_path=frida_path,
        attach=attach,
        no_pause=no_pause,
        extra_args=extra_args,
    )
    cmd_str = " ".join(cmd)
    if dry_run:
        return cmd_str

    stdout_pipe = subprocess.PIPE if log_file else None
    stderr_pipe = subprocess.STDOUT if log_file else None
    proc = subprocess.run(cmd, stdout=stdout_pipe, stderr=stderr_pipe, text=True)
    if log_file and proc.stdout:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        log_file.write_text(proc.stdout)
    if proc.returncode != 0:
        raise RuntimeError(f"frida exited with code {proc.returncode}")
    return cmd_str

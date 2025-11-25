from __future__ import annotations

import logging
import subprocess
import tempfile
from pathlib import Path
from typing import Sequence


logger = logging.getLogger(__name__)


class GhidraRunner:
    """Thin wrapper to invoke Ghidra headless (or a compatible stub).

    Expected to run a postScript that writes StaticMeta JSON to `out_static_meta`.
    When `post_script` is None, the runner will simply execute `headless_cmd` with
    `[binary_path, out_static_meta]` arguments (useful for tests or custom stubs).
    """

    def __init__(
        self,
        headless_cmd: Sequence[str],
        post_script: Path | None = None,
        project_dir: Path | None = None,
        project_name: str = "venomhook_project",
        extra_args: Sequence[str] | None = None,
    ):
        self.headless_cmd = list(headless_cmd)
        self.post_script = post_script
        self.project_dir = project_dir or Path(tempfile.gettempdir()) / "ghidra_projects"
        self.project_name = project_name
        self.extra_args = list(extra_args or [])

    def build_command(self, binary_path: Path, out_static_meta: Path) -> list[str]:
        if self.post_script:
            self.project_dir.mkdir(parents=True, exist_ok=True)
            return [
                *self.headless_cmd,
                str(self.project_dir),
                self.project_name,
                "-import",
                str(binary_path),
                "-overwrite",
                "-postScript",
                str(self.post_script),
                str(out_static_meta),
                *self.extra_args,
            ]
        # Fallback/simple stub mode: assume cmd takes binary + output
        return [*self.headless_cmd, str(binary_path), str(out_static_meta), *self.extra_args]

    def run(self, binary_path: Path, out_static_meta: Path) -> None:
        cmd = self.build_command(binary_path, out_static_meta)
        logger.info("running Ghidra headless: %s", " ".join(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            logger.error("Ghidra headless failed: %s", result.stderr)
            raise RuntimeError(f"Ghidra headless failed (code {result.returncode})")
        if not out_static_meta.exists():
            raise RuntimeError(f"Ghidra headless did not produce output: {out_static_meta}")
        if result.stdout:
            logger.debug("Ghidra stdout: %s", result.stdout.strip())
        if result.stderr:
            logger.debug("Ghidra stderr: %s", result.stderr.strip())

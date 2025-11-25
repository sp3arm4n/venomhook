import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from venomhook.orchestrator import build_frida_command, run_frida


def test_build_frida_command_spawn() -> None:
    cmd = build_frida_command("target.exe", Path("venomhook.frida.js"), frida_path="frida", no_pause=True)
    assert cmd[:3] == ["frida", "-f", "target.exe"]
    assert "--no-pause" in cmd
    assert "venomhook.frida.js" in cmd


def test_build_frida_command_attach_and_dry_run() -> None:
    cmd = build_frida_command("1234", Path("venomhook.frida.js"), frida_path="frida", attach=True, no_pause=False)
    assert cmd[:3] == ["frida", "-p", "1234"]
    assert "--no-pause" not in cmd

    cmd_str = run_frida("1234", Path("venomhook.frida.js"), frida_path="frida", attach=True, dry_run=True)
    assert "-p 1234" in cmd_str

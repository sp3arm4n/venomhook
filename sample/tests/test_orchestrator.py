import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from venomhook.orchestrator import build_frida_command, run_frida


class OrchestratorTests(unittest.TestCase):
    def test_build_frida_command_spawn(self) -> None:
        cmd = build_frida_command("target.exe", Path("venomhook.js"), frida_path="frida", no_pause=True)
        self.assertEqual(cmd[:3], ["frida", "-f", "target.exe"])
        self.assertIn("--no-pause", cmd)
        self.assertIn("venomhook.js", cmd)


    def test_build_frida_command_attach_and_dry_run(self) -> None:
        cmd = build_frida_command("1234", Path("venomhook.js"), frida_path="frida", attach=True, no_pause=False)
        self.assertEqual(cmd[:3], ["frida", "-p", "1234"])
        self.assertNotIn("--no-pause", cmd)

        cmd_str = run_frida("1234", Path("venomhook.js"), frida_path="frida", attach=True, dry_run=True)
        self.assertIn("-p 1234", cmd_str)


if __name__ == "__main__":
    unittest.main()

import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from venomhook.cli import main

SAMPLE_STATIC_META = ROOT / "sample/examples/static_meta.sample.json"


class CliE2eTests(unittest.TestCase):
    def test_offset_e2e_dry_run_creates_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "out"
            argv = [
                "offset-e2e",
                "--static-json",
                str(SAMPLE_STATIC_META),
                "--target",
                "sample.exe",
                "--out-dir",
                str(out_dir),
            ]
            main(argv)

            self.assertTrue((out_dir / "venomhook.json").exists())
            self.assertTrue((out_dir / "venomhook.md").exists())
            self.assertTrue((out_dir / "venomhook.js").exists())
            self.assertTrue((out_dir / "venomhook.db").exists())

    def test_offset_e2e_accepts_static_llm_flags(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "out"
            argv = [
                "offset-e2e",
                "--static-json",
                str(SAMPLE_STATIC_META),
                "--target",
                "sample.exe",
                "--out-dir",
                str(out_dir),
                "--use-llm-tagging",
                "--llm-provider",
                "echo",
                "--no-llm-cache",
            ]
            main(argv)

            payload = json.loads((out_dir / "venomhook.json").read_text())
            self.assertIsInstance(payload, list)
            self.assertTrue((out_dir / "venomhook.js").exists())

    def test_offset_e2e_rejects_runtime_report_llm_flag(self) -> None:
        with mock.patch("sys.stderr", new=io.StringIO()):
            with self.assertRaises(SystemExit) as ctx:
                main([
                    "offset-e2e",
                    "--static-json",
                    str(SAMPLE_STATIC_META),
                    "--target",
                    "sample.exe",
                    "--use-llm-report",
                ])
        self.assertNotEqual(ctx.exception.code, 0)


if __name__ == "__main__":
    unittest.main()

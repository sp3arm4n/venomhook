import tempfile
import unittest
from pathlib import Path

from venomhook.cli import main

ROOT = Path(__file__).resolve().parents[1]
SAMPLE_STATIC_META = ROOT / "examples/static_meta.sample.json"


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


if __name__ == "__main__":
    unittest.main()

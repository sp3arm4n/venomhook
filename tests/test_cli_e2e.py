import tempfile
from pathlib import Path

from venomhook.cli import main

ROOT = Path(__file__).resolve().parents[1]
SAMPLE_STATIC_META = ROOT / "examples/static_meta.sample.json"


def test_offset_e2e_dry_run_creates_artifacts(tmp_path: Path) -> None:
    out_dir = tmp_path / "out"
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

    assert (out_dir / "venomhook.json").exists()
    assert (out_dir / "venomhook.md").exists()
    assert (out_dir / "venomhook.frida.js").exists()
    assert (out_dir / "venomhook.db").exists()

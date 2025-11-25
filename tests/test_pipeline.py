import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from venomhook.dynamic_pipeline import DynamicPipeline
from venomhook.ghidra_runner import GhidraRunner
from venomhook.scoring import ScoreConfig
from venomhook.static_pipeline import StaticPipeline
from venomhook.store import HookSpecStore
from venomhook.report import render_markdown

SAMPLE_STATIC_META = ROOT / "examples/static_meta.sample.json"


class PipelineTests(unittest.TestCase):
    def test_static_pipeline_generates_hookspec(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            out_hookspec = Path(tmpdir) / "venomhook.json"
            pipeline = StaticPipeline(top_n=5, sig_max_bytes=8)
            hooks = pipeline.run_from_static_meta(SAMPLE_STATIC_META, out_hookspec)

            self.assertEqual(len(hooks), 2)
            self.assertEqual(hooks[0].offset, 0x123A0)
            self.assertIn("network", hooks[0].tags)
            self.assertTrue(out_hookspec.exists())
            # signature length is capped
            self.assertLessEqual(len(hooks[0].sig.split()), 8)

            loaded = HookSpecStore.load(out_hookspec)
            self.assertEqual(len(loaded), 2)
            self.assertEqual(loaded[0].offset, hooks[0].offset)

    def test_dynamic_pipeline_generates_frida_script(self) -> None:
        pipeline = StaticPipeline(top_n=2)
        hooks = pipeline.run_from_static_meta(SAMPLE_STATIC_META, Path(tempfile.gettempdir()) / "venomhook.json")

        dyn = DynamicPipeline(
            target="sample.exe",
            log_format="json",
            log_prefix="[venomhook]",
            scenario_message="start",
            auto_start_scenario=True,
            hexdump_len=32,
            string_args=[0],
            string_ret=True,
            string_len=64,
            scan_size=4096,
            retry_attach=2,
        )
        script = dyn.generate_script(hooks)

        self.assertIn("Module.findBaseAddress", script)
        self.assertIn("hook_imports__connect__recv__send", script)
        self.assertIn("0x123a0", script.lower())
        self.assertIn("Interceptor.attach", script)
        self.assertIn("LOG_FORMAT = \"json\"", script)
        self.assertIn("runScenario()", script)
        self.assertIn("HEXDUMP_LEN = 32", script)
        self.assertIn("STRING_LEN = 64", script)
        self.assertIn('logEvent("string", "imports__connect__recv__send"', script)
        self.assertIn("SCAN_SIZE = 4096", script)
        self.assertIn("RETRY_ATTACH = 2", script)

    def test_hookspec_store_sqlite_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            json_out = Path(tmpdir) / "venomhook.json"
            db_out = Path(tmpdir) / "venomhook.db"

            pipeline = StaticPipeline(top_n=2)
            hooks = pipeline.run_from_static_meta(SAMPLE_STATIC_META, json_out)
            HookSpecStore.save(db_out, hooks)

            loaded_from_json = HookSpecStore.load(json_out)
            loaded_from_db = HookSpecStore.load(db_out)

            self.assertEqual(len(loaded_from_json), len(loaded_from_db))
            self.assertEqual(loaded_from_db[0].offset, hooks[0].offset)
            self.assertEqual(loaded_from_db[0].module, hooks[0].module)

    def test_markdown_report_generation(self) -> None:
        pipeline = StaticPipeline(top_n=2)
        hooks = pipeline.run_from_static_meta(SAMPLE_STATIC_META, Path(tempfile.gettempdir()) / "venomhook.json")

        md = render_markdown(hooks)
        self.assertIn("HookSpec Summary", md)
        self.assertIn("0x123a0", md.lower())
        self.assertIn("imports: connect, recv, send", md)

    def test_scoring_config_changes_order(self) -> None:
        cfg = ScoreConfig(network_weight=0, file_weight=100)
        pipeline = StaticPipeline(top_n=2, score_config=cfg)
        hooks = pipeline.run_from_static_meta(SAMPLE_STATIC_META, Path(tempfile.gettempdir()) / "venomhook.json")
        # file_writer should rank higher due to file weight boost
        self.assertEqual(hooks[0].offset, 0x20000)

    def test_ghidra_runner_stub(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            stub_script = Path(tmpdir) / "stub.py"
            out_static = Path(tmpdir) / "out.json"
            stub_script.write_text(
                "import json,sys\n"
                "src='{}'\n".format(SAMPLE_STATIC_META.as_posix()) +
                "dst=sys.argv[2]\n"
                "import shutil; shutil.copy(src, dst)\n",
                encoding="utf-8",
            )
            runner = GhidraRunner(headless_cmd=["python3", stub_script.as_posix()], post_script=None)
            runner.run(SAMPLE_STATIC_META, out_static)
            self.assertTrue(out_static.exists())


if __name__ == "__main__":
    unittest.main()

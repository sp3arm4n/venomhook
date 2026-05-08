"""CLI integration test for ``offset-static --use-llm-tagging``.

Drives the full subcommand against the bundled static_meta.sample.json
with the ``echo`` provider so no live API call is made. Verifies:
    * The CLI accepts the new flags (no argparse error).
    * The pipeline writes a HookSpec JSON.
    * No semantic:* tags are added in the echo path (echo response
      doesn't match the strict tag:reason format), confirming the
      silent-degrade contract.
    * --no-llm-cache stops the LLM cache file from being created.
"""

from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SAMPLE_STATIC_META = ROOT / "examples/static_meta.sample.json"
sys.path.insert(0, str(ROOT.parent / "src"))

from venomhook.cli import main


class CliLLMTaggingFlagsTest(unittest.TestCase):
    def _assert_argparse_error(self, argv: list[str]) -> None:
        with mock.patch("sys.stderr", new=io.StringIO()):
            with self.assertRaises(SystemExit) as ctx:
                main(argv)
        self.assertNotEqual(ctx.exception.code, 0)

    def test_offset_static_with_use_llm_tagging_echo(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "venomhook.json"
            argv = [
                "offset-static",
                "--static-json", str(SAMPLE_STATIC_META),
                "--out", str(out),
                "--use-llm-tagging",
                "--llm-provider", "echo",
                "--llm-token-budget", "100000",
                "--no-llm-cache",
            ]
            main(argv)

            self.assertTrue(out.exists())
            payload = json.loads(out.read_text())
            self.assertIsInstance(payload, list)
            # Echo provider response doesn't match tag:reason format ->
            # zero semantic:* tags should appear on any HookSpec.
            for spec in payload:
                for tag in spec.get("tags", []):
                    self.assertFalse(
                        tag.startswith("semantic:"),
                        f"unexpected semantic tag from echo: {tag}",
                    )

    def test_offset_static_no_llm_flag_returns_no_options(self) -> None:
        # Without --use-llm-* flags, _build_llm_options must return (None, None)
        # — proves the LLM stack stays out of the pipeline path.
        import argparse
        from venomhook.cli import _build_llm_options
        args = argparse.Namespace(
            use_llm_tagging=False,
            use_llm_proto=False,
            use_llm_flow=False,
            use_llm_recovery=False,
            llm_provider="anthropic",
            llm_model=None,
            llm_token_budget=20000,
            llm_cache_dir=None,
            no_llm_cache=False,
        )
        self.assertEqual(_build_llm_options(args), (None, None, None, None))

        # And the subcommand still runs end-to-end with no LLM flags.
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "venomhook.json"
            main([
                "offset-static",
                "--static-json", str(SAMPLE_STATIC_META),
                "--out", str(out),
            ])
            self.assertTrue(out.exists())

    def test_no_llm_cache_disables_cache(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cache_dir = Path(tmp) / "cache"  # would have been created if cache wired
            out = Path(tmp) / "venomhook.json"
            argv = [
                "offset-static",
                "--static-json", str(SAMPLE_STATIC_META),
                "--out", str(out),
                "--use-llm-tagging",
                "--llm-provider", "echo",
                "--llm-cache-dir", str(cache_dir),
                "--no-llm-cache",
            ]
            main(argv)
            self.assertFalse(cache_dir.exists(),
                             "cache dir created despite --no-llm-cache")

    def test_offset_static_rejects_runtime_report_llm_flag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "venomhook.json"
            self._assert_argparse_error([
                "offset-static",
                "--static-json", str(SAMPLE_STATIC_META),
                "--out", str(out),
                "--use-llm-report",
            ])

    def test_offset_report_runtime_rejects_static_llm_flag(self) -> None:
        self._assert_argparse_error([
            "offset-report-runtime",
            "--log", "frida.log",
            "--out-md", "summary.md",
            "--use-llm-tagging",
        ])

    def test_report_flag_does_not_build_static_llm_runtime(self) -> None:
        import argparse
        from venomhook.cli import _build_llm_options

        with tempfile.TemporaryDirectory() as tmp:
            cache_dir = Path(tmp) / "cache"
            args = argparse.Namespace(
                use_llm_tagging=False,
                use_llm_proto=False,
                use_llm_flow=False,
                use_llm_report=True,
                use_llm_recovery=False,
                llm_provider="echo",
                llm_model=None,
                llm_token_budget=20000,
                llm_cache_dir=cache_dir,
                no_llm_cache=False,
            )
            self.assertEqual(_build_llm_options(args), (None, None, None, None))
            self.assertFalse(cache_dir.exists())

    def test_llm_cache_dir_creates_sqlite(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cache_dir = Path(tmp) / "cache"
            out = Path(tmp) / "venomhook.json"
            argv = [
                "offset-static",
                "--static-json", str(SAMPLE_STATIC_META),
                "--out", str(out),
                "--use-llm-tagging",
                "--llm-provider", "echo",
                "--llm-cache-dir", str(cache_dir),
            ]
            main(argv)
            self.assertTrue((cache_dir / "llm_cache.sqlite3").exists())


if __name__ == "__main__":
    unittest.main()

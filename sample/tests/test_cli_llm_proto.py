"""CLI integration test for ``offset-static --use-llm-proto``.

Drives the full subcommand against the bundled static_meta.sample.json
with the ``echo`` provider so no live API call is made. Verifies:
    * --use-llm-proto is accepted by argparse.
    * The pipeline writes a HookSpec JSON.
    * No proto is filled in the echo path (echo response doesn't match
      the strict ret:/argN: format), confirming silent-degrade.
    * Combining --use-llm-tagging + --use-llm-proto shares one budget /
      one cache (no double-allocation).
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SAMPLE_STATIC_META = ROOT / "examples/static_meta.sample.json"
sys.path.insert(0, str(ROOT.parent / "src"))

from venomhook.cli import main


class CliUseLLMProtoTest(unittest.TestCase):
    def test_use_llm_proto_with_echo(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "venomhook.json"
            main([
                "offset-static",
                "--static-json", str(SAMPLE_STATIC_META),
                "--out", str(out),
                "--use-llm-proto",
                "--llm-provider", "echo",
                "--llm-token-budget", "100000",
                "--no-llm-cache",
            ])
            self.assertTrue(out.exists())
            payload = json.loads(out.read_text())
            self.assertIsInstance(payload, list)
            # Echo response doesn't match ret:/argN: format -> no proto filled.
            for spec in payload:
                proto = spec.get("proto") or {}
                self.assertIsNone(proto.get("ret"))
                self.assertEqual(proto.get("args", []), [])

    def test_combined_flags_share_runtime(self) -> None:
        # Build options directly to confirm shared runtime: same provider,
        # same budget object, same cache object across both options.
        import argparse
        from venomhook.cli import _build_llm_options

        with tempfile.TemporaryDirectory() as tmp:
            args = argparse.Namespace(
                use_llm_tagging=True,
                use_llm_proto=True,
                use_llm_flow=False,
                llm_provider="echo",
                llm_model=None,
                llm_token_budget=20000,
                llm_cache_dir=Path(tmp),
                no_llm_cache=False,
            )
            tagging, proto, flow = _build_llm_options(args)
            self.assertIsNotNone(tagging)
            self.assertIsNotNone(proto)
            self.assertIsNone(flow)
            # Same instances — single budget cap shared across both points.
            self.assertIs(tagging.provider, proto.provider)
            self.assertIs(tagging.budget, proto.budget)
            self.assertIs(tagging.cache, proto.cache)


if __name__ == "__main__":
    unittest.main()

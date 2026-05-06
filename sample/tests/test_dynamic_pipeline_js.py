"""Tests focused on the generated Frida JS — syntax safety, escape correctness, and sig fallback shape.

These tests guard against regressions in the JS generator that aren't caught by behavior tests
(syntax errors, injection-style breakage from unescaped user input, broken sig fallback wiring).
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from venomhook.dynamic_pipeline import DynamicPipeline
from venomhook.models import HookConfig, HookSpec, OnEnterHook, OnLeaveHook


def _make_spec(
    *,
    module: str = "libfoo.so",
    name: str = "Java_com_example_MyClass_doCrypto",
    offset: int = 0x1234,
    sig: str | None = "48 89 ?? 24 08 57",
    log_args: list[int] | None = None,
    hexdump_args: list[int] | None = None,
    log_ret: bool = True,
    hexdump_ret: bool = False,
) -> HookSpec:
    return HookSpec(
        module=module,
        arch="arm64",
        offset=offset,
        sig=sig,
        name=name,
        tags=["jni"],
        hook=HookConfig(
            onEnter=OnEnterHook(
                log_args=log_args if log_args is not None else [0, 1],
                hexdump_args=hexdump_args if hexdump_args is not None else [0],
            ),
            onLeave=OnLeaveHook(log_ret=log_ret, hexdump_ret=hexdump_ret),
        ),
    )


class JsGeneratorTests(unittest.TestCase):
    def test_strings_are_json_escaped(self) -> None:
        """Module/name/sig/prefix/scenario containing JS-special chars must not break the script."""
        spec = _make_spec(
            module='lib"with\\quote.so',
            name="hook_with_special_chars",
            sig='48 "?? 24',  # malicious sig with quote
        )
        pipe = DynamicPipeline(
            target="com.example.app",
            log_format="json",
            log_prefix='[venom"hook\\test]',
            scenario_message='start with "quote"',
            auto_start_scenario=True,
        )
        script = pipe.generate_script([spec])

        # If escaping is correct, json.dumps surrounds with quotes and escapes inner quotes
        self.assertIn(r'"lib\"with\\quote.so"', script)
        self.assertIn(r'"[venom\"hook\\test]"', script)
        self.assertIn(r'"start with \"quote\""', script)
        # Naked unescaped sequences must NOT appear at JS string-literal level
        self.assertNotIn('"lib"with\\quote.so"', script)

    def test_generated_js_passes_node_check(self) -> None:
        """If `node` is on PATH, the generated JS must parse without syntax errors."""
        node = shutil.which("node")
        if node is None:
            self.skipTest("node not available on PATH")

        spec = _make_spec(
            module='lib"with\\quote.so',
            name="hook_with_special_chars",
            sig='48 "?? 24',
        )
        pipe = DynamicPipeline(
            target="com.example.app",
            log_format="json",
            log_prefix='[venom"hook\\test]',
            scenario_message='start with "quote"',
            auto_start_scenario=True,
        )
        script = pipe.generate_script([spec])

        import tempfile

        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as fp:
            fp.write(script)
            tmp_path = fp.name
        try:
            result = subprocess.run(
                [node, "--check", tmp_path], capture_output=True, text=True
            )
            self.assertEqual(
                result.returncode,
                0,
                f"node --check failed: stdout={result.stdout!r} stderr={result.stderr!r}",
            )
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_sig_fallback_uses_sync_scan_and_byte_compare(self) -> None:
        """The sig fallback must use Memory.scanSync (not async) and byte-compare via sigMatchesAt."""
        spec = _make_spec(sig="48 89 ?? 24")
        pipe = DynamicPipeline(target="t")
        script = pipe.generate_script([spec])

        # Old (broken) async API must be gone
        self.assertNotIn("Memory.scan(base", script)
        # New synchronous API present
        self.assertIn("Memory.scanSync(base", script)
        # New byte-compare helper present and used as the trigger condition
        self.assertIn("function sigMatchesAt(", script)
        self.assertIn("if (!sigMatchesAt(target, sig))", script)
        self.assertIn('msg: "signature not found in module"});\n        return;', script)
        self.assertIn('msg: "signature scan error: " + e});\n      return;', script)
        # Old (broken) trigger must be gone
        self.assertNotIn("!target.readByteArray(1)", script)
        # Wildcards must be honored
        self.assertIn("if (tokens[i] === '??') continue;", script)

    def test_hookstats_increments_once_per_call(self) -> None:
        """hookStats counter must be incremented once at onEnter prologue, not per-arg."""
        spec = _make_spec(log_args=[0, 1, 2], hexdump_args=[0])
        pipe = DynamicPipeline(target="t")
        script = pipe.generate_script([spec])

        # Exactly one increment line should exist for this hook (regardless of arg count)
        increment_line = 'hookStats["Java_com_example_MyClass_doCrypto"] = (hookStats["Java_com_example_MyClass_doCrypto"] || 0) + 1;'
        self.assertEqual(script.count(increment_line), 1)
        # And a single _count alias
        self.assertEqual(
            script.count('const _count = hookStats["Java_com_example_MyClass_doCrypto"];'), 1
        )

    def test_no_unresolved_format_placeholder(self) -> None:
        """Regression for the f-string typo at the hexdump_ret branch — '{name}' must never appear literally."""
        spec = _make_spec(hexdump_ret=True)
        pipe = DynamicPipeline(target="t")
        script = pipe.generate_script([spec])

        self.assertNotIn('"{name}"', script)
        self.assertNotIn("{name}", script)

    def test_no_sig_omits_fallback_block(self) -> None:
        """When HookSpec.sig is None, no fallback / scan code should be emitted."""
        spec = _make_spec(sig=None)
        pipe = DynamicPipeline(target="t")
        script = pipe.generate_script([spec])

        self.assertNotIn("Memory.scanSync", script)
        self.assertNotIn("sigMatchesAt(target", script)

    def test_log_format_and_prefix_use_json_dumps(self) -> None:
        """LOG_FORMAT and LOG_PREFIX constants must use JSON-escaped string literals."""
        pipe = DynamicPipeline(target="t", log_format="json", log_prefix="[v]")
        script = pipe.generate_script([_make_spec()])
        self.assertIn('const LOG_FORMAT = "json";', script)
        self.assertIn('const LOG_PREFIX = "[v]";', script)


if __name__ == "__main__":
    unittest.main()

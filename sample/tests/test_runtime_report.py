import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from venomhook.runtime_report import parse_log_lines, write_markdown_summary, write_html_summary


class RuntimeReportTests(unittest.TestCase):
    def test_parse_log_lines_counts_events(self) -> None:
        lines = [
            '{"event": "enter", "hook": "foo"}',
            '{"event": "leave", "hook": "foo"}',
            '{"event": "hexdump", "hook": "foo"}',
            '{"event": "error", "hook": "foo"}',
            '{"event": "enter", "hook": "bar"}',
            '{"event": "string", "hook": "foo", "msg": "hello"}',
            '{"event": "enter", "hook": "foo", "value": "0x123"}',
            '{"event": "leave", "hook": "foo", "ret": "0x456"}',
        ]
        summary = parse_log_lines(lines)
        self.assertEqual(summary["total_events"], 8)
        self.assertEqual(summary["hexdumps"], 1)
        self.assertEqual(summary["errors"]["foo"], 1)
        # foo has two "enter" events (lines 1 and 7), bar has one
        self.assertEqual(summary["hooks"]["foo"]["enter"], 2)
        self.assertEqual(summary["hooks"]["bar"]["enter"], 1)
        self.assertEqual(summary["strings"]["foo"][0], "hello")
        self.assertEqual(summary["enter_samples"]["foo"][0], "0x123")
        self.assertEqual(summary["ret_samples"]["foo"][0], "0x456")


    def test_write_markdown_summary(self) -> None:
        summary = {
            "hooks": {"foo": {"enter": 2, "leave": 1, "hexdump": 1}, "bar": {"enter": 1}},
            "errors": {"foo": 1},
            "hexdumps": 1,
            "total_events": 4,
            "strings": {"foo": ["hello"], "bar": ["bye"]},
        }
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "summary.md"
            write_markdown_summary(summary, out)
            content = out.read_text()
        self.assertIn("Runtime Log Summary", content)
        self.assertIn("foo", content)
        self.assertIn("bar", content)
        self.assertIn("hello", content)
        self.assertIn("bye", content)

    def test_write_html_summary(self) -> None:
        summary = {
            "hooks": {"foo": {"enter": 1}},
            "errors": {"foo": 1},
            "hexdumps": 0,
            "total_events": 1,
            "strings": {"foo": ["hello"]},
        }
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "summary.html"
            write_html_summary(summary, out)
            html = out.read_text()
        self.assertIn("<html>", html)
        self.assertIn("foo", html)
        self.assertIn("hello", html)

    def test_write_html_summary_escapes_log_data(self) -> None:
        summary = {
            "hooks": {'<img src=x onerror="alert(1)">': {"enter": 1}},
            "errors": {},
            "hexdumps": 0,
            "total_events": 1,
            "strings": {"foo": ['<script>alert("x")</script>']},
            "enter_samples": {"foo": ["<b>arg</b>"]},
            "ret_samples": {"foo": ["<i>ret</i>"]},
        }
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "summary.html"
            write_html_summary(summary, out)
            html = out.read_text()
        self.assertNotIn("<script>", html)
        self.assertNotIn("<img", html)
        self.assertNotIn('onerror="', html)
        self.assertIn("&lt;script&gt;", html)
        self.assertIn("&lt;b&gt;arg&lt;/b&gt;", html)


if __name__ == "__main__":
    unittest.main()

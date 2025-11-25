import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from venomhook.runtime_report import parse_log_lines, write_markdown_summary, write_html_summary


def test_parse_log_lines_counts_events() -> None:
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
    assert summary["total_events"] == 8
    assert summary["hexdumps"] == 1
    assert summary["errors"]["foo"] == 1
    assert summary["hooks"]["foo"]["enter"] == 1
    assert summary["hooks"]["bar"]["enter"] == 1
    assert summary["strings"]["foo"][0] == "hello"
    assert summary["enter_samples"]["foo"][0] == "0x123"
    assert summary["ret_samples"]["foo"][0] == "0x456"


def test_write_markdown_summary(tmp_path: Path) -> None:
    summary = {
        "hooks": {"foo": {"enter": 2, "leave": 1, "hexdump": 1}, "bar": {"enter": 1}},
        "errors": {"foo": 1},
        "hexdumps": 1,
        "total_events": 4,
        "strings": {"foo": ["hello"], "bar": ["bye"]},
    }
    out = tmp_path / "summary.md"
    write_markdown_summary(summary, out)
    content = out.read_text()
    assert "Runtime Log Summary" in content
    assert "foo" in content
    assert "bar" in content
    assert "hello" in content
    assert "bye" in content

def test_write_html_summary(tmp_path: Path) -> None:
    summary = {
        "hooks": {"foo": {"enter": 1}},
        "errors": {"foo": 1},
        "hexdumps": 0,
        "total_events": 1,
        "strings": {"foo": ["hello"]},
    }
    out = tmp_path / "summary.html"
    write_html_summary(summary, out)
    html = out.read_text()
    assert "<html>" in html
    assert "foo" in html
    assert "hello" in html

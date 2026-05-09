"""Tests for native_strings — categorize ASCII strings extracted from a .so.

The categorizer is pure (input list -> NativeStringHints), so synthetic
inputs are fine. binary_meta._extract_strings is exercised separately
in test_binary_meta_strings.py with a fixture ELF.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from venomhook.native_strings import (
    NativeStringHints,
    categorize_strings,
    summarize_hints,
)


class CategorizeStringsTests(unittest.TestCase):
    def test_url_categories(self) -> None:
        hints = categorize_strings([
            "https://api.example.com/login",
            "http://10.0.0.1:8080/cb",
            "ftp://files.example.org/",
            "wss://chat.example.net/",
            "file:///etc/hosts",
            "irrelevant",
        ])
        self.assertEqual(len(hints.urls), 5)

    def test_url_does_not_double_count_as_ip(self) -> None:
        # http://10.0.0.1:8080/cb is a URL, not a bare IP literal.
        hints = categorize_strings(["http://10.0.0.1:8080/cb"])
        self.assertEqual(hints.urls, ["http://10.0.0.1:8080/cb"])
        self.assertEqual(hints.ip_endpoints, [])

    def test_ip_literal_separately(self) -> None:
        hints = categorize_strings([
            "10.0.0.1",
            "192.168.1.5:443",
            "203.0.113.42",
        ])
        self.assertEqual(len(hints.ip_endpoints), 3)

    def test_sensitive_paths(self) -> None:
        hints = categorize_strings([
            "/system/bin/sh",
            "/data/data/com.example/files",
            "/sdcard/secret.bin",
            "/proc/self/maps",
            "/vendor/etc/init",
            "/usr/local/lib",  # not sensitive — should not match
        ])
        self.assertEqual(len(hints.paths), 5)

    def test_shell_token_su(self) -> None:
        hints = categorize_strings([
            "/system/xbin/su",
            "su -c id",
            "execve",
            "popen",
            "magisk",
            "irrelevant",
        ])
        self.assertGreaterEqual(len(hints.shell_commands), 4)

    def test_crypto_algorithm_names(self) -> None:
        hints = categorize_strings([
            "AES/CBC/PKCS5Padding",
            "DES/ECB",
            "MD5",
            "SHA-256",
            "PBKDF2WithHmacSHA1",
            "BEGIN PUBLIC KEY",
            "irrelevant",
        ])
        self.assertEqual(len(hints.crypto), 6)

    def test_secret_hint_names(self) -> None:
        hints = categorize_strings([
            "api_key",
            "client_secret",
            "auth_token=",
            "X-Api-Key",
            "JWT",
            "innocent string",
        ])
        self.assertGreaterEqual(len(hints.secret_hints), 4)

    def test_sql_fragments(self) -> None:
        hints = categorize_strings([
            "SELECT * FROM users WHERE id = ?",
            "INSERT INTO logs (msg) VALUES (?)",
            "DROP TABLE temp",
            "PRAGMA cipher_default_kdf_iter = 256000",
            "innocent",
        ])
        self.assertEqual(len(hints.sql), 4)

    def test_debug_strings(self) -> None:
        hints = categorize_strings([
            "/Users/jenkins/build/src/secure.cpp:42",
            "assertion failed",
            "/some/path/file.cc:100",
            "regular text",
        ])
        self.assertGreaterEqual(len(hints.debug), 3)

    def test_dedup_preserves_first_occurrence(self) -> None:
        hints = categorize_strings([
            "https://api.example.com/x",
            "https://api.example.com/x",
            "https://api.example.com/x",
        ])
        self.assertEqual(hints.urls, ["https://api.example.com/x"])

    def test_per_category_cap(self) -> None:
        # 100 unique URLs — capped at 50 to keep reports bounded.
        urls = [f"https://h{i}.example.com/" for i in range(100)]
        hints = categorize_strings(urls)
        self.assertEqual(len(hints.urls), 50)

    def test_total_and_is_empty(self) -> None:
        empty = categorize_strings([])
        self.assertTrue(empty.is_empty)
        self.assertEqual(empty.total, 0)
        non_empty = categorize_strings(["http://a", "/system/bin/sh"])
        self.assertFalse(non_empty.is_empty)
        self.assertGreater(non_empty.total, 0)

    def test_to_from_dict_roundtrip(self) -> None:
        hints = categorize_strings([
            "https://api.example.com/x",
            "/sdcard/data",
            "AES/GCM",
        ])
        roundtripped = NativeStringHints.from_dict(hints.to_dict())
        self.assertEqual(roundtripped, hints)

    def test_to_dict_omits_empty_categories(self) -> None:
        hints = categorize_strings(["https://api.example.com/x"])
        d = hints.to_dict()
        self.assertIn("urls", d)
        for missing in ("ip_endpoints", "paths", "shell_commands",
                        "crypto", "secret_hints", "sql", "debug"):
            self.assertNotIn(missing, d)


class SummarizeHintsTests(unittest.TestCase):
    def test_empty(self) -> None:
        self.assertEqual(
            summarize_hints(NativeStringHints()),
            "(no audit-worthy strings)",
        )

    def test_mixed(self) -> None:
        hints = categorize_strings([
            "http://a.example", "AES/CBC", "/system/bin/sh",
        ])
        out = summarize_hints(hints)
        self.assertIn("URL", out)
        self.assertIn("crypto", out)
        self.assertIn("shell", out)


if __name__ == "__main__":
    unittest.main()

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
    attribute_strings_by_symbol_name,
    categorize_strings,
    classify_symbol_name,
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

    def test_ipv6_requires_colon(self) -> None:
        hints = categorize_strings([
            "deadbeef",
            "cafebabe",
            "2001:db8::1",
        ])
        self.assertEqual(hints.ip_endpoints, ["2001:db8::1"])

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


class ClassifySymbolNameTests(unittest.TestCase):
    """Phase 9-4: symbol-name -> category set."""

    def test_jni_crypto_symbol_classifies_as_crypto(self) -> None:
        cats = classify_symbol_name("Java_com_app_Crypto_encrypt")
        self.assertIn("crypto", cats)

    def test_jni_log_symbol_classifies_as_debug(self) -> None:
        cats = classify_symbol_name("Java_com_app_Logger_logSession")
        self.assertIn("debug", cats)

    def test_jni_url_symbol_classifies_as_urls(self) -> None:
        cats = classify_symbol_name("Java_com_app_Net_fetchUrl")
        self.assertIn("urls", cats)

    def test_camelcase_split_works(self) -> None:
        # "encryptPayload" should still be picked up — split on case
        cats = classify_symbol_name("encryptPayload")
        self.assertIn("crypto", cats)

    def test_obfuscated_returns_empty(self) -> None:
        # Single-char names commonly produced by ProGuard / R8 must NOT
        # match anything — better to under-attribute than guess.
        self.assertEqual(classify_symbol_name("a"), frozenset())
        self.assertEqual(classify_symbol_name("Java_a_b_c"), frozenset())

    def test_empty_string_safe(self) -> None:
        self.assertEqual(classify_symbol_name(""), frozenset())

    def test_token_boundary_check(self) -> None:
        # "key" is a category token but should NOT fire on "monkey"
        # (substring without word boundary).
        self.assertNotIn("crypto", classify_symbol_name("monkey"))
        # As a JNI export "Java_x_apiKey" SHOULD fire
        self.assertIn("crypto", classify_symbol_name("Java_x_apiKey"))


class AttributeStringsBySymbolNameTests(unittest.TestCase):
    """Phase 9-4: co-locality attribution."""

    def test_crypto_symbol_gets_crypto_strings(self) -> None:
        hints = NativeStringHints(
            crypto=["AES/CBC/PKCS5Padding", "MD5"],
            urls=["http://a.example"],
        )
        out = attribute_strings_by_symbol_name(
            ["Java_com_app_Cipher_encrypt"], hints
        )
        self.assertIn("Java_com_app_Cipher_encrypt", out)
        attr = out["Java_com_app_Cipher_encrypt"]
        self.assertIn("AES/CBC/PKCS5Padding", attr)
        self.assertIn("MD5", attr)
        # URL must not be attributed to a crypto-named symbol
        self.assertNotIn("http://a.example", attr)

    def test_url_symbol_gets_url_strings(self) -> None:
        hints = NativeStringHints(
            urls=["http://api.example/x"],
            crypto=["AES/CBC"],
        )
        out = attribute_strings_by_symbol_name(
            ["Java_com_app_Net_fetchUrl"], hints
        )
        self.assertEqual(
            out["Java_com_app_Net_fetchUrl"], ["http://api.example/x"]
        )

    def test_obfuscated_symbol_dropped(self) -> None:
        hints = NativeStringHints(crypto=["AES/CBC"])
        out = attribute_strings_by_symbol_name(["Java_a_b_c"], hints)
        self.assertEqual(out, {})

    def test_empty_hints_returns_empty(self) -> None:
        out = attribute_strings_by_symbol_name(
            ["Java_x_encrypt"], NativeStringHints()
        )
        self.assertEqual(out, {})

    def test_cap_per_symbol_respected(self) -> None:
        hints = NativeStringHints(
            crypto=[f"AES_{i}" for i in range(20)],
        )
        out = attribute_strings_by_symbol_name(
            ["Java_x_encrypt"], hints, cap_per_symbol=5,
        )
        self.assertEqual(len(out["Java_x_encrypt"]), 5)

    def test_multi_category_symbol_collects_from_each_bucket(self) -> None:
        # "tokenLog" matches secret_hints (token) AND debug (log)
        hints = NativeStringHints(
            secret_hints=["api_key=abc"],
            debug=["assertion failed"],
            crypto=["AES/CBC"],   # should NOT appear (no crypto in name)
        )
        out = attribute_strings_by_symbol_name(["Java_x_tokenLog"], hints)
        attr = out["Java_x_tokenLog"]
        self.assertIn("api_key=abc", attr)
        self.assertIn("assertion failed", attr)
        self.assertNotIn("AES/CBC", attr)


if __name__ == "__main__":
    unittest.main()

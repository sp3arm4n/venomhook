"""Tests for scoring — OS-split keyword sets and Android JNI 1st-class category.

Guard the scoring contract:
- Which base/OS-suffix tags get attached for each keyword family.
- That JNI/Android signals contribute to the score independently of OS-generic
  network/file/crypto signals.
- That a Java_* symbol alone is enough to flag a function as JNI/Android.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from venomhook.models import FunctionMeta
from venomhook.scoring import ScoreConfig, _score_function


def _fn(
    *,
    name: str | None = None,
    imports: list[str] | None = None,
    strings: list[str] | None = None,
    rva: int = 0x1000,
) -> FunctionMeta:
    return FunctionMeta(
        va=None,
        rva=rva,
        name=name,
        imports=imports or [],
        strings=strings or [],
    )


class ScoringOsAndJniTests(unittest.TestCase):
    def test_jni_symbol_pattern_adds_jni_and_android_tags(self) -> None:
        """A Java_* symbol alone (no imports) is enough to flag a function as JNI/Android."""
        fn = _fn(name="Java_com_example_MyClass_doStuff")
        score, tags, reasons = _score_function(fn, ScoreConfig())

        self.assertIn("jni", tags)
        self.assertIn("android", tags)
        # JNI default weight is 30 — score must include it
        self.assertGreaterEqual(score, ScoreConfig().jni_weight)
        self.assertTrue(any("Java_com_example_MyClass_doStuff" in r for r in reasons))

    def test_posix_network_imports_get_os_suffix_tag(self) -> None:
        """connect/send/recv (POSIX-style) tag as 'network' AND 'network:posix' — but not windows/darwin."""
        fn = _fn(name="login_handler", imports=["connect", "send", "recv"])
        _, tags, reasons = _score_function(fn, ScoreConfig())

        self.assertIn("network", tags)
        self.assertIn("network:posix", tags)
        self.assertNotIn("network:windows", tags)
        self.assertNotIn("network:darwin", tags)
        self.assertTrue(
            any("connect" in r and "recv" in r and "send" in r for r in reasons),
            f"reasons missing imports list: {reasons}",
        )

    def test_win_file_imports_get_windows_suffix_tag(self) -> None:
        """CreateFile/WriteFile tag as 'file' AND 'file:windows' — but not posix/darwin."""
        fn = _fn(name="file_io", imports=["CreateFile", "WriteFile"])
        _, tags, _ = _score_function(fn, ScoreConfig())

        self.assertIn("file", tags)
        self.assertIn("file:windows", tags)
        self.assertNotIn("file:posix", tags)
        self.assertNotIn("file:darwin", tags)

    def test_ssl_imports_get_crypto_ssl_tag(self) -> None:
        """OpenSSL/BoringSSL imports tag as 'crypto' AND 'crypto:ssl' (OS-portable bucket)."""
        fn = _fn(name="tls_handler", imports=["EVP_EncryptInit_ex", "SSL_read"])
        _, tags, _ = _score_function(fn, ScoreConfig())

        self.assertIn("crypto", tags)
        self.assertIn("crypto:ssl", tags)
        self.assertNotIn("crypto:windows", tags)
        self.assertNotIn("crypto:darwin", tags)

    def test_jni_imports_alone_score_independent_of_symbol(self) -> None:
        """JNI imports trigger jni/android tags even without Java_* symbol name."""
        fn = _fn(name="sub_1234", imports=["JNI_OnLoad", "RegisterNatives"])
        score, tags, _ = _score_function(fn, ScoreConfig())

        self.assertIn("jni", tags)
        self.assertIn("android", tags)
        self.assertGreaterEqual(score, ScoreConfig().jni_weight)


if __name__ == "__main__":
    unittest.main()

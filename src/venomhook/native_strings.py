"""Categorize ASCII strings harvested from a native library.

Phase 7-3. Consumes ``BinaryMeta.strings`` (populated by ``binary_meta.
_extract_strings``) and bins them into pentest-relevant categories so the
audit / HTML report can surface specific evidence without forcing the
operator to grep tens of thousands of bytes by hand.

Categories
----------

- ``urls`` — http(s)://, ftp://, ws(s)://, file:// targets baked into the
  binary. Indicates fixed endpoints worth scrutinising under MITM.
- ``ip_endpoints`` — IPv4 / IPv6 literal hosts (with or without port).
- ``paths`` — absolute paths under sensitive Android filesystems
  (/system, /data, /sdcard, /proc, /sbin, /vendor). Often used by anti-
  tamper, root checks, or hardcoded data file references.
- ``shell_commands`` — invocations of ``sh``/``su``/``busybox``/
  ``magisk``/etc., or arguments commonly passed to ``execve``.
- ``crypto`` — algorithm names and PEM markers ("BEGIN PUBLIC KEY",
  "AES/", "MD5", "PBKDF2", etc.).
- ``secret_hints`` — strings that *look like* credential / token names
  (api_key, password, jwt, secret). Hits are starting points; matching
  the surrounding constant table is left to the operator.
- ``sql`` — SQL fragments and pragma calls. The presence of "SELECT" or
  "INSERT" indicates an embedded query plane worth fuzzing.
- ``debug`` — diagnostic strings (assert names, file paths, log tags)
  that often leak class structure even after stripping.

Empty categories are returned (not omitted) so the caller can render a
stable shape. ``categorize_strings`` is pure / deterministic.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


__all__ = [
    "NativeStringHints",
    "categorize_strings",
    "summarize_hints",
]


_URL_RE = re.compile(
    r"^(https?|ftp|wss?|file)://", re.IGNORECASE
)
_IPV4_RE = re.compile(
    r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d{1,5})?(?:/[\w./~-]*)?$"
)
_IPV6_RE = re.compile(r"^(?=.*:)\[?[0-9a-fA-F:]{2,}\]?(?::\d{1,5})?$")

_SENSITIVE_PATH_RE = re.compile(
    r"^/(system|data|sdcard|storage|proc|sbin|vendor|product|apex)(?:/|$)"
)

_SHELL_TOKENS = (
    " su ", "/su", "su -c", "/system/bin/sh", "/system/xbin/su",
    "busybox", "magisk", "/system/bin/sh", "su\0", "system/bin/su",
    "execve", "execvp", "popen", "/bin/sh",
)

_CRYPTO_TOKENS = (
    "AES/", "DES/", "DES3", "3DES", "Blowfish", "RC4", "RC2",
    "MD5", "MD2", "SHA-1", "SHA1", "SHA-256", "SHA256", "SHA-512",
    "PBKDF2", "PKCS5", "PKCS7", "RSA", "ECDSA", "ECDH",
    "BEGIN PUBLIC KEY", "BEGIN PRIVATE KEY", "BEGIN CERTIFICATE",
    "BEGIN RSA PRIVATE KEY", "BEGIN EC PRIVATE KEY",
)

_SECRET_RE = re.compile(
    r"(api[_-]?key|access[_-]?key|secret|password|passwd|"
    r"token|auth(?:orization)?|jwt|bearer|client[_-]?secret)",
    re.IGNORECASE,
)

_SQL_RE = re.compile(
    r"\b(SELECT|INSERT INTO|UPDATE\s+\w+\s+SET|DELETE FROM|"
    r"CREATE TABLE|DROP TABLE|PRAGMA)\b", re.IGNORECASE
)

# Keep debug-string heuristics intentionally narrow — assertion mangling
# and cross-compilation file paths are the highest-signal forms.
_DEBUG_RE = re.compile(
    r"(\.cpp:\d+|\.cc:\d+|\.h:\d+|"
    r"assert(?:ion)?\s*failed|"
    r"^.+/[^/]+\.(?:cpp|cc|c|h|m|mm)$)"
)


@dataclass
class NativeStringHints:
    """Pentest-oriented categorization of native-library strings."""

    urls: list[str] = field(default_factory=list)
    ip_endpoints: list[str] = field(default_factory=list)
    paths: list[str] = field(default_factory=list)
    shell_commands: list[str] = field(default_factory=list)
    crypto: list[str] = field(default_factory=list)
    secret_hints: list[str] = field(default_factory=list)
    sql: list[str] = field(default_factory=list)
    debug: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return sum(len(getattr(self, f.name)) for f in self.__dataclass_fields__.values())

    @property
    def is_empty(self) -> bool:
        return self.total == 0

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "NativeStringHints":
        return cls(
            urls=list(data.get("urls", [])),
            ip_endpoints=list(data.get("ip_endpoints", [])),
            paths=list(data.get("paths", [])),
            shell_commands=list(data.get("shell_commands", [])),
            crypto=list(data.get("crypto", [])),
            secret_hints=list(data.get("secret_hints", [])),
            sql=list(data.get("sql", [])),
            debug=list(data.get("debug", [])),
        )

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {}
        if self.urls:
            result["urls"] = list(self.urls)
        if self.ip_endpoints:
            result["ip_endpoints"] = list(self.ip_endpoints)
        if self.paths:
            result["paths"] = list(self.paths)
        if self.shell_commands:
            result["shell_commands"] = list(self.shell_commands)
        if self.crypto:
            result["crypto"] = list(self.crypto)
        if self.secret_hints:
            result["secret_hints"] = list(self.secret_hints)
        if self.sql:
            result["sql"] = list(self.sql)
        if self.debug:
            result["debug"] = list(self.debug)
        return result


# Per-category cap so a binary saturated in (e.g.) PEM-style fragments
# doesn't drown the report. Any one category is interesting at first 50;
# beyond that the caller can dump the full BinaryMeta.strings list.
_PER_CATEGORY_CAP = 50


def categorize_strings(strings: list[str]) -> NativeStringHints:
    """Bucket each string into zero-or-more pentest-relevant categories.

    Pure function — no I/O. Strings can be uppercased / mixed case;
    individual matchers are case-insensitive where it makes sense.
    Each output list is deduped (preserving first-seen order) and
    capped at ``_PER_CATEGORY_CAP``.
    """
    hints = NativeStringHints()
    seen: dict[str, set[str]] = {
        k: set() for k in (
            "urls", "ip_endpoints", "paths", "shell_commands",
            "crypto", "secret_hints", "sql", "debug",
        )
    }

    def _add(bucket: str, value: str) -> None:
        s = seen[bucket]
        if value in s:
            return
        target: list[str] = getattr(hints, bucket)
        if len(target) >= _PER_CATEGORY_CAP:
            return
        s.add(value)
        target.append(value)

    for s in strings:
        if not s:
            continue
        if _URL_RE.match(s):
            _add("urls", s)
            continue  # URL itself usually isn't simultaneously an IP literal
        if _IPV4_RE.match(s) or _IPV6_RE.match(s):
            _add("ip_endpoints", s)
        if _SENSITIVE_PATH_RE.match(s):
            _add("paths", s)
        # Shell tokens are matched as substrings; only fire once per
        # original string regardless of how many tokens hit.
        s_lower_padded = f" {s.lower()} "
        if any(tok in s_lower_padded or tok in s for tok in _SHELL_TOKENS):
            _add("shell_commands", s)
        if any(tok in s for tok in _CRYPTO_TOKENS):
            _add("crypto", s)
        if _SECRET_RE.search(s):
            _add("secret_hints", s)
        if _SQL_RE.search(s):
            _add("sql", s)
        if _DEBUG_RE.search(s):
            _add("debug", s)

    return hints


def summarize_hints(hints: NativeStringHints) -> str:
    """One-line "5 urls, 12 paths, 1 shell, ..." text suitable for stdout/HTML."""
    counts = []
    if hints.urls:
        counts.append(f"{len(hints.urls)} URL")
    if hints.ip_endpoints:
        counts.append(f"{len(hints.ip_endpoints)} IP")
    if hints.paths:
        counts.append(f"{len(hints.paths)} path")
    if hints.shell_commands:
        counts.append(f"{len(hints.shell_commands)} shell")
    if hints.crypto:
        counts.append(f"{len(hints.crypto)} crypto")
    if hints.secret_hints:
        counts.append(f"{len(hints.secret_hints)} secret hint")
    if hints.sql:
        counts.append(f"{len(hints.sql)} SQL")
    if hints.debug:
        counts.append(f"{len(hints.debug)} debug")
    return ", ".join(counts) if counts else "(no audit-worthy strings)"

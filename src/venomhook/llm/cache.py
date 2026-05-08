"""Disk-backed cache for LLM responses.

Phase 5 / Unit 2. Sits between the integration points and the live
provider so re-runs over the same inputs return the cached completion
instead of paying for another API call. Restoring the determinism
property of the automation core when LLM features are enabled.

Key composition:
    (provider, model, schema_version, request_hash)

``request_hash`` is :meth:`LLMRequest.cache_key`, which already covers
the request body. ``provider`` and ``model`` are layered on top so two
backends can coexist for the same logical prompt without colliding.
``schema_version`` is bumped if the stored payload shape changes.

Design parallels :mod:`venomhook.analysis_cache`:
    * SQLite, single-file, atomic writes.
    * ``put`` is INSERT OR REPLACE so re-runs idempotently overwrite.
    * Context-manager support for ``with LLMCache(...) as c``.

This module is import-safe without optional SDKs — only stdlib.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

from venomhook.llm.provider import LLMRequest, LLMResponse


__all__ = [
    "CachedLLMEntry",
    "LLMCache",
    "SCHEMA_VERSION",
]


# Bumped when the persisted shape of an LLMResponse changes incompatibly.
SCHEMA_VERSION = 1


@dataclass(frozen=True)
class CachedLLMEntry:
    """Header-only view of one cache row (no response body).

    Returned by :meth:`LLMCache.list_entries` for inspection without
    paying the deserialization cost of every payload.
    """

    provider: str
    model: str
    request_hash: str
    schema_version: int
    created_at: str  # ISO 8601 UTC
    input_tokens: int
    output_tokens: int


class LLMCache:
    """SQLite-backed cache for :class:`LLMResponse` payloads.

    The default location should be derived by callers (the CLI passes
    ``~/.venomhook/llm_cache.sqlite3`` or whatever ``--llm-cache-dir``
    resolves to); this class only takes an explicit path so unit tests
    can use ``tmp_path``.
    """

    _CREATE_SQL = """
    CREATE TABLE IF NOT EXISTS llm_responses (
        provider       TEXT    NOT NULL,
        model          TEXT    NOT NULL,
        request_hash   TEXT    NOT NULL,
        schema_version INTEGER NOT NULL,
        created_at     TEXT    NOT NULL,
        input_tokens   INTEGER NOT NULL DEFAULT 0,
        output_tokens  INTEGER NOT NULL DEFAULT 0,
        payload        TEXT    NOT NULL,
        PRIMARY KEY (provider, model, request_hash, schema_version)
    )
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path)
        self._conn.execute(self._CREATE_SQL)
        self._conn.commit()

    # ---------- public API ----------

    def put(
        self,
        request: LLMRequest,
        response: LLMResponse,
    ) -> None:
        """Store (or replace) the cache row for this (provider, model, request).

        ``response.provider`` and ``response.model`` are the cache key —
        callers must populate them. An empty string is permitted but
        will collide across providers; the integration points always
        forward the values from the provider that produced the response.
        """
        now = datetime.now(timezone.utc).isoformat()
        payload = json.dumps(response.to_dict(), ensure_ascii=False)
        self._conn.execute(
            "INSERT OR REPLACE INTO llm_responses "
            "(provider, model, request_hash, schema_version, "
            " created_at, input_tokens, output_tokens, payload) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                response.provider,
                response.model,
                request.cache_key(),
                SCHEMA_VERSION,
                now,
                response.input_tokens,
                response.output_tokens,
                payload,
            ),
        )
        self._conn.commit()

    def get(
        self,
        provider: str,
        model: str,
        request: LLMRequest,
        schema_version: int = SCHEMA_VERSION,
    ) -> Optional[LLMResponse]:
        """Return the cached response, or ``None`` if absent."""
        cur = self._conn.execute(
            "SELECT payload FROM llm_responses "
            "WHERE provider = ? AND model = ? "
            "  AND request_hash = ? AND schema_version = ?",
            (provider, model, request.cache_key(), schema_version),
        )
        row = cur.fetchone()
        if row is None:
            return None
        return LLMResponse.from_dict(json.loads(row[0]))

    def has(
        self,
        provider: str,
        model: str,
        request: LLMRequest,
        schema_version: int = SCHEMA_VERSION,
    ) -> bool:
        cur = self._conn.execute(
            "SELECT 1 FROM llm_responses "
            "WHERE provider = ? AND model = ? "
            "  AND request_hash = ? AND schema_version = ?",
            (provider, model, request.cache_key(), schema_version),
        )
        return cur.fetchone() is not None

    def delete(
        self,
        provider: str,
        model: str,
        request: LLMRequest,
        schema_version: Optional[int] = None,
    ) -> int:
        """Remove a single cache row; returns the number of rows deleted (0 or 1)."""
        if schema_version is None:
            cur = self._conn.execute(
                "DELETE FROM llm_responses "
                "WHERE provider = ? AND model = ? AND request_hash = ?",
                (provider, model, request.cache_key()),
            )
        else:
            cur = self._conn.execute(
                "DELETE FROM llm_responses "
                "WHERE provider = ? AND model = ? "
                "  AND request_hash = ? AND schema_version = ?",
                (provider, model, request.cache_key(), schema_version),
            )
        self._conn.commit()
        return cur.rowcount

    def clear(self) -> int:
        """Delete every row. Returns total rows removed. Use with care — there
        is no undo. Intended for tests and ``--clear-llm-cache`` operator flows.
        """
        cur = self._conn.execute("DELETE FROM llm_responses")
        self._conn.commit()
        return cur.rowcount

    def list_entries(self) -> list[CachedLLMEntry]:
        """Header rows ordered most-recent-first. No payloads loaded."""
        cur = self._conn.execute(
            "SELECT provider, model, request_hash, schema_version, "
            "       created_at, input_tokens, output_tokens "
            "FROM llm_responses ORDER BY created_at DESC"
        )
        return [
            CachedLLMEntry(
                provider=row[0], model=row[1], request_hash=row[2],
                schema_version=row[3], created_at=row[4],
                input_tokens=row[5], output_tokens=row[6],
            )
            for row in cur.fetchall()
        ]

    def iter_responses(self) -> Iterator[LLMResponse]:
        """Yield every stored response. Loads all payloads in memory order."""
        cur = self._conn.execute(
            "SELECT payload FROM llm_responses ORDER BY created_at DESC"
        )
        for row in cur.fetchall():
            yield LLMResponse.from_dict(json.loads(row[0]))

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "LLMCache":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

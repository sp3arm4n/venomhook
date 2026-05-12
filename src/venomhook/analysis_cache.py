"""Analysis cache — persist AndroidAnalysis runs by APK hash.

Phase 4 / Unit 2. Provides a SQLite-backed store for AndroidAnalysis
records produced by ``android_pipeline.analyze_apk``. The cache is
keyed by the APK's content hash (already computed by apk_extractor,
stored in ``ApkMeta.hash`` as ``"sha256:<hex>"``) plus a schema
version so the format of stored payloads can evolve without colliding.

Use cases:
    * **Replay**: skip a 30-second apktool/jadx run on a re-analysis of
      the same APK. ``cache.get(apk_hash)`` returns the previously
      stored AndroidAnalysis (via from_dict) when present.
    * **Diff**: hold multiple analyses for the same APK across
      different rule-engine versions (schema bumps) or for different
      APK hashes (versions of the same app). ``cache.list_entries()``
      yields ``CacheEntry`` records suitable for the diff layer to
      compare.
    * **Audit history**: ``created_at`` timestamps form an append-only
      log of when each analysis was captured.

The cache deliberately stores only what ``to_dict`` produces — not
extracted .so files, not apktool output trees. Those are large and
re-derivable; the AndroidAnalysis JSON is the canonical artifact.

Pure-Python sqlite3, zero external dependencies.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

from venomhook.android_pipeline import AndroidAnalysis


__all__ = [
    "AnalysisCache",
    "CacheEntry",
    "SCHEMA_VERSION",
]


# Bumped whenever AndroidAnalysis.to_dict() changes shape incompatibly.
# Phase 7 added code_audit_report and native_string_hints; keeping the old
# version would let pre-Phase-7 cache rows replay without code findings.
# Phase 9-1 added additional_so_metas / additional_so_paths for the
# --apk-lib all path; without the bump a v2 single-lib payload could be
# replayed for an --apk-lib all request and silently miss the extra .so
# data the new request actually wanted.
# Phase 9-4 added strings_by_symbol (co-locality string attribution per
# JNI export); v3 rows replay with empty attribution which would mis-
# represent a fresh-run report, so we bump again.
# Phase 10-3 added CodeAuditReport.partial — v4 rows are forward-compat
# (partial defaults to False on load) so we *don't* bump for this one.
# Phase 10-4 added smali-tier findings. Old v4 rows can have a populated
# Java code_audit_report yet still miss every smali finding, so replaying
# them would silently under-report the new tier.
SCHEMA_VERSION = 5


@dataclass(frozen=True)
class CacheEntry:
    """Lightweight record describing an analysis row without loading
    the full payload. Returned by ``list_entries`` for inspection /
    diff selection.
    """

    apk_hash: str
    schema_version: int
    created_at: str  # ISO 8601 UTC string
    package_name: Optional[str]
    apk_name: Optional[str]
    finding_count: int


class AnalysisCache:
    """SQLite-backed cache for AndroidAnalysis records.

    Thread-safety: each instance opens one connection. SQLite handles
    serialization of writes by default; for concurrent process access
    use one cache instance per process.
    """

    _CREATE_SQL = """
    CREATE TABLE IF NOT EXISTS analyses (
        apk_hash       TEXT    NOT NULL,
        schema_version INTEGER NOT NULL,
        created_at     TEXT    NOT NULL,
        package_name   TEXT,
        apk_name       TEXT,
        finding_count  INTEGER NOT NULL DEFAULT 0,
        payload        TEXT    NOT NULL,
        PRIMARY KEY (apk_hash, schema_version)
    )
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path)
        self._conn.execute(self._CREATE_SQL)
        self._conn.commit()

    # ---------- public API ----------

    def put(self, analysis: AndroidAnalysis) -> None:
        """Store (or replace) the cache row for this analysis's APK hash
        at the current ``SCHEMA_VERSION``.

        Older-version rows for the same hash are preserved; only the
        (hash, current_schema) row is overwritten. This lets callers
        keep a history across schema bumps if they want, without
        making the common case (same schema, latest run) more complex.
        """
        apk_hash = analysis.apk_meta.hash
        package = analysis.app_meta.package_name if analysis.app_meta else None
        apk_name = analysis.apk_meta.name
        finding_count = (
            (len(analysis.audit_report.findings) if analysis.audit_report else 0)
            + (
                len(analysis.code_audit_report.findings)
                if analysis.code_audit_report else 0
            )
        )
        payload = json.dumps(analysis.to_dict())
        now = datetime.now(timezone.utc).isoformat()
        self._conn.execute(
            "INSERT OR REPLACE INTO analyses "
            "(apk_hash, schema_version, created_at, package_name, "
            " apk_name, finding_count, payload) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (apk_hash, SCHEMA_VERSION, now, package, apk_name,
             finding_count, payload),
        )
        self._conn.commit()

    def get(self, apk_hash: str, schema_version: int = SCHEMA_VERSION) -> Optional[AndroidAnalysis]:
        """Return the cached analysis for ``apk_hash`` at the given
        schema version, or None if not stored. Defaults to the current
        schema version so callers in normal-flow code don't have to
        think about it.
        """
        cur = self._conn.execute(
            "SELECT payload FROM analyses "
            "WHERE apk_hash = ? AND schema_version = ?",
            (apk_hash, schema_version),
        )
        row = cur.fetchone()
        if row is None:
            return None
        return AndroidAnalysis.from_dict(json.loads(row[0]))

    def has(self, apk_hash: str, schema_version: int = SCHEMA_VERSION) -> bool:
        cur = self._conn.execute(
            "SELECT 1 FROM analyses "
            "WHERE apk_hash = ? AND schema_version = ?",
            (apk_hash, schema_version),
        )
        return cur.fetchone() is not None

    def delete(self, apk_hash: str, schema_version: Optional[int] = None) -> int:
        """Remove cache rows for ``apk_hash``. With ``schema_version`` set,
        only that version is removed; otherwise all versions for the hash
        are removed. Returns the number of rows deleted.
        """
        if schema_version is None:
            cur = self._conn.execute(
                "DELETE FROM analyses WHERE apk_hash = ?", (apk_hash,)
            )
        else:
            cur = self._conn.execute(
                "DELETE FROM analyses "
                "WHERE apk_hash = ? AND schema_version = ?",
                (apk_hash, schema_version),
            )
        self._conn.commit()
        return cur.rowcount

    def list_entries(self) -> list[CacheEntry]:
        """Return every cached row as a ``CacheEntry``, ordered by most
        recent ``created_at`` first.
        """
        cur = self._conn.execute(
            "SELECT apk_hash, schema_version, created_at, "
            "       package_name, apk_name, finding_count "
            "FROM analyses ORDER BY created_at DESC"
        )
        return [
            CacheEntry(
                apk_hash=row[0],
                schema_version=row[1],
                created_at=row[2],
                package_name=row[3],
                apk_name=row[4],
                finding_count=row[5],
            )
            for row in cur.fetchall()
        ]

    def iter_analyses(self) -> Iterator[AndroidAnalysis]:
        """Yield every stored AndroidAnalysis (latest first). Useful for
        bulk diffs or report aggregation; loads all payloads, so for
        large caches prefer ``list_entries`` + targeted ``get`` calls.
        """
        cur = self._conn.execute(
            "SELECT payload FROM analyses ORDER BY created_at DESC"
        )
        for row in cur.fetchall():
            yield AndroidAnalysis.from_dict(json.loads(row[0]))

    def close(self) -> None:
        self._conn.close()

    # Context-manager support so callers can use `with AnalysisCache(...)`.
    def __enter__(self) -> "AnalysisCache":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

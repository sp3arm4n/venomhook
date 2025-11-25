from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Iterable

from venomhook.models import HookSpec, StaticMeta, iter_hookspecs


class StaticMetaStore:
    @staticmethod
    def load(path: Path) -> StaticMeta:
        with path.open("r", encoding="utf-8") as fp:
            data = json.load(fp)
        return StaticMeta.from_dict(data)

    @staticmethod
    def save(path: Path, meta: StaticMeta) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as fp:
            json.dump(meta.to_dict(), fp, indent=2)


class HookSpecJsonStore:
    @staticmethod
    def load(path: Path) -> list[HookSpec]:
        with path.open("r", encoding="utf-8") as fp:
            data = json.load(fp)
        items: Iterable[dict] = data.get("hooks", data) if isinstance(data, dict) else data
        return iter_hookspecs(items)

    @staticmethod
    def save(path: Path, specs: list[HookSpec]) -> None:
        payload = [spec.to_dict() for spec in specs]
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as fp:
            json.dump(payload, fp, indent=2)


class HookSpecSqliteStore:
    TABLE_NAME = "hookspecs"

    def __init__(self, path: Path):
        self.path = path
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.path)
        try:
            conn.execute(
                f"""
                CREATE TABLE IF NOT EXISTS {self.TABLE_NAME} (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    module TEXT NOT NULL,
                    arch TEXT NOT NULL,
                    offset INTEGER NOT NULL,
                    sig TEXT,
                    name TEXT,
                    tags TEXT,
                    proto TEXT,
                    hook TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            conn.commit()
        finally:
            conn.close()

    def save_all(self, specs: list[HookSpec]) -> None:
        conn = sqlite3.connect(self.path)
        try:
            conn.execute(f"DELETE FROM {self.TABLE_NAME}")
            for spec in specs:
                conn.execute(
                    f"""
                    INSERT INTO {self.TABLE_NAME}
                    (module, arch, offset, sig, name, tags, proto, hook)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        spec.module,
                        spec.arch,
                        spec.offset,
                        spec.sig,
                        spec.name,
                        json.dumps(spec.tags),
                        json.dumps(spec.proto.to_dict() if spec.proto else None),
                        json.dumps(spec.hook.to_dict()),
                    ),
                )
            conn.commit()
        finally:
            conn.close()

    def load_all(self) -> list[HookSpec]:
        conn = sqlite3.connect(self.path)
        try:
            rows = conn.execute(
                f"""
                SELECT module, arch, offset, sig, name, tags, proto, hook
                FROM {self.TABLE_NAME}
                ORDER BY id ASC
                """
            ).fetchall()
            conn.commit()
        finally:
            conn.close()
        specs: list[HookSpec] = []
        for module, arch, offset, sig, name, tags, proto, hook in rows:
            spec_dict = {
                "module": module,
                "arch": arch,
                "offset": offset,
                "sig": sig,
                "name": name,
                "tags": json.loads(tags) if tags else [],
                "proto": json.loads(proto) if proto else None,
                "hook": json.loads(hook) if hook else {},
            }
            specs.append(HookSpec.from_dict(spec_dict))
        return specs


class HookSpecStore:
    @staticmethod
    def load(path: Path) -> list[HookSpec]:
        if path.suffix.lower() == ".db":
            return HookSpecSqliteStore(path).load_all()
        return HookSpecJsonStore.load(path)

    @staticmethod
    def save(path: Path, specs: list[HookSpec]) -> None:
        if path.suffix.lower() == ".db":
            HookSpecSqliteStore(path).save_all(specs)
        else:
            HookSpecJsonStore.save(path, specs)

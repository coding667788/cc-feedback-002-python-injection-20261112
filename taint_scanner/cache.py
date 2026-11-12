"""Persistent scan cache backed by SQLite.

Two tables are stored:

* ``file_facts``  - one row per parsed source file (hash + structural facts);
* ``summaries``   - one row per function summary, keyed by a content basis
  that includes the file hash and every callee's basis transitively.

Crash safety: every write happens inside one transaction.  SQLite's rollback
journal guarantees that a process killed mid-transaction leaves the database
  in its last committed state, so restarting produces the same result as a
clean full scan.
"""

from __future__ import annotations

import json
import os
import sqlite3
from typing import Optional

from .models import Finding, Term, UnsupportedItem
from .analysis import ReturnRecord, Summary, WriteRecord


SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS file_facts (
    rel_path TEXT PRIMARY KEY,
    module_name TEXT NOT NULL,
    source_hash TEXT NOT NULL,
    payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS summaries (
    summary_key TEXT PRIMARY KEY,
    basis TEXT NOT NULL,
    payload TEXT NOT NULL
);
"""


def _return_to_dict(record: ReturnRecord) -> dict:
    return {
        "terms": [term.to_dict() for term in record.terms],
        "object_id": record.object_id,
        "type_tag": record.type_tag,
        "object_fields": {
            name: [term.to_dict() for term in terms]
            for name, terms in record.object_fields.items()
        },
        "object_class": record.object_class,
    }


def _return_from_dict(data: dict) -> ReturnRecord:
    return ReturnRecord(
        terms={Term.from_dict(item) for item in data["terms"]},
        object_id=data["object_id"],
        type_tag=data["type_tag"],
        object_fields={
            name: [Term.from_dict(item) for item in terms]
            for name, terms in data.get("object_fields", {}).items()
        },
        object_class=data.get("object_class"),
    )


def _write_to_dict(record: WriteRecord) -> dict:
    return {
        "param_index": record.param_index,
        "param_name": record.param_name,
        "field_path": list(record.field_path),
        "terms": [term.to_dict() for term in record.terms],
        "object_id": record.object_id,
    }


def _write_from_dict(data: dict) -> WriteRecord:
    return WriteRecord(
        param_index=data["param_index"],
        param_name=data["param_name"],
        field_path=tuple(data["field_path"]),
        terms={Term.from_dict(item) for item in data["terms"]},
        object_id=data["object_id"],
    )


def summary_to_dict(summary: Summary) -> dict:
    return {
        "key": summary.key,
        "module": summary.module,
        "func": summary.func,
        "is_route": summary.is_route,
        "route_method": summary.route_method,
        "source_params": summary.source_params,
        "basis": summary.basis,
        "findings": [finding.to_dict() for finding in summary.findings],
        "unsupported": [item.to_dict() for item in summary.unsupported],
        "returns": [_return_to_dict(item) for item in summary.returns],
        "writes": [_write_to_dict(item) for item in summary.writes],
        "calls": [],
    }


def summary_from_dict(data: dict) -> Summary:
    return Summary(
        key=data["key"],
        module=data["module"],
        func=data["func"],
        is_route=data["is_route"],
        route_method=data["route_method"],
        source_params=data["source_params"],
        basis=data["basis"],
        findings=[Finding.from_dict(item) for item in data["findings"]],
        unsupported=[UnsupportedItem.from_dict(item) for item in data["unsupported"]],
        returns=[_return_from_dict(item) for item in data["returns"]],
        writes=[_write_from_dict(item) for item in data["writes"]],
        calls=[],
    )


class ScanCache:
    def __init__(self, cache_dir: str):
        self.cache_dir = cache_dir
        os.makedirs(cache_dir, exist_ok=True)
        self.db_path = os.path.join(cache_dir, "scan_cache.sqlite3")
        self.conn = sqlite3.connect(self.db_path)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=FULL")
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    # ------------------------------------------------------------ file facts
    def get_file_fact(self, rel_path: str) -> Optional[dict]:
        row = self.conn.execute(
            "SELECT payload FROM file_facts WHERE rel_path = ?", (rel_path,)
        ).fetchone()
        return json.loads(row[0]) if row else None

    def put_file_facts(self, facts: dict[str, dict]) -> None:
        with self.conn:
            self.conn.executemany(
                "INSERT OR REPLACE INTO file_facts(rel_path, module_name, "
                "source_hash, payload) VALUES(?, ?, ?, ?)",
                [
                    (
                        rel_path,
                        payload["module_name"],
                        payload["source_hash"],
                        json.dumps(payload, sort_keys=True),
                    )
                    for rel_path, payload in sorted(facts.items())
                ],
            )

    def all_file_hashes(self) -> dict[str, str]:
        rows = self.conn.execute(
            "SELECT rel_path, source_hash FROM file_facts"
        ).fetchall()
        return {row[0]: row[1] for row in rows}

    def delete_file_facts(self, rel_paths: set[str]) -> None:
        if not rel_paths:
            return
        with self.conn:
            self.conn.executemany(
                "DELETE FROM file_facts WHERE rel_path = ?",
                [(path,) for path in sorted(rel_paths)],
            )

    # -------------------------------------------------------------- summary
    def get_summary(self, key: str, basis: str) -> Optional[Summary]:
        row = self.conn.execute(
            "SELECT payload, basis FROM summaries WHERE summary_key = ?", (key,)
        ).fetchone()
        if row is None or row[1] != basis:
            return None
        return summary_from_dict(json.loads(row[0]))

    def put_summaries(self, summaries: dict[str, Summary]) -> None:
        with self.conn:
            self.conn.executemany(
                "INSERT OR REPLACE INTO summaries(summary_key, basis, payload) "
                "VALUES(?, ?, ?)",
                [
                    (
                        key,
                        summary.basis,
                        json.dumps(summary_to_dict(summary), sort_keys=True),
                    )
                    for key, summary in sorted(summaries.items())
                ],
            )

    def all_summary_bases(self) -> dict[str, str]:
        rows = self.conn.execute("SELECT summary_key, basis FROM summaries").fetchall()
        return {row[0]: row[1] for row in rows}

    def delete_summaries(self, keys: set[str]) -> None:
        if not keys:
            return
        with self.conn:
            self.conn.executemany(
                "DELETE FROM summaries WHERE summary_key = ?",
                [(key,) for key in sorted(keys)],
            )

    def clear(self) -> None:
        with self.conn:
            self.conn.execute("DELETE FROM file_facts")
            self.conn.execute("DELETE FROM summaries")

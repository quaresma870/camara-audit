"""
SQLite-backed persistence for scan results — the --db flag lets a
scan's findings survive past the single CLI invocation that produced
them, so multiple scans (possibly against different targets/modules,
over time) can be reviewed together via `camara-audit dashboard`.

Deliberately dependency-free: sqlite3 is in the Python standard
library, keeping this portfolio's minimal-dependency approach intact
rather than pulling in an ORM or a separate database service.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

from camara_audit.core.models import ModuleResult

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id TEXT NOT NULL,
    target TEXT NOT NULL,
    module TEXT NOT NULL,
    started_at REAL NOT NULL,
    duration_ms REAL NOT NULL,
    error TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id),
    module TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    target TEXT NOT NULL,
    description TEXT NOT NULL,
    evidence TEXT NOT NULL,
    remediation TEXT NOT NULL,
    extra_json TEXT NOT NULL
);
"""


def open_db(path: str | Path) -> sqlite3.Connection:
    """Opens (creating if needed) the SQLite database at `path` and
    ensures its schema exists. Safe to call repeatedly against the
    same file — CREATE TABLE IF NOT EXISTS is idempotent."""
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.executescript(_SCHEMA)
    return conn


def record_result(
    conn: sqlite3.Connection, engagement_id: str, target: str, result: ModuleResult,
) -> int:
    """Persists one plugin run's ModuleResult (and all its findings) and
    returns the new scan row's id."""
    cur = conn.execute(
        "INSERT INTO scans (engagement_id, target, module, started_at, duration_ms, error) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (engagement_id, target, result.module, time.time(), result.duration_ms, result.error),
    )
    scan_id = cur.lastrowid
    for finding in result.findings:
        conn.execute(
            "INSERT INTO findings (scan_id, module, title, severity, category, target, "
            "description, evidence, remediation, extra_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                scan_id, finding.module, finding.title, finding.severity.value,
                finding.category.value, finding.target, finding.description,
                finding.evidence, finding.remediation, json.dumps(finding.extra),
            ),
        )
    conn.commit()
    return scan_id


def list_scans(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM scans ORDER BY started_at DESC").fetchall()


def list_findings(
    conn: sqlite3.Connection, severity: str | None = None, module: str | None = None,
) -> list[sqlite3.Row]:
    query = (
        "SELECT findings.*, scans.engagement_id, scans.started_at FROM findings "
        "JOIN scans ON scans.id = findings.scan_id WHERE 1=1"
    )
    params: list[str] = []
    if severity:
        query += " AND findings.severity = ?"
        params.append(severity)
    if module:
        query += " AND findings.module = ?"
        params.append(module)
    query += " ORDER BY scans.started_at DESC"
    return conn.execute(query, params).fetchall()


def severity_counts(conn: sqlite3.Connection) -> dict[str, int]:
    rows = conn.execute("SELECT severity, COUNT(*) AS n FROM findings GROUP BY severity").fetchall()
    return {row["severity"]: row["n"] for row in rows}

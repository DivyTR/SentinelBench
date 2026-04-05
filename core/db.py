"""
core/db.py
----------
SQLite persistence layer for SentinelBench.

Schema
------
  runs          — one row per benchmark run (a suite or single technique execution)
  results       — one row per technique result within a run
  kql_suggestions — generated KQL for missed detections, linked to a result row

All timestamps are stored as ISO-8601 UTC strings so they survive
SQLite's lack of a native datetime type and are trivially JSON-serialisable.
"""

import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

DB_PATH = Path(__file__).parent.parent / "sentinelbench.db"


# ── connection helper ──────────────────────────────────────────────────────────

def get_connection(path: Path = DB_PATH) -> sqlite3.Connection:
    """Return a connection with row_factory set so rows behave like dicts."""
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")   # safe for concurrent reads
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


# ── schema initialisation ─────────────────────────────────────────────────────

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id          TEXT PRIMARY KEY,
    suite           TEXT NOT NULL,          -- 'v1' or a single technique ID
    started_at      TEXT NOT NULL,
    finished_at     TEXT,
    host            TEXT,                   -- hostname of the lab VM
    sentinel_workspace TEXT,               -- workspace ID used (not the secret)
    notes           TEXT
);

CREATE TABLE IF NOT EXISTS results (
    result_id           TEXT PRIMARY KEY,
    run_id              TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    technique_id        TEXT NOT NULL,      -- e.g. 'T1003.001'
    technique_name      TEXT NOT NULL,
    tactic              TEXT NOT NULL,
    timestamp_exec      TEXT NOT NULL,      -- when ART script fired
    timestamp_alert     TEXT,              -- first matching alert in Sentinel (NULL = missed)
    latency_seconds     REAL,              -- NULL if missed
    caught              INTEGER NOT NULL DEFAULT 0,  -- 1 = caught, 0 = missed
    severity_assigned   TEXT,              -- Sentinel severity: High/Medium/Low/Informational
    severity_expected   TEXT NOT NULL,     -- ATT&CK-derived expected severity
    severity_delta      INTEGER,           -- positive = under-rated, negative = over-rated
    poll_checkpoint     TEXT,              -- which poll caught it: T+2, T+5, T+10, T+15
    raw_log_sample      TEXT               -- JSON string of key log fields for KQL seeding
);

CREATE TABLE IF NOT EXISTS kql_suggestions (
    suggestion_id   TEXT PRIMARY KEY,
    result_id       TEXT NOT NULL REFERENCES results(result_id) ON DELETE CASCADE,
    technique_id    TEXT NOT NULL,
    kql_query       TEXT NOT NULL,
    confidence      TEXT NOT NULL CHECK(confidence IN ('high', 'medium', 'requires_tuning')),
    data_source     TEXT NOT NULL,         -- e.g. 'SecurityEvent', 'Sysmon'
    false_positive_note TEXT,
    created_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_results_run    ON results(run_id);
CREATE INDEX IF NOT EXISTS idx_results_tech   ON results(technique_id);
CREATE INDEX IF NOT EXISTS idx_kql_result     ON kql_suggestions(result_id);
"""


def init_db(path: Path = DB_PATH) -> None:
    """Create tables and indexes if they don't exist."""
    with get_connection(path) as conn:
        conn.executescript(SCHEMA)
    print(f"[db] Database ready at {path}")


# ── run operations ─────────────────────────────────────────────────────────────

def create_run(
    suite: str,
    host: str,
    sentinel_workspace: str,
    notes: str = "",
    path: Path = DB_PATH,
) -> str:
    """Insert a new run row and return its run_id."""
    run_id = str(uuid.uuid4())
    started_at = _now()
    with get_connection(path) as conn:
        conn.execute(
            """
            INSERT INTO runs (run_id, suite, started_at, host, sentinel_workspace, notes)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (run_id, suite, started_at, host, sentinel_workspace, notes),
        )
    return run_id


def finish_run(run_id: str, path: Path = DB_PATH) -> None:
    """Stamp finished_at on a run."""
    with get_connection(path) as conn:
        conn.execute(
            "UPDATE runs SET finished_at = ? WHERE run_id = ?",
            (_now(), run_id),
        )


def get_run(run_id: str, path: Path = DB_PATH) -> Optional[dict]:
    with get_connection(path) as conn:
        row = conn.execute(
            "SELECT * FROM runs WHERE run_id = ?", (run_id,)
        ).fetchone()
    return dict(row) if row else None


def list_runs(limit: int = 20, path: Path = DB_PATH) -> list[dict]:
    with get_connection(path) as conn:
        rows = conn.execute(
            "SELECT * FROM runs ORDER BY started_at DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


# ── result operations ──────────────────────────────────────────────────────────

def save_result(
    run_id: str,
    technique_id: str,
    technique_name: str,
    tactic: str,
    timestamp_exec: str,
    caught: bool,
    severity_expected: str,
    timestamp_alert: Optional[str] = None,
    latency_seconds: Optional[float] = None,
    severity_assigned: Optional[str] = None,
    poll_checkpoint: Optional[str] = None,
    raw_log_sample: Optional[str] = None,
    path: Path = DB_PATH,
) -> str:
    """Insert a result row and return its result_id."""
    result_id = str(uuid.uuid4())

    severity_delta = None
    if severity_assigned and severity_expected:
        severity_delta = _severity_delta(severity_assigned, severity_expected)

    with get_connection(path) as conn:
        conn.execute(
            """
            INSERT INTO results (
                result_id, run_id, technique_id, technique_name, tactic,
                timestamp_exec, timestamp_alert, latency_seconds, caught,
                severity_assigned, severity_expected, severity_delta,
                poll_checkpoint, raw_log_sample
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result_id, run_id, technique_id, technique_name, tactic,
                timestamp_exec, timestamp_alert, latency_seconds, int(caught),
                severity_assigned, severity_expected, severity_delta,
                poll_checkpoint, raw_log_sample,
            ),
        )
    return result_id


def get_results_for_run(run_id: str, path: Path = DB_PATH) -> list[dict]:
    with get_connection(path) as conn:
        rows = conn.execute(
            "SELECT * FROM results WHERE run_id = ? ORDER BY timestamp_exec",
            (run_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_missed_detections(run_id: str, path: Path = DB_PATH) -> list[dict]:
    """Return only the results where caught = 0 (missed detections)."""
    with get_connection(path) as conn:
        rows = conn.execute(
            "SELECT * FROM results WHERE run_id = ? AND caught = 0",
            (run_id,),
        ).fetchall()
    return [dict(r) for r in rows]


# ── KQL suggestion operations ─────────────────────────────────────────────────

def save_kql_suggestion(
    result_id: str,
    technique_id: str,
    kql_query: str,
    confidence: str,
    data_source: str,
    false_positive_note: str = "",
    path: Path = DB_PATH,
) -> str:
    """Insert a KQL suggestion and return its suggestion_id."""
    suggestion_id = str(uuid.uuid4())
    with get_connection(path) as conn:
        conn.execute(
            """
            INSERT INTO kql_suggestions (
                suggestion_id, result_id, technique_id, kql_query,
                confidence, data_source, false_positive_note, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                suggestion_id, result_id, technique_id, kql_query,
                confidence, data_source, false_positive_note, _now(),
            ),
        )
    return suggestion_id


def get_kql_for_run(run_id: str, path: Path = DB_PATH) -> list[dict]:
    """Return all KQL suggestions for missed detections in a run."""
    with get_connection(path) as conn:
        rows = conn.execute(
            """
            SELECT ks.*
            FROM kql_suggestions ks
            JOIN results r ON ks.result_id = r.result_id
            WHERE r.run_id = ?
            ORDER BY ks.created_at
            """,
            (run_id,),
        ).fetchall()
    return [dict(r) for r in rows]


# ── summary / reporting helpers ────────────────────────────────────────────────

def run_summary(run_id: str, path: Path = DB_PATH) -> dict:
    """
    Return a compact summary dict for a run — useful for the dashboard
    and for the CLI progress printer.
    """
    results = get_results_for_run(run_id, path)
    if not results:
        return {"run_id": run_id, "total": 0, "caught": 0, "missed": 0}

    total   = len(results)
    caught  = sum(1 for r in results if r["caught"])
    missed  = total - caught
    latencies = [r["latency_seconds"] for r in results if r["latency_seconds"] is not None]
    avg_latency = round(sum(latencies) / len(latencies), 1) if latencies else None

    severity_miscals = [
        r for r in results
        if r["severity_delta"] is not None and r["severity_delta"] > 0
    ]

    return {
        "run_id":              run_id,
        "total":               total,
        "caught":              caught,
        "missed":              missed,
        "coverage_pct":        round(caught / total * 100, 1),
        "avg_latency_seconds": avg_latency,
        "severity_miscalibrations": len(severity_miscals),
    }


# ── internal helpers ───────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


_SEVERITY_RANK = {
    "informational": 0,
    "low":           1,
    "medium":        2,
    "high":          3,
}


def _severity_delta(assigned: str, expected: str) -> int:
    """
    Positive delta means Sentinel under-rated the severity (bad).
    Negative delta means Sentinel over-rated it.
    Zero means accurate.
    """
    a = _SEVERITY_RANK.get(assigned.lower(), -1)
    e = _SEVERITY_RANK.get(expected.lower(), -1)
    if a == -1 or e == -1:
        return 0
    return e - a   # expected - assigned; positive = under-rated

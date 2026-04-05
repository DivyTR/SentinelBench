"""
db.py — SQLite result store.

Schema (single table: runs):
    run_id              TEXT  PRIMARY KEY
    technique_id        TEXT  NOT NULL
    timestamp_exec      TEXT  NOT NULL  (ISO 8601)
    caught              INTEGER NOT NULL  (0 or 1)
    latency_seconds     REAL            (NULL if missed)
    severity_assigned   TEXT            (NULL if missed)
    severity_expected   TEXT  NOT NULL
    severity_delta      INTEGER NOT NULL
    kql_suggestion      TEXT            (NULL if caught)
    raw_log_sample      TEXT            (JSON, NULL if caught)
    created_at          TEXT  NOT NULL  (ISO 8601)
"""

import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "results.db"

CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS runs (
    run_id            TEXT PRIMARY KEY,
    technique_id      TEXT NOT NULL,
    timestamp_exec    TEXT NOT NULL,
    caught            INTEGER NOT NULL,
    latency_seconds   REAL,
    severity_assigned TEXT,
    severity_expected TEXT NOT NULL,
    severity_delta    INTEGER NOT NULL,
    kql_suggestion    TEXT,
    raw_log_sample    TEXT,
    created_at        TEXT NOT NULL
);
"""


class ResultStore:
    """Stub. Thin wrapper around sqlite3 for persisting DetectionResults."""

    def __init__(self, db_path: Path = DB_PATH) -> None:
        self.db_path = db_path
        # TODO: call self._init_db() here once implemented

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(CREATE_TABLE)

    def save(self, result: dict) -> None:
        """Insert a single run result row."""
        raise NotImplementedError

    def get_all(self) -> list[dict]:
        """Return all run rows as a list of dicts."""
        raise NotImplementedError

    def get_missed(self) -> list[dict]:
        """Return only missed detections (caught=0)."""
        raise NotImplementedError

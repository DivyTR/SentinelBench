import sqlite3

import pytest

from core import db


@pytest.fixture
def path(tmp_path):
    p = tmp_path / "t.db"
    db.init_db(p, verbose=False)
    return p


def _result(run_id, path, **kw):
    base = {"run_id": run_id, "technique_id": "T1112", "technique_name": "Modify Registry",
            "tactic": "Defense Impairment", "timestamp_exec": "2026-10-03T10:00:00+00:00",
            "caught": True, "severity_expected": "Medium", "path": path}
    return db.save_result(**{**base, **kw})


def test_dry_run_flag_is_persisted(path):
    run_id = db.create_run("v1", "host", "dry-run", dry_run=True, path=path)
    assert db.get_run(run_id, path)["dry_run"] == 1


def test_save_result_computes_severity_delta_and_keeps_alert_metadata(path):
    run_id = db.create_run("v1", "host", "ws", path=path)
    _result(run_id, path, severity_assigned="Low", latency_seconds=0.0,
            alert_name="Reg mod", alert_matched_ids='["T1112"]')
    _result(run_id, path, severity_assigned="Weird")
    rows = db.get_results_for_run(run_id, path)
    assert [r["severity_delta"] for r in rows] == [1, None]
    assert rows[0]["alert_name"] == "Reg mod"
    s = db.run_summary(run_id, path)
    assert s["severity_miscalibrations"] == 1
    assert s["avg_latency_seconds"] == 0.0


def test_empty_run_summary_has_all_keys(path):
    s = db.run_summary("nope", path)
    assert s["total"] == 0 and s["coverage_pct"] is None and s["avg_latency_seconds"] is None


def test_init_db_migrates_a_database_from_the_old_schema(tmp_path):
    p = tmp_path / "old.db"
    conn = sqlite3.connect(p)
    conn.executescript("""
        CREATE TABLE runs (run_id TEXT PRIMARY KEY, suite TEXT NOT NULL,
            started_at TEXT NOT NULL, finished_at TEXT, host TEXT,
            sentinel_workspace TEXT, notes TEXT);
        CREATE TABLE results (result_id TEXT PRIMARY KEY, run_id TEXT NOT NULL,
            technique_id TEXT NOT NULL, technique_name TEXT NOT NULL, tactic TEXT NOT NULL,
            timestamp_exec TEXT NOT NULL, timestamp_alert TEXT, latency_seconds REAL,
            caught INTEGER NOT NULL DEFAULT 0, severity_assigned TEXT,
            severity_expected TEXT NOT NULL, severity_delta INTEGER,
            poll_checkpoint TEXT, raw_log_sample TEXT);
    """)
    conn.close()
    db.init_db(p, verbose=False)
    run_id = db.create_run("v1", "h", "ws", dry_run=True, path=p)
    _result(run_id, p, art_guid="g")
    assert db.get_results_for_run(run_id, p)[0]["art_guid"] == "g"

"""
tests/test_aggregate.py
-----------------------
Statistical aggregation across repeated runs (core/aggregate.py).

These are pure-function tests: synthetic result rows in, aggregates out. No
DB, no network, no clock. They lock the Wilson-interval maths to known values
and prove the per-technique rate / latency / severity aggregation behaves at
the edges (0 trials, single trial, all caught, all missed, flaky).
"""
import pytest

from core.aggregate import (
    aggregate_batch,
    aggregate_technique,
    latency_stats,
    wilson_interval,
)


def _row(tid, caught, latency=None, severity=None, name=None, tactic=None):
    """Minimal result row as core.db.get_results_for_run would return."""
    return {
        "technique_id": tid,
        "technique_name": name or f"name-{tid}",
        "tactic": tactic or "Execution",
        "caught": 1 if caught else 0,
        "latency_seconds": latency,
        "severity_assigned": severity,
    }


# ── wilson_interval ──────────────────────────────────────────────────────────

def test_wilson_known_value_7_of_10():
    # Hand-computed with z=1.96: centre 0.6445, margin 0.2477.
    low, high = wilson_interval(7, 10)
    assert low == pytest.approx(0.3968, abs=1e-3)
    assert high == pytest.approx(0.8922, abs=1e-3)


def test_wilson_zero_trials_is_zero_width():
    assert wilson_interval(0, 0) == (0.0, 0.0)


def test_wilson_stays_within_unit_interval_at_extremes():
    # All caught: rate 1.0, but the interval must not exceed 1.0 and lower
    # bound must be below 1 (not a zero-width point like Wald gives).
    low, high = wilson_interval(8, 8)
    assert 0.0 < low < 1.0
    assert high <= 1.0
    # All missed: symmetric at the bottom.
    low0, high0 = wilson_interval(0, 8)
    assert low0 == 0.0
    assert 0.0 < high0 < 1.0


def test_wilson_interval_brackets_point_estimate():
    for s, n in [(1, 4), (3, 7), (5, 9), (10, 20)]:
        low, high = wilson_interval(s, n)
        assert low <= s / n <= high


def test_wilson_wider_at_smaller_n():
    # Same proportion (0.5), fewer trials -> wider interval.
    narrow = wilson_interval(50, 100)
    wide = wilson_interval(2, 4)
    assert (wide[1] - wide[0]) > (narrow[1] - narrow[0])


# ── latency_stats ────────────────────────────────────────────────────────────

def test_latency_stats_basic():
    s = latency_stats([100.0, 200.0, 300.0])
    assert s["n"] == 3
    assert s["mean"] == 200.0
    assert s["median"] == 200.0
    assert s["min"] == 100.0
    assert s["max"] == 300.0
    assert s["stdev"] == 100.0   # sample stdev of [100,200,300]


def test_latency_stats_drops_none():
    s = latency_stats([None, 50.0, None, 150.0])
    assert s["n"] == 2
    assert s["mean"] == 100.0


def test_latency_stats_single_sample_has_zero_stdev():
    s = latency_stats([120.0])
    assert s["n"] == 1
    assert s["stdev"] == 0.0


def test_latency_stats_empty_is_none():
    assert latency_stats([]) is None
    assert latency_stats([None, None]) is None


# ── aggregate_technique ──────────────────────────────────────────────────────

def test_technique_rate_and_flaky():
    rows = [
        _row("T1059.001", True, 100, "Medium"),
        _row("T1059.001", True, 140, "Medium"),
        _row("T1059.001", False),
        _row("T1059.001", True, 120, "Medium"),
    ]
    agg = aggregate_technique(rows)
    assert agg["trials"] == 4
    assert agg["detections"] == 3
    assert agg["detection_rate"] == 0.75
    assert agg["flaky"] is True
    # Latency only over caught runs.
    assert agg["latency"]["n"] == 3
    assert agg["latency"]["mean"] == 120.0
    assert agg["severity_mode"] == "medium"
    assert agg["severity_consistent"] is True


def test_technique_all_caught_not_flaky():
    rows = [_row("T1", True, 10, "High"), _row("T1", True, 20, "High")]
    agg = aggregate_technique(rows)
    assert agg["detection_rate"] == 1.0
    assert agg["flaky"] is False


def test_technique_all_missed_has_no_latency():
    rows = [_row("T1", False), _row("T1", False)]
    agg = aggregate_technique(rows)
    assert agg["detections"] == 0
    assert agg["detection_rate"] == 0.0
    assert agg["flaky"] is False          # never caught -> not flaky, just absent
    assert agg["latency"] is None
    assert agg["severity_mode"] is None


def test_technique_inconsistent_severity_flagged():
    rows = [
        _row("T1", True, 10, "High"),
        _row("T1", True, 12, "Medium"),
        _row("T1", True, 11, "Medium"),
    ]
    agg = aggregate_technique(rows)
    assert agg["severity_consistent"] is False
    assert agg["severity_mode"] == "medium"   # most frequent
    assert agg["severity_counts"] == {"high": 1, "medium": 2}


def test_technique_metadata_carried_through():
    rows = [_row("T1003.001", False, name="LSASS Memory", tactic="Credential Access")]
    agg = aggregate_technique(rows)
    assert agg["technique_name"] == "LSASS Memory"
    assert agg["tactic"] == "Credential Access"


# ── aggregate_batch ──────────────────────────────────────────────────────────

def test_batch_summary_and_ordering():
    # Two runs, two techniques. Run1: both caught. Run2: only T1059 caught.
    run1 = [_row("T1110.001", True, 500, "Medium"), _row("T1059.001", True, 90, "Medium")]
    run2 = [_row("T1110.001", False), _row("T1059.001", True, 95, "Medium")]
    agg = aggregate_batch([run1, run2])

    assert agg["n_runs"] == 2
    assert agg["n_techniques"] == 2
    # Techniques sorted by ID.
    assert [t["technique_id"] for t in agg["techniques"]] == ["T1059.001", "T1110.001"]

    by_id = {t["technique_id"]: t for t in agg["techniques"]}
    assert by_id["T1059.001"]["detection_rate"] == 1.0
    assert by_id["T1059.001"]["flaky"] is False
    assert by_id["T1110.001"]["detection_rate"] == 0.5
    assert by_id["T1110.001"]["flaky"] is True
    assert agg["flaky_count"] == 1

    # Coverage per run: run1 100%, run2 50% -> mean 75%, stdev of {1.0,0.5}.
    assert agg["coverage_mean_pct"] == 75.0
    expected_stdev = round(__import__("statistics").stdev([1.0, 0.5]) * 100, 1)
    assert agg["coverage_stdev_pct"] == expected_stdev


def test_batch_drops_empty_runs():
    run1 = [_row("T1", True, 10, "High")]
    agg = aggregate_batch([run1, []])
    assert agg["n_runs"] == 1


def test_batch_empty_is_safe():
    agg = aggregate_batch([])
    assert agg["n_runs"] == 0
    assert agg["n_techniques"] == 0
    assert agg["coverage_mean_pct"] is None
    assert agg["techniques"] == []


def test_batch_single_run_zero_coverage_spread():
    agg = aggregate_batch([[_row("T1", True, 10, "High"), _row("T2", False)]])
    assert agg["coverage_mean_pct"] == 50.0
    assert agg["coverage_stdev_pct"] == 0.0   # one run -> no spread


def test_batch_is_deterministic():
    run1 = [_row("T1", True, 100, "Medium"), _row("T2", False)]
    run2 = [_row("T1", False), _row("T2", True, 200, "High")]
    a = aggregate_batch([run1, run2])
    b = aggregate_batch([run1, run2])
    assert a == b

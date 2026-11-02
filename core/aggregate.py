"""
core/aggregate.py
-----------------
Statistical aggregation across repeated benchmark runs.

A single run gives n=1 per technique: caught or missed, one latency sample,
one severity. That is an anecdote, not a measurement — a timing-variable
technique can read 0/1 or 1/1 on luck alone. Running the same config N times
(`sentinelbench.py --repeat N`) and aggregating here turns it into a
measurement: a per-technique DETECTION RATE with a confidence interval, and
a latency DISTRIBUTION instead of a single point.

Everything in this module is pure. It takes lists of result dicts (as
returned by core.db.get_results_for_run) and returns plain dicts — no DB, no
network, no clock — so it is fully unit-testable with synthetic data and
produces identical output for identical input.
"""
from __future__ import annotations

import math
import statistics
from collections import Counter

# Fixed display order for severities, lowest to highest.
_SEVERITY_ORDER = ["informational", "low", "medium", "high"]


def wilson_interval(successes: int, trials: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion.

    Preferred over the normal (Wald) approximation because at small n, and at
    rates near 0 or 1, Wald produces intervals that fall outside [0, 1] or
    collapse to zero width — exactly the regime a 5–10 run benchmark lives in.
    `z` defaults to 1.96 (95% confidence). Returns (low, high) as proportions
    in [0, 1].
    """
    if trials <= 0:
        return (0.0, 0.0)
    p = successes / trials
    z2 = z * z
    denom = 1.0 + z2 / trials
    centre = (p + z2 / (2.0 * trials)) / denom
    margin = (z * math.sqrt((p * (1.0 - p) + z2 / (4.0 * trials)) / trials)) / denom
    return (max(0.0, centre - margin), min(1.0, centre + margin))


def latency_stats(values: list[float | None]) -> dict | None:
    """Distribution summary for latency samples (seconds).

    None entries (missed runs carry no latency) are dropped. Returns None when
    no samples remain. stdev is 0.0 for a single sample (undefined population
    spread, reported as no observed spread).
    """
    vals = [v for v in values if v is not None]
    if not vals:
        return None
    return {
        "n":      len(vals),
        "mean":   round(statistics.fmean(vals), 1),
        "median": round(statistics.median(vals), 1),
        "stdev":  round(statistics.stdev(vals), 1) if len(vals) > 1 else 0.0,
        "min":    round(min(vals), 1),
        "max":    round(max(vals), 1),
    }


def aggregate_technique(rows: list[dict]) -> dict:
    """Aggregate per-run result rows for ONE technique across a batch.

    `rows` is a list of result dicts (one per run), all sharing technique_id.
    """
    trials = len(rows)
    caught_rows = [r for r in rows if r.get("caught")]
    detections = len(caught_rows)
    rate = detections / trials if trials else 0.0
    ci_low, ci_high = wilson_interval(detections, trials)
    lat = latency_stats([r.get("latency_seconds") for r in caught_rows])

    sev_counts: Counter = Counter(
        (r.get("severity_assigned") or "").strip().lower()
        for r in caught_rows
        if r.get("severity_assigned")
    )
    # Mode = most frequently assigned severity among caught runs; ties broken
    # by severity order (highest wins) so the result is deterministic.
    if sev_counts:
        top = max(sev_counts.values())
        tied = [s for s, c in sev_counts.items() if c == top]
        sev_mode = max(tied, key=lambda s: _SEVERITY_ORDER.index(s)
                       if s in _SEVERITY_ORDER else -1)
    else:
        sev_mode = None

    first = rows[0] if rows else {}
    return {
        "technique_id":        first.get("technique_id"),
        "technique_name":      first.get("technique_name"),
        "tactic":              first.get("tactic"),
        "trials":              trials,
        "detections":          detections,
        "detection_rate":      round(rate, 3),
        "rate_ci_low":         round(ci_low, 3),
        "rate_ci_high":        round(ci_high, 3),
        # Caught in some runs but not all — the detection is unreliable, which a
        # single run would hide as a clean caught/missed.
        "flaky":               0 < detections < trials,
        "latency":             lat,
        "severity_mode":       sev_mode,
        # Every caught run assigned the same severity (<=1 distinct value).
        "severity_consistent": len(sev_counts) <= 1,
        "severity_counts":     dict(sev_counts),
    }


def aggregate_batch(runs_results: list[list[dict]]) -> dict:
    """Aggregate across a batch of runs.

    `runs_results` is a list of runs, each a list of result dicts — i.e.
    ``[get_results_for_run(r) for r in runs]``. Returns per-technique
    aggregates plus a batch-level summary (mean coverage across runs with its
    spread, and how many techniques were flaky).
    """
    runs = [r for r in runs_results if r]  # drop empty runs
    n_runs = len(runs)

    by_tech: dict[str, list[dict]] = {}
    for run_rows in runs:
        for row in run_rows:
            by_tech.setdefault(row["technique_id"], []).append(row)

    techniques = [aggregate_technique(rows) for rows in by_tech.values()]
    techniques.sort(key=lambda t: t["technique_id"] or "")

    # Per-run coverage fraction -> mean across runs with spread.
    coverages = []
    for run_rows in runs:
        total = len(run_rows)
        if total:
            coverages.append(sum(1 for r in run_rows if r.get("caught")) / total)
    cov_mean = round(statistics.fmean(coverages) * 100, 1) if coverages else None
    cov_stdev = round(statistics.stdev(coverages) * 100, 1) if len(coverages) > 1 else 0.0

    return {
        "n_runs":             n_runs,
        "n_techniques":       len(techniques),
        "coverage_mean_pct":  cov_mean,
        "coverage_stdev_pct": cov_stdev,
        "flaky_count":        sum(1 for t in techniques if t["flaky"]),
        "techniques":         techniques,
    }

"""
dashboard/api.py
----------------
Minimal FastAPI backend that serves SentinelBench SQLite data
to the React dashboard.

Run:
    python dashboard/api.py
    # or
    uvicorn dashboard.api:app --reload --port 8000

Endpoints:
    GET /api/runs                    list of all runs
    GET /api/runs/{run_id}           full run detail (results + summary)
    GET /api/runs/{run_id}/kql       KQL suggestions for a run
    GET /api/techniques              full v1 technique registry
    GET /health                      liveness check
"""

import sys
import os

# Allow running from repo root: python dashboard/api.py
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

from core.db import (
    list_runs,
    get_run,
    get_results_for_run,
    get_kql_for_run,
    run_summary,
)
from core.simulation_runner import TECHNIQUES, V1_SUITE_ORDER
from core.metrics_engine import latency_band

app = FastAPI(
    title="SentinelBench API",
    description="Serves benchmark results to the React dashboard.",
    version="1.0.0",
)

# Allow the Vite dev server (port 5173) to call this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["GET"],
    allow_headers=["*"],
)


# ── routes ─────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/api/runs")
def get_runs():
    """Return the last 50 runs, newest first."""
    runs = list_runs(limit=50)
    # Attach a quick summary to each run for the history table
    enriched = []
    for r in runs:
        s = run_summary(r["run_id"])
        enriched.append({**r, **s})
    return enriched


@app.get("/api/runs/{run_id}")
def get_run_detail(run_id: str):
    """Return full run detail: metadata + all results + summary."""
    run = get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"Run {run_id} not found")

    results = get_results_for_run(run_id)
    summary = run_summary(run_id)

    # Enrich each result with latency_band and technique metadata
    enriched_results = []
    for r in results:
        meta = TECHNIQUES.get(r["technique_id"], {})
        enriched_results.append({
            **r,
            "latency_band":   latency_band(r["latency_seconds"]),
            "tactic":         meta.get("tactic", r.get("tactic", "")),
            "description":    meta.get("description", ""),
        })

    return {
        "run":     run,
        "summary": summary,
        "results": enriched_results,
    }


@app.get("/api/runs/{run_id}/kql")
def get_kql_suggestions(run_id: str):
    """Return all KQL suggestions for missed detections in a run."""
    run = get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"Run {run_id} not found")
    return get_kql_for_run(run_id)


@app.get("/api/techniques")
def get_techniques():
    """Return the full v1 technique registry in suite order."""
    return [
        {"technique_id": tid, **TECHNIQUES[tid]}
        for tid in V1_SUITE_ORDER
    ]


# ── entrypoint ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Pass the app object directly so it works regardless of invocation path
    uvicorn.run(app, host="127.0.0.1", port=8000)

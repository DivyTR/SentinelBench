# SentinelBench Dashboard

A React dashboard that visualises benchmark runs stored in `sentinelbench.db`.
A small FastAPI backend (`api.py`) serves the SQLite data; the React app
(Vite + D3 + Tailwind) renders it.

## Views

| View | What it shows |
|------|---------------|
| **ATT&CK Heatmap** | Every technique as a tile, grouped by tactic, colour-coded by detection latency (green < 3 min, amber 3–10 min, red > 10 min, dark = missed). |
| **Run History** | Every run side by side — caught/missed, coverage %, average latency, severity issues. This is where config B vs C reads at a glance. |
| **Remediation** | The missed detections only, each with the generated KQL rule, a confidence badge, and its data source — the closed-loop "here's how to fix the gap" view. |

## Running

The backend reads the repo's `sentinelbench.db`, so run a benchmark first (or
copy a `sentinelbench.db` with runs in it to the repo root).

```bash
# 1. backend (serves the SQLite data on :8000)
python dashboard/api.py

# 2. frontend (Vite dev server on :5173, proxies /api to the backend)
cd dashboard && npm install && npm run dev
# open http://localhost:5173
```

## Tech stack

React 18 · D3.js (heatmap) · Tailwind · Vite · FastAPI (backend).

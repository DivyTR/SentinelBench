#!/usr/bin/env python3
"""
sentinelbench.py
----------------
Main entry point for SentinelBench.

Usage
-----
  # Test a single technique (production mode)
  python sentinelbench.py --technique T1003.001

  # Run the full v1 suite
  python sentinelbench.py --suite v1

  # Dry run — simulates the pipeline with random results, no ART execution
  python sentinelbench.py --suite v1 --dry-run

  # Show the last 5 run summaries from the database
  python sentinelbench.py --history 5

  # Show all KQL suggestions for a specific run
  python sentinelbench.py --run-id <run_id> --show-kql

Environment
-----------
  Copy .env.example to .env and fill in your Azure credentials before running.
  The .env file is loaded automatically at startup.
"""

import argparse
import json
import os
import platform
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path

# Load .env before importing core modules so env vars are available
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    print("[warn] python-dotenv not installed — reading env vars from shell only")

from core import (
    init_db,
    SentinelClient,
    SimulationRunner,
    TECHNIQUES,
    V1_SUITE_ORDER,
    MetricsEngine,
    KQLGenerator,
)
from core.db import (
    create_run,
    finish_run,
    save_result,
    save_kql_suggestion,
    run_summary,
    list_runs,
    get_results_for_run,
    get_kql_for_run,
    get_missed_detections,
)


# ── CLI ────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sentinelbench",
        description="Detection quality benchmarking for Microsoft Sentinel.",
    )
    mode = p.add_mutually_exclusive_group()
    mode.add_argument(
        "--technique", metavar="ID",
        help="Run a single ATT&CK technique (e.g. T1003.001)",
    )
    mode.add_argument(
        "--suite", metavar="NAME", default=None,
        help="Run a named suite of techniques (currently only 'v1')",
    )
    mode.add_argument(
        "--history", metavar="N", type=int, default=None,
        help="Show the last N run summaries",
    )
    mode.add_argument(
        "--list-techniques", action="store_true",
        help="Print all v1 techniques and exit",
    )
    p.add_argument(
        "--dry-run", action="store_true",
        help="Simulate pipeline without executing ART or polling Sentinel",
    )
    p.add_argument(
        "--run-id", metavar="ID",
        help="Specify a run ID for --show-kql or --show-results",
    )
    p.add_argument(
        "--show-kql", action="store_true",
        help="Print KQL suggestions for the specified --run-id",
    )
    p.add_argument(
        "--show-results", action="store_true",
        help="Print all results for the specified --run-id",
    )
    p.add_argument(
        "--notes", metavar="TEXT", default="",
        help="Optional notes to attach to this run",
    )
    return p


# ── main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    # Initialise DB on every startup (no-op if already exists)
    init_db()

    # ── informational modes ────────────────────────────────────────────────────

    if args.list_techniques:
        _print_techniques()
        sys.exit(0)

    if args.history is not None:
        _print_history(args.history)
        sys.exit(0)

    if args.show_results and args.run_id:
        _print_results(args.run_id)
        sys.exit(0)

    if args.show_kql and args.run_id:
        _print_kql(args.run_id)
        sys.exit(0)

    # ── benchmark modes ────────────────────────────────────────────────────────

    if not args.technique and not args.suite:
        parser.print_help()
        sys.exit(0)

    dry_run = args.dry_run

    # Build technique list
    if args.technique:
        if args.technique not in TECHNIQUES:
            print(f"[error] Unknown technique '{args.technique}'")
            print(f"        Use --list-techniques to see valid IDs.")
            sys.exit(1)
        techniques = [args.technique]
        suite_name = args.technique
    else:
        techniques = V1_SUITE_ORDER
        suite_name = args.suite

    # Validate credentials early (skip in dry-run)
    client = None
    if not dry_run:
        try:
            client = SentinelClient()
            print("[auth] Testing Sentinel connection ...")
            client.test_connection()
            print("[auth] Connected to Log Analytics workspace ✓")
        except Exception as exc:
            print(f"[error] Sentinel connection failed: {exc}")
            print("        Check your .env credentials or use --dry-run to test the pipeline.")
            sys.exit(1)
    else:
        print("[mode] DRY RUN — no ART execution, synthetic alert data")
        client = None  # MetricsEngine handles dry_run internally

    # Create the run record
    run_id = create_run(
        suite=suite_name,
        host=socket.gethostname(),
        sentinel_workspace=os.environ.get("SENTINEL_WORKSPACE_ID", "dry-run"),
        notes=args.notes,
    )
    print(f"\n[run] Started run {run_id}")
    print(f"[run] Suite: {suite_name}  |  Techniques: {len(techniques)}\n")

    runner  = SimulationRunner(dry_run=dry_run)
    metrics = MetricsEngine(client=client, dry_run=dry_run)
    gen     = KQLGenerator()

    results = []

    for i, technique_id in enumerate(techniques, 1):
        meta = TECHNIQUES[technique_id]
        print(f"\n{'-' * 60}")
        print(f"[{i}/{len(techniques)}] {technique_id} - {meta['name']}")
        print(f"  Tactic: {meta['tactic']}  |  Expected severity: {meta['severity_expected']}")

        # 1. Execute the simulation
        sim_result = runner.run_technique(technique_id)

        if not sim_result["success"] and not dry_run:
            print(f"  [warn] ART execution failed: {sim_result['error']}")
            print(f"  [warn] Skipping alert observation for this technique.")
            continue

        exec_time = datetime.fromisoformat(sim_result["timestamp_exec"])

        # 2. Observe Sentinel for alerts
        measurement = metrics.observe(
            technique_id=technique_id,
            severity_expected=meta["severity_expected"],
            exec_time=exec_time,
        )

        # 3. Persist result
        raw_log_json = (
            json.dumps(measurement["raw_logs"][:5])
            if measurement["raw_logs"]
            else None
        )

        result_id = save_result(
            run_id=run_id,
            technique_id=technique_id,
            technique_name=meta["name"],
            tactic=meta["tactic"],
            timestamp_exec=sim_result["timestamp_exec"],
            caught=measurement["caught"],
            severity_expected=meta["severity_expected"],
            timestamp_alert=measurement.get("alert_row", {}).get("TimeGenerated") if measurement["alert_row"] else None,
            latency_seconds=measurement["latency_seconds"],
            severity_assigned=measurement["severity_assigned"],
            poll_checkpoint=measurement["poll_checkpoint"],
            raw_log_sample=raw_log_json,
        )

        # 4. Generate KQL if missed
        if not measurement["caught"]:
            suggestion = gen.generate(
                technique_id=technique_id,
                raw_logs=measurement["raw_logs"],
            )
            save_kql_suggestion(
                result_id=result_id,
                technique_id=technique_id,
                kql_query=suggestion["kql_query"],
                confidence=suggestion["confidence"],
                data_source=suggestion["data_source"],
                false_positive_note=suggestion["false_positive_note"],
            )
            print(f"  [kql] KQL suggestion generated ({suggestion['confidence']} confidence)")

        results.append({**sim_result, **measurement, "result_id": result_id})

    # Finish the run
    finish_run(run_id)

    # Print summary
    _print_run_summary(run_id)

    print(f"\n[run] Complete. Run ID: {run_id}")
    print(f"[run] View KQL suggestions: python sentinelbench.py --run-id {run_id} --show-kql")


# ── display helpers ────────────────────────────────────────────────────────────

def _print_run_summary(run_id: str) -> None:
    summary = run_summary(run_id)
    print(f"\n{'=' * 60}")
    print(f"  Run Summary - {run_id[:8]}...")
    print(f"{'-' * 60}")
    print(f"  Techniques run  : {summary['total']}")
    print(f"  Caught          : {summary['caught']}  ({summary['coverage_pct']}%)")
    print(f"  Missed          : {summary['missed']}")
    avg = summary['avg_latency_seconds']
    print(f"  Avg latency     : {avg:.0f}s" if avg else "  Avg latency     : n/a")
    print(f"  Severity miscal.: {summary['severity_miscalibrations']}")
    print(f"{'=' * 60}")


def _print_techniques() -> None:
    print(f"\n{'-' * 70}")
    print(f"{'ID':<14} {'Name':<40} {'Tactic':<20} {'Exp. Sev.'}")
    print(f"{'-' * 70}")
    for tid in V1_SUITE_ORDER:
        t = TECHNIQUES[tid]
        print(f"{tid:<14} {t['name'][:38]:<40} {t['tactic']:<20} {t['severity_expected']}")
    print(f"{'-' * 70}")
    print(f"Total: {len(V1_SUITE_ORDER)} techniques in v1 suite\n")


def _print_history(n: int) -> None:
    runs = list_runs(limit=n)
    if not runs:
        print("[history] No runs found.")
        return
    print(f"\n{'-' * 80}")
    print(f"{'Run ID':<38} {'Suite':<15} {'Started':<22} {'Finished'}")
    print(f"{'-' * 80}")
    for r in runs:
        finished = r["finished_at"][:16] if r["finished_at"] else "in progress"
        print(f"{r['run_id']:<38} {r['suite']:<15} {r['started_at'][:16]:<22} {finished}")


def _print_results(run_id: str) -> None:
    results = get_results_for_run(run_id)
    if not results:
        print(f"[error] No results found for run {run_id}")
        return
    print(f"\n{'-' * 80}")
    for r in results:
        status  = "CAUGHT" if r["caught"] else "MISSED"
        latency = f"{r['latency_seconds']:.0f}s" if r["latency_seconds"] else "—"
        sev     = r["severity_assigned"] or "—"
        delta   = r["severity_delta"]
        delta_s = f"delta={delta:+d}" if delta is not None else ""
        print(f"  {r['technique_id']:<14} [{status}]  latency={latency:<6}  sev={sev:<14} {delta_s}")


def _print_kql(run_id: str) -> None:
    suggestions = get_kql_for_run(run_id)
    if not suggestions:
        print(f"[kql] No KQL suggestions for run {run_id} (all techniques were caught?)")
        return
    print(f"\n[kql] {len(suggestions)} suggestion(s) for run {run_id[:8]}...\n")
    for s in suggestions:
        print(f"{'=' * 70}")
        print(f"  Technique : {s['technique_id']}")
        print(f"  Data src  : {s['data_source']}")
        print(f"  Confidence: {s['confidence']}")
        print(f"  FP note   : {s['false_positive_note']}")
        print(f"\n{s['kql_query']}\n")


if __name__ == "__main__":
    main()

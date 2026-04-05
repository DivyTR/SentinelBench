"""
core/metrics_engine.py
----------------------
Polls Microsoft Sentinel for alerts after each technique simulation,
measures detection latency and severity accuracy, and decides caught/missed.

Poll schedule
-------------
After a technique executes, we check Sentinel at four checkpoints:
  T+2min, T+5min, T+10min, T+15min

If an alert surfaces at any checkpoint, we record it as caught along with
the latency (alert_timestamp - exec_timestamp).  If nothing surfaces by
T+15min, the technique is recorded as missed.

Why T+15min cutoff?
-------------------
Microsoft's Log Analytics ingestion pipeline typically adds 1–3 minutes of
baseline lag.  Anything beyond 15 minutes is operationally useless — an
attacker who triggered an LSASS dump at T+0 has had 15 minutes to harvest
credentials, pivot, and establish persistence before the first alert fires.
We note this lag in all latency outputs so results are interpreted correctly.
"""

import time
from datetime import datetime, timezone
from typing import Optional

from .sentinel_client import SentinelClient


# ── latency thresholds (seconds) ──────────────────────────────────────────────

LATENCY_GREEN  = 180    # < 3 min  — operationally effective
LATENCY_AMBER  = 600    # 3–10 min — narrow response window
LATENCY_RED    = 900    # > 10 min — unlikely to prevent attacker progress
# > 15 min (900s) = missed


POLL_CHECKPOINTS_MINUTES = [2, 5, 10, 15]


def latency_band(latency_seconds: Optional[float]) -> str:
    """Return a human-readable band label for a latency value."""
    if latency_seconds is None:
        return "missed"
    if latency_seconds < LATENCY_GREEN:
        return "green"
    if latency_seconds < LATENCY_AMBER:
        return "amber"
    return "red"


# ── main observer ──────────────────────────────────────────────────────────────

class MetricsEngine:
    """
    Observes Sentinel alerts for a technique that just ran and
    produces a structured measurement result.

    Usage
    -----
        engine = MetricsEngine(client)
        measurement = engine.observe(
            technique_id="T1003.001",
            severity_expected="High",
            exec_time=datetime.now(timezone.utc),
        )
    """

    def __init__(self, client: SentinelClient, dry_run: bool = False):
        self.client  = client
        self.dry_run = dry_run

    def observe(
        self,
        technique_id: str,
        severity_expected: str,
        exec_time: datetime,
    ) -> dict:
        """
        Poll Sentinel at each checkpoint until an alert is found or
        all checkpoints are exhausted.

        Returns a measurement dict:
          caught             bool
          latency_seconds    float | None
          latency_band       str ('green'|'amber'|'red'|'missed')
          severity_assigned  str | None
          severity_expected  str
          severity_delta     int | None  (positive = under-rated)
          poll_checkpoint    str | None  (e.g. 'T+5min')
          alert_row          dict | None (raw Sentinel row)
          raw_logs           list[dict]  (event logs for KQL seeding)
        """
        if self.dry_run:
            return _dry_run_measurement(technique_id, severity_expected)

        previous_checkpoint_elapsed = 0

        for checkpoint_minutes in POLL_CHECKPOINTS_MINUTES:
            # Sleep only the delta since we last checked
            sleep_seconds = (checkpoint_minutes * 60) - previous_checkpoint_elapsed
            if sleep_seconds > 0:
                print(
                    f"    [obs] Waiting {sleep_seconds}s "
                    f"(checkpoint T+{checkpoint_minutes}min) ..."
                )
                time.sleep(sleep_seconds)

            previous_checkpoint_elapsed = checkpoint_minutes * 60

            alert_row = self.client.check_alert_for_technique(
                technique_id=technique_id,
                since=exec_time,
                window_minutes=checkpoint_minutes + 2,  # slight overlap for safety
            )

            if alert_row:
                alert_time     = _parse_alert_time(alert_row)
                latency        = _calc_latency(exec_time, alert_time)
                sev_assigned   = _extract_severity(alert_row)
                sev_delta      = _severity_delta(sev_assigned, severity_expected)
                checkpoint_label = f"T+{checkpoint_minutes}min"

                print(
                    f"    [obs] CAUGHT at {checkpoint_label} — "
                    f"latency={latency:.0f}s  severity={sev_assigned} "
                    f"(expected {severity_expected})"
                )

                # Fetch raw logs for KQL seeding (best-effort)
                raw_logs = _safe_fetch_logs(
                    self.client, technique_id, exec_time
                )

                return {
                    "caught":            True,
                    "latency_seconds":   latency,
                    "latency_band":      latency_band(latency),
                    "severity_assigned": sev_assigned,
                    "severity_expected": severity_expected,
                    "severity_delta":    sev_delta,
                    "poll_checkpoint":   checkpoint_label,
                    "alert_row":         alert_row,
                    "raw_logs":          raw_logs,
                }

        # All checkpoints exhausted — missed detection
        print(f"    [obs] MISSED — no alert found within {POLL_CHECKPOINTS_MINUTES[-1]} minutes")

        raw_logs = _safe_fetch_logs(self.client, technique_id, exec_time)

        return {
            "caught":            False,
            "latency_seconds":   None,
            "latency_band":      "missed",
            "severity_assigned": None,
            "severity_expected": severity_expected,
            "severity_delta":    None,
            "poll_checkpoint":   None,
            "alert_row":         None,
            "raw_logs":          raw_logs,
        }


# ── internal helpers ───────────────────────────────────────────────────────────

def _parse_alert_time(alert_row: dict) -> datetime:
    """
    Extract the alert creation timestamp from a Sentinel row.
    Handles both SecurityAlert (TimeGenerated) and SecurityIncident (CreatedTime).
    """
    raw = alert_row.get("TimeGenerated") or alert_row.get("CreatedTime") or ""
    try:
        # Azure returns ISO 8601 with Z suffix
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return datetime.now(timezone.utc)


def _calc_latency(exec_time: datetime, alert_time: datetime) -> float:
    """Return latency in seconds, minimum 0."""
    delta = (alert_time - exec_time).total_seconds()
    return max(0.0, delta)


def _extract_severity(alert_row: dict) -> str:
    """Pull the severity string from an alert row, normalised to Title Case."""
    raw = alert_row.get("AlertSeverity") or alert_row.get("Severity") or "Unknown"
    return raw.strip().title()


_SEVERITY_RANK = {"Informational": 0, "Low": 1, "Medium": 2, "High": 3}


def _severity_delta(assigned: str, expected: str) -> int:
    """
    Positive = Sentinel under-rated (bad).
    Zero     = accurate.
    Negative = Sentinel over-rated.
    """
    a = _SEVERITY_RANK.get(assigned.title(), -1)
    e = _SEVERITY_RANK.get(expected.title(), -1)
    if a == -1 or e == -1:
        return 0
    return e - a


def _safe_fetch_logs(
    client: SentinelClient,
    technique_id: str,
    exec_time: datetime,
) -> list[dict]:
    """Fetch raw event logs; return empty list on any failure."""
    try:
        return client.fetch_raw_logs(technique_id, exec_time, window_minutes=5)
    except Exception as exc:
        print(f"    [obs] Warning: could not fetch raw logs — {exc}")
        return []


def _dry_run_measurement(technique_id: str, severity_expected: str) -> dict:
    """Return a synthetic measurement for dry-run mode."""
    import random
    simulated_caught = random.random() > 0.35  # ~65% detection rate for demo
    latency = round(random.uniform(30, 800), 1) if simulated_caught else None

    return {
        "caught":            simulated_caught,
        "latency_seconds":   latency,
        "latency_band":      latency_band(latency),
        "severity_assigned": random.choice(["High", "Medium", "Low"]) if simulated_caught else None,
        "severity_expected": severity_expected,
        "severity_delta":    random.choice([0, 0, 1, -1]) if simulated_caught else None,
        "poll_checkpoint":   random.choice(["T+2min", "T+5min", "T+10min"]) if simulated_caught else None,
        "alert_row":         {"AlertName": "[dry-run alert]"} if simulated_caught else None,
        "raw_logs":          [{"EventID": 4688, "Process": "powershell.exe", "CommandLine": "[dry-run]"}],
    }

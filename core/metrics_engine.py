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
from datetime import datetime, timedelta, timezone

import requests

from .sentinel_client import SentinelClient, SentinelClientError

# ── latency thresholds (seconds) ──────────────────────────────────────────────

LATENCY_GREEN  = 180    # < 3 min  — operationally effective
LATENCY_AMBER  = 600    # 3–10 min — narrow response window
LATENCY_RED    = 900    # > 10 min — unlikely to prevent attacker progress
# > 15 min (900s) = missed


POLL_CHECKPOINTS_MINUTES = [2, 5, 10, 15]


def latency_band(latency_seconds: float | None) -> str:
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
        engine = MetricsEngine(client, host="sb-lab-vm")
        measurement = engine.observe(
            technique_id="T1003.001",
            match_ids=["T1003.001", "T1003"],
            severity_expected="High",
            exec_time=datetime.now(timezone.utc),
        )
    """

    def __init__(
        self,
        client: SentinelClient | None,
        dry_run: bool = False,
        host: str | None = None,
        clock=None,
        sleep=time.sleep,
    ):
        self.client  = client
        self.dry_run = dry_run
        self.host    = host
        # Injectable for tests; production uses the real clock and sleep.
        self._clock  = clock or (lambda: datetime.now(timezone.utc))
        self._sleep  = sleep

    def observe(
        self,
        technique_id: str,
        match_ids: list[str],
        severity_expected: str,
        exec_time: datetime,
    ) -> dict:
        """
        Poll Sentinel at each checkpoint until an alert is found or
        all checkpoints are exhausted.

        Checkpoints are absolute offsets from exec_time (T+2min means
        exec_time + 2 minutes), not from when observe() is called, and each
        poll only considers alerts created up to its checkpoint, so the
        result does not depend on how promptly the polls actually run.

        Returns a measurement dict:
          caught             bool
          latency_seconds    float | None  (alert created - exec_time)
          latency_band       str ('green'|'amber'|'red'|'missed')
          severity_assigned  str | None
          severity_expected  str
          severity_delta     int | None  (positive = under-rated; None if
                                          severity is missing or unrecognised)
          poll_checkpoint    str | None  (e.g. 'T+5min')
          timestamp_alert    str | None  (ISO; when the alert was created)
          alert_row          dict | None (raw Sentinel row)
          raw_logs           list[dict]  (event logs for KQL seeding)
        """
        if self.dry_run:
            return _dry_run_measurement(technique_id, severity_expected)

        for checkpoint_minutes in POLL_CHECKPOINTS_MINUTES:
            checkpoint_at = exec_time + timedelta(minutes=checkpoint_minutes)
            sleep_seconds = (checkpoint_at - self._clock()).total_seconds()
            if sleep_seconds > 0:
                print(
                    f"    [obs] Waiting {sleep_seconds:.0f}s "
                    f"(checkpoint T+{checkpoint_minutes}min) ..."
                )
                self._sleep(sleep_seconds)

            # Search only up to the checkpoint itself, not "now". If polling
            # runs late (a paused console, a slow query), an alert created
            # after T+15min must still count as missed, and an alert found at
            # a late T+5 poll must not be credited to an earlier checkpoint.
            alert_row = self.client.check_alert_for_technique(
                match_ids=match_ids,
                since=exec_time,
                until=checkpoint_at,
                host=self.host,
            )

            if alert_row:
                alert_time     = _parse_alert_time(alert_row)
                latency        = _calc_latency(exec_time, alert_time)
                sev_assigned   = _extract_severity(alert_row)
                sev_delta      = severity_delta(sev_assigned, severity_expected)
                checkpoint_label = f"T+{checkpoint_minutes}min"

                print(
                    f"    [obs] CAUGHT at {checkpoint_label} - "
                    f"latency={latency:.0f}s  severity={sev_assigned} "
                    f"(expected {severity_expected})"
                )

                # Fetch raw logs for KQL seeding (best-effort)
                raw_logs = _safe_fetch_logs(
                    self.client, technique_id, exec_time, self.host
                )

                return {
                    "caught":            True,
                    "latency_seconds":   latency,
                    "latency_band":      latency_band(latency),
                    "severity_assigned": sev_assigned,
                    "severity_expected": severity_expected,
                    "severity_delta":    sev_delta,
                    "poll_checkpoint":   checkpoint_label,
                    "timestamp_alert":   alert_time.isoformat(),
                    "alert_row":         alert_row,
                    "raw_logs":          raw_logs,
                }

        # All checkpoints exhausted — missed detection
        print(f"    [obs] MISSED - no alert found within {POLL_CHECKPOINTS_MINUTES[-1]} minutes")

        raw_logs = _safe_fetch_logs(self.client, technique_id, exec_time, self.host)

        return {
            "caught":            False,
            "latency_seconds":   None,
            "latency_band":      "missed",
            "severity_assigned": None,
            "severity_expected": severity_expected,
            "severity_delta":    None,
            "poll_checkpoint":   None,
            "timestamp_alert":   None,
            "alert_row":         None,
            "raw_logs":          raw_logs,
        }


# ── severity ───────────────────────────────────────────────────────────────────

_SEVERITY_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3}


def severity_delta(assigned: str | None, expected: str | None) -> int | None:
    """
    expected - assigned, on the scale Informational(0) .. High(3).

    Positive = Sentinel under-rated (bad).
    Zero     = accurate.
    Negative = Sentinel over-rated.
    None     = either value is missing or not a recognised severity, so no
               judgement can be made (never silently counted as accurate).
    """
    if not assigned or not expected:
        return None
    a = _SEVERITY_RANK.get(assigned.strip().lower())
    e = _SEVERITY_RANK.get(expected.strip().lower())
    if a is None or e is None:
        return None
    return e - a


# ── internal helpers ───────────────────────────────────────────────────────────

def _parse_alert_time(alert_row: dict) -> datetime:
    """
    Extract the alert creation timestamp from a Sentinel row.
    Handles both SecurityAlert (TimeGenerated) and SecurityIncident (CreatedTime).

    Raises ValueError rather than guessing: substituting "now" would record
    a fabricated latency.
    """
    raw = alert_row.get("TimeGenerated") or alert_row.get("CreatedTime")
    if not raw:
        raise ValueError(f"Alert row has no timestamp: {alert_row}")
    # Azure returns ISO 8601 with a Z suffix and up to 7 fractional digits,
    # which datetime.fromisoformat() rejects before Python 3.11.
    raw = raw.replace("Z", "+00:00")
    if "." in raw:
        head, rest = raw.split(".", 1)
        frac, tz = rest[:-6], rest[-6:]
        raw = f"{head}.{frac[:6].ljust(6, '0')}{tz}"
    return datetime.fromisoformat(raw)


def _calc_latency(exec_time: datetime, alert_time: datetime) -> float:
    """Return latency in seconds, minimum 0."""
    delta = (alert_time - exec_time).total_seconds()
    return max(0.0, delta)


def _extract_severity(alert_row: dict) -> str | None:
    """Pull the severity string from an alert row, normalised to Title Case."""
    raw = alert_row.get("AlertSeverity") or alert_row.get("Severity")
    return raw.strip().title() if raw else None


def _safe_fetch_logs(
    client: SentinelClient,
    technique_id: str,
    exec_time: datetime,
    host: str | None = None,
) -> list[dict]:
    """
    Fetch raw event logs for KQL seeding.  Best-effort: a query or network
    failure here must not lose the caught/missed measurement, so it degrades
    to an empty list.  Programming errors still propagate.
    """
    try:
        return client.fetch_raw_logs(technique_id, exec_time, window_minutes=5, host=host)
    except (SentinelClientError, requests.RequestException, ValueError) as exc:
        print(f"    [obs] Warning: could not fetch raw logs - {exc}")
        return []


def _dry_run_measurement(technique_id: str, severity_expected: str) -> dict:
    """Return a synthetic measurement for dry-run mode."""
    import random
    simulated_caught = random.random() > 0.35  # ~65% detection rate for demo
    latency = round(random.uniform(30, 800), 1) if simulated_caught else None
    sev_assigned = random.choice(["High", "Medium", "Low"]) if simulated_caught else None

    return {
        "caught":            simulated_caught,
        "latency_seconds":   latency,
        "latency_band":      latency_band(latency),
        "severity_assigned": sev_assigned,
        "severity_expected": severity_expected,
        "severity_delta":    severity_delta(sev_assigned, severity_expected),
        "poll_checkpoint":   random.choice(["T+2min", "T+5min", "T+10min"]) if simulated_caught else None,
        "timestamp_alert":   None,
        "alert_row":         {"AlertName": "[dry-run alert]"} if simulated_caught else None,
        "raw_logs":          [{"EventID": 4688, "Process": "powershell.exe", "CommandLine": "[dry-run]"}],
    }

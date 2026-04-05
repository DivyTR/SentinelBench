"""
metrics_engine.py — Latency and severity metrics computation.

Responsibilities:
  - Compute detection latency: timestamp_alert - timestamp_exec (seconds).
  - Compare Sentinel-assigned severity against ATT&CK-expected severity.
  - Emit a DetectionResult for each technique run.
"""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class Severity(str, Enum):
    INFORMATIONAL = "Informational"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


# Expected severity per technique based on ATT&CK impact characterisation.
EXPECTED_SEVERITY: dict[str, Severity] = {
    "T1059.001": Severity.HIGH,
    "T1059.003": Severity.MEDIUM,
    "T1569.002": Severity.HIGH,
    "T1547.001": Severity.HIGH,
    "T1053.005": Severity.HIGH,
    "T1136.001": Severity.MEDIUM,
    "T1003.001": Severity.HIGH,
    "T1110.001": Severity.HIGH,
    "T1552.001": Severity.MEDIUM,
    "T1555.003": Severity.MEDIUM,
    "T1040":     Severity.MEDIUM,
    "T1070.001": Severity.HIGH,
    "T1562.001": Severity.HIGH,
    "T1027":     Severity.MEDIUM,
    "T1112":     Severity.LOW,
}


@dataclass
class DetectionResult:
    technique_id: str
    timestamp_exec: datetime
    caught: bool
    latency_seconds: float | None          # None if missed
    severity_assigned: Severity | None     # None if missed
    severity_expected: Severity
    severity_delta: int                    # assigned - expected (ordinal); 0 = accurate
    needs_kql_suggestion: bool


class MetricsEngine:
    """Stub. Computes per-technique detection metrics from alert data."""

    def evaluate(
        self,
        technique_id: str,
        timestamp_exec: datetime,
        alerts: list[dict],
    ) -> DetectionResult:
        """
        Given the list of alerts returned by SentinelClient, compute metrics.
        alerts=[] means the technique was missed.
        """
        raise NotImplementedError

    def _severity_delta(
        self,
        assigned: Severity,
        expected: Severity,
    ) -> int:
        """Return ordinal difference (negative = over-assigned, positive = under-assigned)."""
        order = [s for s in Severity]
        return order.index(expected) - order.index(assigned)

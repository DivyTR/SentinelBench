"""
kql_generator.py — KQL detection rule generator for missed techniques.

Responsibilities:
  - Accept raw log rows from the simulation window.
  - Select the most signal-rich event fields (EventID, process, cmdline, parent).
  - Render a targeted KQL rule using event-seeded templates.
  - Tag each rule with: ATT&CK ID, data source, confidence, FP risk note.
"""

from dataclasses import dataclass
from enum import Enum


class Confidence(str, Enum):
    HIGH = "High"        # Seeded from observed EventIDs + process names; low FP risk.
    MEDIUM = "Medium"    # Technique-class heuristics; review before production.
    REQUIRES_TUNING = "Requires tuning"  # Environment-specific fields need adjustment.


@dataclass
class KQLSuggestion:
    technique_id: str
    data_source: str          # e.g. "SecurityEvent", "Sysmon", "DeviceProcessEvents"
    confidence: Confidence
    fp_risk_note: str
    kql: str                  # The rendered KQL rule body


class KQLGenerator:
    """Stub. Generates detection rules seeded from simulation log data."""

    def generate(
        self,
        technique_id: str,
        raw_logs: list[dict],
    ) -> KQLSuggestion:
        """
        Produce a KQL suggestion for a missed technique.
        raw_logs are rows fetched by SentinelClient.get_raw_logs().
        """
        raise NotImplementedError

    def _select_template(self, technique_id: str) -> str:
        """Return the KQL template string for this technique family."""
        raise NotImplementedError

    def _seed_template(self, template: str, log_sample: dict) -> str:
        """Substitute observed values (EventID, process name, cmdline) into the template."""
        raise NotImplementedError

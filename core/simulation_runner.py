"""
simulation_runner.py — Atomic Red Team execution wrapper.

Responsibilities:
  - Invoke Invoke-AtomicTest via PowerShell for a given technique ID.
  - Record the execution timestamp immediately before triggering the atomic.
  - Return a SimulationResult with technique ID, host info, and exec timestamp.
"""

import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class SimulationResult:
    technique_id: str
    timestamp_exec: datetime
    host: str
    success: bool
    error: str | None = None
    raw_output: str = field(default="", repr=False)


class SimulationRunner:
    """Stub. Requires Atomic Red Team installed on the lab VM."""

    def __init__(self, atomic_base_path: str = "C:\\AtomicRedTeam") -> None:
        self.atomic_base_path = atomic_base_path

    def run(self, technique_id: str, test_number: int = 1) -> SimulationResult:
        """
        Execute an Atomic Red Team test for technique_id.
        Records timestamp_exec immediately before the PowerShell call.
        """
        raise NotImplementedError

    def _build_ps_command(self, technique_id: str, test_number: int) -> list[str]:
        """Return the subprocess argv list for Invoke-AtomicTest."""
        # Example:
        # powershell -ExecutionPolicy Bypass -Command
        #   "Invoke-AtomicTest T1003.001 -TestNumbers 1 -GetPrereqs; Invoke-AtomicTest T1003.001 -TestNumbers 1"
        raise NotImplementedError

    def cleanup(self, technique_id: str, test_number: int = 1) -> None:
        """Run Invoke-AtomicTest cleanup to restore the system after simulation."""
        raise NotImplementedError

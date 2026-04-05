"""
core/simulation_runner.py
-------------------------
Orchestrates Atomic Red Team (ART) technique execution on the lab VM.

How ART execution works
-----------------------
Atomic Red Team ships as a PowerShell module (AtomicRedTeam) with individual
YAML test definitions per technique.  SentinelBench calls the ART
`Invoke-AtomicTest` cmdlet via subprocess, which:
  1. Checks prerequisites (installs them if needed with -GetPrereqs)
  2. Executes the atomic test (the actual simulation)
  3. Optionally runs cleanup (-Cleanup) to undo lab artefacts

Safety note
-----------
All ART simulations are designed to be safe in an isolated lab environment.
They do NOT exfiltrate data, connect to real C2 infrastructure, or cause
permanent OS damage.  However, they DO create real artefacts — registry keys,
local accounts, scheduled tasks, LSASS memory access — which is exactly what
generates the telemetry Sentinel needs to detect.

Never run this against a production host.
"""

import json
import platform
import subprocess
import sys
from datetime import datetime, timezone
from typing import Optional


# ── technique registry ────────────────────────────────────────────────────────
# Each entry defines the 15 v1 techniques with their ATT&CK metadata and
# the specific ART atomic test number to use.

TECHNIQUES: dict[str, dict] = {
    # ── Execution ─────────────────────────────────────────────────────────────
    "T1059.001": {
        "name":              "PowerShell",
        "tactic":            "Execution",
        "severity_expected": "High",
        "art_test_number":   1,
        "description":       "Executes a benign encoded PowerShell command to test "
                             "Sentinel's script-block logging and process-creation alerts.",
        "cleanup":           True,
    },
    "T1059.003": {
        "name":              "Windows Command Shell",
        "tactic":            "Execution",
        "severity_expected": "Medium",
        "art_test_number":   1,
        "description":       "Runs cmd.exe with a benign command; baseline for "
                             "process-creation event logging.",
        "cleanup":           True,
    },
    "T1569.002": {
        "name":              "Service Execution",
        "tactic":            "Execution",
        "severity_expected": "High",
        "art_test_number":   1,
        "description":       "Creates and starts a benign Windows service to test "
                             "service-installation alert coverage.",
        "cleanup":           True,
    },

    # ── Persistence ───────────────────────────────────────────────────────────
    "T1547.001": {
        "name":              "Registry Run Keys / Startup Folder",
        "tactic":            "Persistence",
        "severity_expected": "High",
        "art_test_number":   1,
        "description":       "Adds a benign entry to HKCU Run key; tests registry "
                             "modification detection.",
        "cleanup":           True,
    },
    "T1053.005": {
        "name":              "Scheduled Task/Job",
        "tactic":            "Persistence",
        "severity_expected": "High",
        "art_test_number":   1,
        "description":       "Creates a benign scheduled task; tests Task Scheduler "
                             "event log detection.",
        "cleanup":           True,
    },
    "T1136.001": {
        "name":              "Create Local Account",
        "tactic":            "Persistence",
        "severity_expected": "High",
        "art_test_number":   1,
        "description":       "Creates a local user account; high-signal, low "
                             "false-positive test for account-management alerts.",
        "cleanup":           True,
    },

    # ── Credential Access ─────────────────────────────────────────────────────
    "T1003.001": {
        "name":              "LSASS Memory",
        "tactic":            "Credential Access",
        "severity_expected": "High",
        "art_test_number":   1,
        "description":       "Attempts to read LSASS process memory using legitimate "
                             "Windows APIs (no Mimikatz); tests MDE/Sysmon coverage.",
        "cleanup":           True,
    },
    "T1110.001": {
        "name":              "Brute Force — Password Guessing",
        "tactic":            "Credential Access",
        "severity_expected": "Medium",
        "art_test_number":   1,
        "description":       "Generates rapid failed logon attempts against a local "
                             "account; tests failed-login correlation thresholds.",
        "cleanup":           True,
    },
    "T1552.001": {
        "name":              "Credentials in Files",
        "tactic":            "Credential Access",
        "severity_expected": "Medium",
        "art_test_number":   1,
        "description":       "Searches local file system for credential patterns; "
                             "tests file-access and file-content scanning coverage.",
        "cleanup":           True,
    },
    "T1555.003": {
        "name":              "Credentials from Web Browsers",
        "tactic":            "Credential Access",
        "severity_expected": "High",
        "art_test_number":   1,
        "description":       "Reads browser credential store paths (no actual "
                             "extraction); tests whether Sentinel's severity for "
                             "browser-targeted activity is appropriate.",
        "cleanup":           True,
    },
    "T1040": {
        "name":              "Network Sniffing",
        "tactic":            "Credential Access",
        "severity_expected": "Medium",
        "art_test_number":   1,
        "description":       "Launches a network capture process briefly; tests "
                             "whether network-monitoring telemetry reaches Sentinel.",
        "cleanup":           True,
    },

    # ── Defense Evasion ───────────────────────────────────────────────────────
    "T1070.001": {
        "name":              "Clear Windows Event Logs",
        "tactic":            "Defense Evasion",
        "severity_expected": "High",
        "art_test_number":   1,
        "description":       "Clears the Security event log; critical meta-test — "
                             "if Sentinel misses this, subsequent detections may be "
                             "unreliable.",
        "cleanup":           False,   # log clearing is its own cleanup
    },
    "T1562.001": {
        "name":              "Disable or Modify Tools",
        "tactic":            "Defense Evasion",
        "severity_expected": "High",
        "art_test_number":   1,
        "description":       "Attempts to stop Windows Defender service; tests "
                             "whether MDE → Sentinel telemetry detects AV tampering.",
        "cleanup":           True,
    },
    "T1027": {
        "name":              "Obfuscated Files or Information",
        "tactic":            "Defense Evasion",
        "severity_expected": "Medium",
        "art_test_number":   1,
        "description":       "Executes a base64-encoded benign payload; tests "
                             "behaviour-based vs signature-based detection balance.",
        "cleanup":           True,
    },
    "T1112": {
        "name":              "Modify Registry",
        "tactic":            "Defense Evasion",
        "severity_expected": "Medium",
        "art_test_number":   1,
        "description":       "Modifies a registry key used by common malware; tests "
                             "whether high false-positive suppression is masking "
                             "real activity.",
        "cleanup":           True,
    },
}

# Ordered list for the v1 suite — run in this sequence to avoid interference
V1_SUITE_ORDER = [
    "T1059.003",  # cmd baseline first (lowest risk)
    "T1059.001",  # PowerShell
    "T1569.002",  # Service execution
    "T1136.001",  # Create account (persistence baseline)
    "T1547.001",  # Registry run key
    "T1053.005",  # Scheduled task
    "T1110.001",  # Brute force
    "T1552.001",  # Creds in files
    "T1555.003",  # Browser creds
    "T1040",      # Network sniffing
    "T1112",      # Modify registry
    "T1027",      # Obfuscation
    "T1562.001",  # Disable AV
    "T1003.001",  # LSASS (high-impact — run near end)
    "T1070.001",  # Clear logs (always last — meta-technique)
]


# ── runner ─────────────────────────────────────────────────────────────────────

class SimulationRunner:
    """
    Wraps Invoke-AtomicTest PowerShell calls.

    Prerequisites
    -------------
    On the lab VM, with PowerShell (5.1+ or PowerShell 7):
        Install-Module -Name invoke-atomicredteam -Force
        IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
        Invoke-WebRequest https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics -OutFile ...
    """

    def __init__(self, dry_run: bool = False):
        """
        Parameters
        ----------
        dry_run : If True, print the PowerShell command without executing it.
                  Useful for testing the pipeline without a live ART install.
        """
        self.dry_run = dry_run
        if not dry_run:
            _assert_windows()

    def run_technique(self, technique_id: str) -> dict:
        """
        Execute a single ART atomic test and return a result dict containing:
          - technique_id
          - technique_name
          - tactic
          - severity_expected
          - timestamp_exec  (UTC ISO string, set just before execution)
          - success         (bool — did the subprocess exit cleanly?)
          - stdout / stderr (truncated to 2000 chars each)
          - error           (None or exception message)
        """
        if technique_id not in TECHNIQUES:
            raise ValueError(
                f"Unknown technique '{technique_id}'. "
                f"Valid IDs: {list(TECHNIQUES.keys())}"
            )

        meta = TECHNIQUES[technique_id]
        test_num = meta["art_test_number"]
        timestamp_exec = _now()

        print(f"  [sim] Running {technique_id} ({meta['name']}) ...")

        if self.dry_run:
            print(f"  [sim] DRY RUN — would execute ART test {test_num} for {technique_id}")
            return {
                "technique_id":      technique_id,
                "technique_name":    meta["name"],
                "tactic":            meta["tactic"],
                "severity_expected": meta["severity_expected"],
                "timestamp_exec":    timestamp_exec,
                "success":           True,
                "stdout":            "[dry-run]",
                "stderr":            "",
                "error":             None,
            }

        # Step 1: install prerequisites (idempotent, safe to always run)
        prereq_cmd = _build_art_command(technique_id, test_num, get_prereqs=True)
        _run_powershell(prereq_cmd)

        # Step 2: execute the actual simulation — this is what generates telemetry
        exec_cmd = _build_art_command(technique_id, test_num)
        result = _run_powershell(exec_cmd)

        if result["success"] and meta.get("cleanup"):
            cleanup_cmd = _build_art_command(
                technique_id, test_num, cleanup=True
            )
            _run_powershell(cleanup_cmd)

        return {
            "technique_id":      technique_id,
            "technique_name":    meta["name"],
            "tactic":            meta["tactic"],
            "severity_expected": meta["severity_expected"],
            "timestamp_exec":    timestamp_exec,
            **result,
        }

    def run_suite(self, suite: str = "v1") -> list[dict]:
        """
        Run all techniques in the suite and return a list of result dicts.
        Currently only 'v1' is defined.
        """
        if suite != "v1":
            raise ValueError(f"Unknown suite '{suite}'. Only 'v1' is available.")

        results = []
        total = len(V1_SUITE_ORDER)
        for i, technique_id in enumerate(V1_SUITE_ORDER, 1):
            print(f"\n[{i}/{total}] {technique_id}")
            result = self.run_technique(technique_id)
            results.append(result)
        return results


# ── PowerShell helpers ─────────────────────────────────────────────────────────

def _build_art_command(
    technique_id: str,
    test_number: int,
    get_prereqs: bool = False,
    cleanup: bool = False,
) -> list[str]:
    """Build the PowerShell command list for subprocess."""
    ps_script = f"Invoke-AtomicTest {technique_id} -TestNumbers {test_number}"
    if get_prereqs:
        ps_script += " -GetPrereqs"
    if cleanup:
        ps_script += " -Cleanup"

    return [
        "powershell.exe",
        "-NonInteractive",
        "-ExecutionPolicy", "Bypass",
        "-Command", ps_script,
    ]


def _run_powershell(cmd: list[str], timeout: int = 120) -> dict:
    """Execute a PowerShell command and return success/stdout/stderr."""
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return {
            "success": proc.returncode == 0,
            "stdout":  proc.stdout[:2000],
            "stderr":  proc.stderr[:2000],
            "error":   None,
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "stdout":  "",
            "stderr":  "",
            "error":   f"Timed out after {timeout}s",
        }
    except Exception as exc:
        return {
            "success": False,
            "stdout":  "",
            "stderr":  "",
            "error":   str(exc),
        }


def _assert_windows() -> None:
    if platform.system() != "Windows":
        print(
            "[sim] WARNING: SimulationRunner is designed for Windows lab VMs. "
            "Non-Windows platforms will fail at technique execution. "
            "Use --dry-run to test the pipeline without executing ART.",
            file=sys.stderr,
        )


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

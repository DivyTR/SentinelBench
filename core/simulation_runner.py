"""
core/simulation_runner.py
-------------------------
Orchestrates Atomic Red Team (ART) technique execution on the lab VM.

How ART execution works
-----------------------
Atomic Red Team ships as a PowerShell module (AtomicRedTeam) with individual
YAML test definitions per technique.  SentinelBench calls the ART
`Invoke-AtomicTest` cmdlet via subprocess, which:
  1. Installs prerequisites (-GetPrereqs) and verifies them (-CheckPrereqs)
  2. Executes the pinned atomic test (selected by -TestGuids)
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

import os
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# ── technique registry ────────────────────────────────────────────────────────
# Each v1 technique is pinned to one specific ART test by GUID.  Test numbers
# are not stable across ART releases (tests get inserted and reordered), and
# test #1 is frequently a Linux/macOS test — which Invoke-AtomicTest silently
# skips on Windows.  Every test below runs on Windows and was chosen from
# the upstream atomics as of ART master 2026-09.
#
# Field reference
#   technique_id  ATT&CK v19 ID; key used throughout SentinelBench
#   tactic        primary ATT&CK v19 tactic (some techniques have several)
#   art_technique folder name in the atomics repo
#   match_ids     every ATT&CK ID an alert may carry for this technique.
#                 ATT&CK v19 revoked some IDs (e.g. T1070.001 -> T1685.005);
#                 Sentinel content written before v19 still uses the old
#                 ones, so alert matching accepts both.
#   art_guid      auto_generated_guid of the pinned atomic test
#   input_args    overrides for the test's input_arguments (optional)
#   atomics       "upstream" (C:\AtomicRedTeam\atomics) or "custom"
#                 (this repo's atomics/ folder, for gaps in upstream ART)
#   description   what the pinned test actually does on the host

TECHNIQUES: dict[str, dict] = {
    # ── Execution ─────────────────────────────────────────────────────────────
    "T1059.001": {
        "name":              "PowerShell",
        "tactic":            "Execution",
        "severity_expected": "High",
        "art_technique":     "T1059.001",
        "match_ids":         ["T1059.001", "T1059"],
        "art_guid":          "49eb9404-5e0f-4031-a179-b40f7be385e3",
        "atomics":           "upstream",
        "description":       "Defines and calls stub functions named after offensive "
                             "PowerShell cmdlets (Invoke-Mimikatz, Get-GPPPassword, ...). "
                             "Nothing malicious runs; tests script-block logging (4104) "
                             "and cmdlet-name detections.",
        "cleanup":           False,
    },
    "T1059.003": {
        "name":              "Windows Command Shell",
        "tactic":            "Execution",
        "severity_expected": "Medium",
        "art_technique":     "T1059.003",
        "match_ids":         ["T1059.003", "T1059"],
        "art_guid":          "d0eb3597-a1b3-4d65-b33b-2cda8d397f20",
        "atomics":           "upstream",
        "description":       "Launches cmd.exe via an environment-variable substring "
                             "(%LOCALAPPDATA:~-3,1%md) to evade naive process-name "
                             "matching; tests process-creation (4688) coverage.",
        "cleanup":           False,
    },
    "T1569.002": {
        "name":              "Service Execution",
        "tactic":            "Execution",
        "severity_expected": "High",
        "art_technique":     "T1569.002",
        "match_ids":         ["T1569.002", "T1569"],
        "art_guid":          "2382dee2-a75f-49aa-9378-f52df6ed3fb1",
        "atomics":           "upstream",
        "description":       "Creates, starts and deletes a service (sc.exe) whose "
                             "binPath runs hidden PowerShell; tests service-install "
                             "(4697/7045) alerting.",
        "cleanup":           True,
    },

    # ── Persistence ───────────────────────────────────────────────────────────
    "T1547.001": {
        "name":              "Registry Run Keys / Startup Folder",
        "tactic":            "Persistence",
        "severity_expected": "High",
        "art_technique":     "T1547.001",
        "match_ids":         ["T1547.001", "T1547"],
        "art_guid":          "e55be3fd-3521-4610-9d1a-e210e42dcf05",
        "atomics":           "upstream",
        "description":       "Adds a value under HKCU\\...\\CurrentVersion\\Run with "
                             "reg.exe; tests registry-modification detection "
                             "(Sysmon 13).",
        "cleanup":           True,
    },
    "T1053.005": {
        "name":              "Scheduled Task/Job",
        "tactic":            "Persistence",
        "severity_expected": "High",
        "art_technique":     "T1053.005",
        "match_ids":         ["T1053.005", "T1053"],
        "art_guid":          "fec27f65-db86-4c2d-b66c-61945aee87c2",
        "atomics":           "upstream",
        "description":       "Creates on-logon and on-startup (SYSTEM) scheduled tasks "
                             "with schtasks.exe; tests task-creation (4698) alerting.",
        "cleanup":           True,
    },
    "T1136.001": {
        "name":              "Create Local Account",
        "tactic":            "Persistence",
        "severity_expected": "High",
        "art_technique":     "T1136.001",
        "match_ids":         ["T1136.001", "T1136"],
        "art_guid":          "6657864e-0323-4206-9344-ac9cd7265a4f",
        "atomics":           "upstream",
        "description":       "Creates a local user with 'net user /add'; high-signal "
                             "account-management (4720) test.",
        "cleanup":           True,
    },

    # ── Credential Access ─────────────────────────────────────────────────────
    "T1003.001": {
        "name":              "LSASS Memory",
        "tactic":            "Credential Access",
        "severity_expected": "High",
        "art_technique":     "T1003.001",
        "match_ids":         ["T1003.001", "T1003"],
        "art_guid":          "2536dee2-12fb-459a-8c37-971844fa73be",
        "atomics":           "upstream",
        "description":       "Dumps LSASS with the built-in comsvcs.dll MiniDump export "
                             "(rundll32); no third-party tooling.  Defender AV is "
                             "expected to block it — the block itself is telemetry.",
        "cleanup":           True,
    },
    "T1110.001": {
        "name":              "Brute Force: Password Guessing",
        "tactic":            "Credential Access",
        "severity_expected": "Medium",
        "art_technique":     "T1110.001",
        "match_ids":         ["T1110.001", "T1110"],
        "art_guid":          "2a0a08a4-1f45-4089-984d-656e7764f699",
        "atomics":           "custom",
        "description":       "Custom atomic: creates a local account, then makes 20 "
                             "wrong-password SMB logons to it over loopback.  Upstream "
                             "ART's Windows tests for this technique all need Active "
                             "Directory.  Tests failed-logon (4625) correlation.",
        "cleanup":           True,
    },
    "T1552.001": {
        "name":              "Credentials in Files",
        "tactic":            "Credential Access",
        "severity_expected": "Medium",
        "art_technique":     "T1552.001",
        "match_ids":         ["T1552.001", "T1552"],
        "art_guid":          "0e56bf29-ff49-4ea5-9af4-3b81283fd513",
        "atomics":           "upstream",
        "description":       "Searches the file system for 'pass'/'password' strings "
                             "with findstr and Select-String; tests file-search "
                             "behaviour detection.",
        "cleanup":           False,
    },
    "T1555.003": {
        "name":              "Credentials from Web Browsers",
        "tactic":            "Credential Access",
        "severity_expected": "High",
        "art_technique":     "T1555.003",
        "match_ids":         ["T1555.003", "T1555"],
        "art_guid":          "a6a5ec26-a2d1-4109-9d35-58b867689329",
        "atomics":           "upstream",
        "description":       "Copies the Edge profile directory (incl. Login Data) to a "
                             "staging folder; no decryption.  Requires Edge with an "
                             "existing profile on the lab VM.",
        "cleanup":           True,
    },
    "T1040": {
        "name":              "Network Sniffing",
        "tactic":            "Credential Access",
        "severity_expected": "Medium",
        "art_technique":     "T1040",
        "match_ids":         ["T1040"],
        "art_guid":          "c67ba807-f48b-446e-b955-e4928cd1bf91",
        "atomics":           "upstream",
        "description":       "Runs a 5-second packet capture with the built-in "
                             "pktmon.exe; tests whether native capture tooling is "
                             "detected.",
        "cleanup":           True,
    },

    # ── Stealth / Defense Impairment (v19 split of Defense Evasion) ──────────
    "T1685.005": {
        "name":              "Clear Windows Event Logs",
        "tactic":            "Defense Impairment",
        "severity_expected": "High",
        "art_technique":     "T1685.005",
        "match_ids":         ["T1685.005", "T1685", "T1070.001", "T1070"],  # T1070.001 pre-v19
        "art_guid":          "e6abb60e-26b8-41da-8aae-0c35174b0967",
        "input_args":        {"log_name": "Security"},
        "atomics":           "upstream",
        "description":       "Clears the Security log with wevtutil (event 1102).  "
                             "Critical meta-test: run last, because it destroys the "
                             "host-side evidence of everything before it.",
        "cleanup":           False,   # log clearing is its own cleanup
    },
    "T1685": {
        "name":              "Disable or Modify Tools",
        "tactic":            "Defense Impairment",
        "severity_expected": "High",
        "art_technique":     "T1685",
        "match_ids":         ["T1685", "T1562.001", "T1562"],  # T1562.001 pre-v19
        "art_guid":          "aa875ed4-8935-47e2-b2c5-6ec00ab220d2",
        "atomics":           "upstream",
        "description":       "Attempts to stop and disable the WinDefend service with "
                             "sc.exe.  Tamper Protection is expected to refuse; the "
                             "attempt is what should be detected.",
        "cleanup":           True,
    },
    "T1027": {
        "name":              "Obfuscated Files or Information",
        "tactic":            "Stealth",
        "severity_expected": "Medium",
        "art_technique":     "T1027",
        "match_ids":         ["T1027"],
        "art_guid":          "a50d5a97-2531-499e-a1de-5544c74432c6",
        "atomics":           "upstream",
        "description":       "Runs a benign command through powershell.exe "
                             "-EncodedCommand; tests encoded-command detection.",
        "cleanup":           False,
    },
    "T1112": {
        "name":              "Modify Registry",
        "tactic":            "Defense Impairment",
        "severity_expected": "Medium",
        "art_technique":     "T1112",
        "match_ids":         ["T1112"],
        "art_guid":          "1324796b-d0f6-455a-b4ae-21ffee6aa6b9",
        "atomics":           "upstream",
        "description":       "Sets HideFileExt=1 under HKCU Explorer\\Advanced with "
                             "reg.exe (a setting malware flips to disguise payloads).",
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
    "T1685",      # Disable AV (T1562.001 before ATT&CK v19)
    "T1003.001",  # LSASS (high-impact — run near end)
    "T1685.005",  # Clear logs (always last; T1070.001 before ATT&CK v19)
]


# ── runner ─────────────────────────────────────────────────────────────────────

REPO_ROOT = Path(__file__).resolve().parent.parent
CUSTOM_ATOMICS_DIR = REPO_ROOT / "atomics"

# Paths on the lab VM; override via env vars if ART is installed elsewhere.
DEFAULT_ART_ATOMICS_DIR = r"C:\AtomicRedTeam\atomics"
DEFAULT_ART_MODULE = r"C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1"

# Invoke-AtomicTest prints this line only when it actually starts a test.
# If a test is skipped (wrong platform, bad GUID) the process still exits 0,
# so the exit code alone cannot be trusted.
_EXECUTED_MARKER = "Executing test:"
_PREREQS_NOT_MET_MARKER = "Prerequisites not met"


class SimulationRunner:
    """
    Wraps Invoke-AtomicTest PowerShell calls.

    Prerequisites
    -------------
    On the lab VM, with PowerShell (5.1+ or PowerShell 7):
        IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
        Install-AtomicRedTeam -getAtomics
    """

    def __init__(self, dry_run: bool = False):
        """
        Parameters
        ----------
        dry_run : If True, print the PowerShell command without executing it.
                  Useful for testing the pipeline without a live ART install.
        """
        self.dry_run = dry_run
        self.atomics_dir = os.environ.get("ART_ATOMICS_DIR", DEFAULT_ART_ATOMICS_DIR)
        self.module_path = os.environ.get("ART_MODULE_PATH", DEFAULT_ART_MODULE)
        if not dry_run:
            _assert_windows()

    def run_technique(self, technique_id: str) -> dict:
        """
        Execute the pinned ART test for a technique and return a result dict:
          - technique_id, technique_name, tactic, severity_expected, art_guid
          - timestamp_exec      UTC ISO string, taken immediately before the
                                execution step (after prerequisites)
          - timestamp_exec_end  UTC ISO string, taken after execution returns
          - success             True only if the process exited cleanly AND
                                ART reported that it executed the test
          - stdout / stderr     truncated to 2000 chars each
          - error               None or a reason string
        """
        if technique_id not in TECHNIQUES:
            raise ValueError(
                f"Unknown technique '{technique_id}'. "
                f"Valid IDs: {list(TECHNIQUES.keys())}"
            )

        meta = TECHNIQUES[technique_id]
        base = {
            "technique_id":      technique_id,
            "technique_name":    meta["name"],
            "tactic":            meta["tactic"],
            "severity_expected": meta["severity_expected"],
            "art_guid":          meta["art_guid"],
        }

        print(f"  [sim] Running {technique_id} ({meta['name']}) ...")

        if self.dry_run:
            print(f"  [sim] DRY RUN — would execute ART test {meta['art_guid']}")
            now = _now()
            return {
                **base,
                "timestamp_exec":     now,
                "timestamp_exec_end": now,
                "success":            True,
                "stdout":             "[dry-run]",
                "stderr":             "",
                "error":              None,
            }

        # Step 1: install prerequisites, then confirm they are met.  Done before
        # the timestamp is taken so download time never counts as latency.
        _run_powershell(self._command(meta, "-GetPrereqs"), timeout=600)
        check = _run_powershell(self._command(meta, "-CheckPrereqs"))
        if _PREREQS_NOT_MET_MARKER in check["stdout"]:
            return {
                **base,
                "timestamp_exec":     _now(),
                "timestamp_exec_end": _now(),
                **check,
                "success":            False,
                "error":              "ART prerequisites not met",
            }

        # Step 2: execute the actual simulation — this is what generates telemetry
        timestamp_exec = _now()
        result = _run_powershell(self._command(meta))
        timestamp_exec_end = _now()

        if result["success"] and _EXECUTED_MARKER not in result["stdout"]:
            result = {
                **result,
                "success": False,
                "error":   "Invoke-AtomicTest exited 0 but did not execute the "
                           "test (wrong platform or unknown GUID?)",
            }

        if result["success"] and meta.get("cleanup"):
            _run_powershell(self._command(meta, "-Cleanup"))

        return {
            **base,
            "timestamp_exec":     timestamp_exec,
            "timestamp_exec_end": timestamp_exec_end,
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

    def _command(self, meta: dict, flag: str = "") -> list[str]:
        atomics_dir = (
            str(CUSTOM_ATOMICS_DIR) if meta["atomics"] == "custom" else self.atomics_dir
        )
        return _build_art_command(
            art_technique=meta["art_technique"],
            art_guid=meta["art_guid"],
            atomics_dir=atomics_dir,
            module_path=self.module_path,
            input_args=meta.get("input_args"),
            flag=flag,
        )


# ── PowerShell helpers ─────────────────────────────────────────────────────────

def _ps_quote(value: str) -> str:
    """Single-quote a value for PowerShell (single quotes are doubled)."""
    return "'" + str(value).replace("'", "''") + "'"


def _build_art_command(
    art_technique: str,
    art_guid: str,
    atomics_dir: str,
    module_path: str,
    input_args: Optional[dict] = None,
    flag: str = "",
) -> list[str]:
    """Build the PowerShell command list for subprocess."""
    if flag not in ("", "-GetPrereqs", "-CheckPrereqs", "-Cleanup"):
        raise ValueError(f"Unsupported Invoke-AtomicTest flag: {flag}")

    import_module = (
        f"if (Test-Path {_ps_quote(module_path)}) "
        f"{{ Import-Module {_ps_quote(module_path)} -Force }} "
        f"else {{ Import-Module invoke-atomicredteam -Force }}"
    )
    invoke = (
        f"Invoke-AtomicTest {art_technique} "
        f"-TestGuids {art_guid} "
        f"-PathToAtomicsFolder {_ps_quote(atomics_dir)}"
    )
    if input_args:
        pairs = "; ".join(f"{k} = {_ps_quote(v)}" for k, v in input_args.items())
        invoke += f" -InputArgs @{{ {pairs} }}"
    if flag:
        invoke += f" {flag}"

    return [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy", "Bypass",
        "-Command", f"{import_module}; {invoke}",
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
            "error":   None if proc.returncode == 0 else f"exit code {proc.returncode}",
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

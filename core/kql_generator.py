"""
core/kql_generator.py
---------------------
Generates KQL detection rules for missed detections.

Design principle
----------------
Rules are seeded with real event data from the simulation run — process names,
EventIDs, command-line fragments observed in the lab — rather than generic
templates.  This produces rules that are immediately relevant to the specific
environment under test rather than copy-paste generic signatures.

Every generated rule includes:
  - Inline comments explaining the detection logic
  - A confidence level tag (high / medium / requires_tuning)
  - A false-positive risk note
  - The ATT&CK technique ID and tactic as metadata comments

Confidence levels
-----------------
  high            — Seeded directly from observed EventIDs and process names;
                    specific enough to have low false-positive risk in most
                    enterprise environments.

  medium          — Uses technique-class heuristics; correct in principle but
                    may need threshold tuning for the target environment.

  requires_tuning — Template generated; requires analyst review and environment-
                    specific adjustments before production deployment.
"""

import json
from typing import Optional


# ── public interface ──────────────────────────────────────────────────────────

class KQLGenerator:
    """
    Generates KQL detection rules for missed detections.

    Usage
    -----
        gen = KQLGenerator()
        suggestion = gen.generate(
            technique_id="T1003.001",
            raw_logs=[{"EventID": 10, "Process": "lsass.exe", ...}],
        )
    """

    def generate(
        self,
        technique_id: str,
        raw_logs: list[dict],
    ) -> dict:
        """
        Generate a KQL suggestion for a missed detection.

        Parameters
        ----------
        technique_id : ATT&CK technique ID
        raw_logs     : Event log rows fetched from Sentinel during the
                       simulation window (may be empty)

        Returns
        -------
        dict with keys:
          kql_query          str
          confidence         str
          data_source        str
          false_positive_note str
        """
        generator_fn = _GENERATORS.get(technique_id, _generic_generator)
        return generator_fn(technique_id, raw_logs)


# ── per-technique generators ──────────────────────────────────────────────────

def _gen_T1059_001(technique_id: str, raw_logs: list[dict]) -> dict:
    """PowerShell execution detection."""
    # Try to extract a real process name / command-line fragment from logs
    cmdline_hint = _extract_field(raw_logs, "CommandLine", default="")
    process_hint = _extract_field(raw_logs, "Process", default="powershell.exe")

    confidence = "high" if cmdline_hint else "medium"
    cmdline_filter = (
        f'\n| where CommandLine has_any ("{cmdline_hint[:60]}", "-EncodedCommand", "-enc", "-e ")'
        if cmdline_hint
        else '\n| where CommandLine has_any ("-EncodedCommand", "-enc", "-e ", "IEX", "Invoke-Expression")'
    )

    kql = f"""// T1059.001 — PowerShell Execution
// ATT&CK Tactic: Execution
// Data source: SecurityEvent (Event ID 4688 — Process Creation)
// Confidence: {confidence}
//
// Detects PowerShell invocations with common obfuscation or execution flags.
// Lab evidence: process '{process_hint}' observed during simulation.

SecurityEvent
| where TimeGenerated >= ago(1h)
| where EventID == 4688
| where Process has_any ("powershell.exe", "pwsh.exe"){cmdline_filter}
| project TimeGenerated, Computer, Account, Process, CommandLine,
          ParentProcessName, SubjectUserName
| extend AttackTechnique = "T1059.001"
"""
    return {
        "kql_query":           kql.strip(),
        "confidence":          confidence,
        "data_source":         "SecurityEvent",
        "false_positive_note": "Legitimate PowerShell administration will trigger this rule. "
                               "Consider scoping to non-admin accounts or adding exclusions "
                               "for known management hosts.",
    }


def _gen_T1059_003(technique_id: str, raw_logs: list[dict]) -> dict:
    """Windows Command Shell detection."""
    cmdline_hint = _extract_field(raw_logs, "CommandLine", default="")
    confidence = "medium"

    kql = f"""// T1059.003 — Windows Command Shell
// ATT&CK Tactic: Execution
// Data source: SecurityEvent (Event ID 4688)
// Confidence: {confidence}
//
// Detects cmd.exe spawned by unusual parent processes.

SecurityEvent
| where TimeGenerated >= ago(1h)
| where EventID == 4688
| where Process =~ "cmd.exe"
| where ParentProcessName !has_any (
    "explorer.exe", "services.exe", "svchost.exe",
    "cmd.exe", "conhost.exe"
  )
| project TimeGenerated, Computer, Account, Process,
          CommandLine, ParentProcessName
| extend AttackTechnique = "T1059.003"
"""
    return {
        "kql_query":           kql.strip(),
        "confidence":          confidence,
        "data_source":         "SecurityEvent",
        "false_positive_note": "Many legitimate applications spawn cmd.exe. "
                               "Tune the ParentProcessName exclusion list for your environment.",
    }


def _gen_T1569_002(technique_id: str, raw_logs: list[dict]) -> dict:
    """Service Execution detection."""
    kql = """// T1569.002 — Service Execution
// ATT&CK Tactic: Execution
// Data source: SecurityEvent (Event ID 4697 — Service Installed)
// Confidence: high
//
// Detects new service installations — a reliable high-fidelity signal.

SecurityEvent
| where TimeGenerated >= ago(1h)
| where EventID == 4697
| project TimeGenerated, Computer, Account, ServiceName,
          ServiceFileName, ServiceType, ServiceStartType
| extend AttackTechnique = "T1569.002"
"""
    return {
        "kql_query":           kql.strip(),
        "confidence":          "high",
        "data_source":         "SecurityEvent",
        "false_positive_note": "Software installation and Windows Update may create "
                               "new services. Consider filtering by ServiceFileName paths "
                               "outside of Program Files.",
    }


def _gen_T1547_001(technique_id: str, raw_logs: list[dict]) -> dict:
    """Registry Run Keys persistence detection."""
    kql = """// T1547.001 — Registry Run Keys / Startup Folder
// ATT&CK Tactic: Persistence
// Data source: SecurityEvent (Sysmon Event ID 13 — Registry Value Set)
// Confidence: high
//
// Monitors writes to common Run key locations.
// Requires Sysmon with registry monitoring configured.

Event
| where TimeGenerated >= ago(1h)
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 13
| extend EventData = parse_xml(EventData)
| extend TargetObject = tostring(EventData.DataItem.TargetObject)
| extend Details = tostring(EventData.DataItem.Details)
| where TargetObject has_any (
    "\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run",
    "\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce",
    "\\\\SOFTWARE\\\\WOW6432Node\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run"
  )
| project TimeGenerated, Computer, TargetObject, Details
| extend AttackTechnique = "T1547.001"
"""
    return {
        "kql_query":           kql.strip(),
        "confidence":          "high",
        "data_source":         "Sysmon (Event)",
        "false_positive_note": "Software installers commonly write Run keys. "
                               "Add exclusions for known software paths (e.g., "
                               "'C:\\\\Program Files\\\\*').",
    }


def _gen_T1053_005(technique_id: str, raw_logs: list[dict]) -> dict:
    """Scheduled Task detection."""
    kql = """// T1053.005 — Scheduled Task/Job
// ATT&CK Tactic: Persistence
// Data source: SecurityEvent (Event ID 4698 — Scheduled Task Created)
// Confidence: high
//
// Detects new scheduled task creation with suspicious execution paths.
// EventData is XML in this event; we use extract() to pull the task name.

SecurityEvent
| where TimeGenerated >= ago(1h)
| where EventID == 4698
| extend TaskName = extract(@"<Data Name='TaskName'>([^<]+)<", 1, EventData)
| where EventData has_any (
    "\\Windows\\Temp\\", "\\AppData\\", "%TEMP%",
    "powershell", "cmd.exe", "wscript", "mshta"
  )
| project TimeGenerated, Computer, SubjectUserName, TaskName,
          TaskContent = EventData
| extend AttackTechnique = "T1053.005"
"""
    return {
        "kql_query":           kql.strip(),
        "confidence":          "medium",
        "data_source":         "SecurityEvent",
        "false_positive_note": "Legitimate software schedulers (antivirus, backup tools) "
                               "will trigger this. Refine path exclusions for known vendors.",
    }


def _gen_T1136_001(technique_id: str, raw_logs: list[dict]) -> dict:
    """Create Local Account detection."""
    kql = """// T1136.001 — Create Local Account
// ATT&CK Tactic: Persistence
// Data source: SecurityEvent (Event ID 4720 — User Account Created)
// Confidence: high
//
// High-fidelity: new local account creation is rarely a false positive
// outside of IT provisioning workflows.

SecurityEvent
| where TimeGenerated >= ago(1h)
| where EventID == 4720
| project TimeGenerated, Computer, SubjectUserName, TargetUserName,
          TargetDomainName, SubjectDomainName
| extend AttackTechnique = "T1136.001"
"""
    return {
        "kql_query":           kql.strip(),
        "confidence":          "high",
        "data_source":         "SecurityEvent",
        "false_positive_note": "IT provisioning scripts that create accounts will trigger "
                               "this. Consider filtering by known provisioning service accounts "
                               "in SubjectUserName.",
    }


def _gen_T1003_001(technique_id: str, raw_logs: list[dict]) -> dict:
    """LSASS Memory access detection."""
    kql = """// T1003.001 — LSASS Memory
// ATT&CK Tactic: Credential Access
// Data source: SecurityEvent (Event ID 4656 — Handle requested for LSASS)
//              Sysmon Event ID 10 — Process accessed LSASS
// Confidence: high
//
// LSASS access from non-system processes is a strong indicator of
// credential dumping activity.

SecurityEvent
| where TimeGenerated >= ago(1h)
| where EventID == 4656
| where ObjectName has "lsass"
| where SubjectUserName !has_any ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE")
| project TimeGenerated, Computer, SubjectUserName, ObjectName,
          ProcessName, HandleID
| extend AttackTechnique = "T1003.001"
| union (
    Event
    | where Source == "Microsoft-Windows-Sysmon" and EventID == 10
    | where EventData has "lsass.exe"
    | extend AttackTechnique = "T1003.001"
    | project TimeGenerated, Computer, EventData, AttackTechnique
)
"""
    return {
        "kql_query":           kql.strip(),
        "confidence":          "high",
        "data_source":         "SecurityEvent + Sysmon",
        "false_positive_note": "Security software (AV, EDR agents) legitimately accesses "
                               "LSASS. Add exclusions for known security tool process names.",
    }


def _gen_T1110_001(technique_id: str, raw_logs: list[dict]) -> dict:
    """Brute Force — Password Guessing detection."""
    kql = """// T1110.001 — Brute Force: Password Guessing
// ATT&CK Tactic: Credential Access
// Data source: SecurityEvent (Event ID 4625 — Failed Logon)
// Confidence: medium
//
// Detects rapid sequential failed logon attempts from a single account
// or to a single target within a 5-minute window.

SecurityEvent
| where TimeGenerated >= ago(1h)
| where EventID == 4625
| summarize
    FailureCount = count(),
    Accounts     = make_set(TargetUserName),
    FirstSeen    = min(TimeGenerated),
    LastSeen     = max(TimeGenerated)
    by Computer, IpAddress, bin(TimeGenerated, 5m)
| where FailureCount >= 10
| project FirstSeen, LastSeen, Computer, IpAddress,
          FailureCount, Accounts
| extend AttackTechnique = "T1110.001"
"""
    return {
        "kql_query":           kql.strip(),
        "confidence":          "medium",
        "data_source":         "SecurityEvent",
        "false_positive_note": "Misconfigured applications with cached wrong credentials "
                               "can generate high failure rates. Tune the threshold (>= 10) "
                               "based on your baseline.",
    }


def _gen_T1070_001(technique_id: str, raw_logs: list[dict]) -> dict:
    """Clear Windows Event Logs detection."""
    kql = """// T1070.001 — Clear Windows Event Logs
// ATT&CK Tactic: Defense Evasion
// Data source: SecurityEvent (Event ID 1102 — Security log cleared)
//              System log (Event ID 104 — System log cleared)
// Confidence: high
//
// CRITICAL: Log clearing is almost never a legitimate automated activity.
// This rule should be high-priority with immediate alerting.

SecurityEvent
| where TimeGenerated >= ago(1h)
| where EventID in (1102, 104)
| project TimeGenerated, Computer, SubjectUserName,
          SubjectDomainName, Channel = "Security"
| extend AttackTechnique = "T1070.001", Priority = "CRITICAL"
| union (
    Event
    | where Source == "Microsoft-Windows-Eventlog"
    | where EventID == 104
    | project TimeGenerated, Computer, AttackTechnique = "T1070.001",
              Priority = "CRITICAL"
)
"""
    return {
        "kql_query":           kql.strip(),
        "confidence":          "high",
        "data_source":         "SecurityEvent + System",
        "false_positive_note": "Legitimate log rotation scripts may clear logs on a schedule. "
                               "Exclude known maintenance windows or service accounts if needed, "
                               "but do not suppress entirely — this is a critical signal.",
    }


def _generic_generator(technique_id: str, raw_logs: list[dict]) -> dict:
    """
    Fallback generator for techniques without a specific rule template.
    Produces a process-creation rule seeded with observed process names.
    """
    process_hint = _extract_field(raw_logs, "Process", default="")
    cmdline_hint = _extract_field(raw_logs, "CommandLine", default="")

    process_filter = (
        f'| where Process has "{process_hint}"'
        if process_hint
        else "// TODO: add specific process name filter for this technique"
    )

    kql = f"""// {technique_id} — Generic Process Creation Rule
// ATT&CK Tactic: (see MITRE ATT&CK for {technique_id})
// Data source: SecurityEvent (Event ID 4688)
// Confidence: requires_tuning
//
// Auto-generated fallback rule. Review and customise before deploying.
// Add specific process names, command-line patterns, or parent process
// filters based on observed lab behaviour.

SecurityEvent
| where TimeGenerated >= ago(1h)
| where EventID == 4688
{process_filter}
| project TimeGenerated, Computer, Account, Process,
          CommandLine, ParentProcessName
| extend AttackTechnique = "{technique_id}"
"""
    return {
        "kql_query":           kql.strip(),
        "confidence":          "requires_tuning",
        "data_source":         "SecurityEvent",
        "false_positive_note": "This is a generic template. Refine the process name "
                               "and command-line filters before production deployment.",
    }


# ── technique → generator mapping ────────────────────────────────────────────

_GENERATORS = {
    "T1059.001": _gen_T1059_001,
    "T1059.003": _gen_T1059_003,
    "T1569.002": _gen_T1569_002,
    "T1547.001": _gen_T1547_001,
    "T1053.005": _gen_T1053_005,
    "T1136.001": _gen_T1136_001,
    "T1003.001": _gen_T1003_001,
    "T1110.001": _gen_T1110_001,
    "T1070.001": _gen_T1070_001,
    # Remaining techniques fall through to _generic_generator
    # and will be replaced with specific implementations in v1.1
}


# ── helpers ────────────────────────────────────────────────────────────────────

def _extract_field(
    logs: list[dict],
    field: str,
    default: str = "",
) -> str:
    """Return the first non-empty value for `field` across all log rows."""
    for row in logs:
        val = row.get(field, "")
        if val and str(val).strip():
            return str(val).strip()
    return default

"""
core/kql_generator.py
---------------------
Generates KQL detection rules for missed detections.

Design principle
----------------
Each generated rule is a *behavioral* detection template for the technique —
keyed on the EventID and the structural pattern that identifies the activity
(e.g. "any new service install", "cmd.exe from an unusual parent") — not on
the specific artifacts the lab happened to produce.

This is deliberate. In a controlled Atomic Red Team lab the "real" telemetry
is largely synthetic: ART's own test service/task/account names, benign `echo`
command lines, and processes spawned by the Invoke-AtomicTest harness. Seeding
those literal values into a rule's logic would overfit it to the lab and miss
real tradecraft — the opposite of useful. So the observed telemetry is used to
*ground* a rule (cited in a comment, so an analyst sees what the rule targets)
but never pasted into its detection logic. (core/evidence.py isolates the
technique's own processes from the harness; even so, the technique's top
process is spawned by the harness, so its parent is not a trustworthy
discriminator either.)

Every generated rule includes:
  - A "Lab evidence" comment grounding it in what the run actually observed
  - Inline comments explaining the detection logic
  - A confidence level tag (high / medium / requires_tuning)
  - A false-positive risk note
  - The ATT&CK technique ID and tactic as metadata comments

Confidence levels
-----------------
  high            — Keyed on a high-fidelity structural signal (e.g. a service-
                    install or log-clear EventID) that is rare outside the
                    technique; low false-positive risk in most environments.

  medium          — Uses a technique-class behavioral heuristic; correct in
                    principle but may need threshold or exclusion tuning.

  requires_tuning — Skeleton rule; requires analyst review and environment-
                    specific discriminators before production deployment.
"""



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
        suggestion = generator_fn(technique_id, raw_logs)
        # Ground the rule in what the run observed, as a leading comment — never
        # fed into the detection logic (see module docstring).
        grounding = _evidence_grounding(raw_logs)
        if grounding:
            suggestion["kql_query"] = grounding + suggestion["kql_query"]
        return suggestion


# ── per-technique generators ──────────────────────────────────────────────────

def _gen_T1059_001(technique_id: str, raw_logs: list[dict]) -> dict:
    """PowerShell execution detection."""
    # Behavioral: keyed on obfuscation / download-and-execute flag patterns,
    # not on the specific command the lab ran (that would overfit to ART).
    kql = """// T1059.001 — PowerShell Execution
// ATT&CK Tactic: Execution
// Data source: SecurityEvent (Event ID 4688 — Process Creation)
// Confidence: medium
//
// Detects PowerShell invocations carrying common obfuscation or
// download-and-execute flags.

SecurityEvent
| where TimeGenerated >= ago(1h)
| where EventID == 4688
| where Process has_any ("powershell.exe", "pwsh.exe")
| where CommandLine has_any ("-EncodedCommand", "-enc", "-e ", "IEX",
                             "Invoke-Expression", "DownloadString", "FromBase64String")
| project TimeGenerated, Computer, Account, Process, CommandLine,
          ParentProcessName, SubjectUserName
| extend AttackTechnique = "T1059.001"
"""
    return {
        "kql_query":           kql.strip(),
        "confidence":          "medium",
        "data_source":         "SecurityEvent",
        "false_positive_note": "Legitimate PowerShell administration will trigger this rule. "
                               "Consider scoping to non-admin accounts or adding exclusions "
                               "for known management hosts.",
    }


def _gen_T1059_003(technique_id: str, raw_logs: list[dict]) -> dict:
    """Windows Command Shell detection."""
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


def _gen_T1685_005(technique_id: str, raw_logs: list[dict]) -> dict:
    """Clear Windows Event Logs detection."""
    kql = """// T1685.005 — Clear Windows Event Logs (T1070.001 before ATT&CK v19)
// ATT&CK Tactic: Defense Impairment
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
| extend AttackTechnique = "T1685.005", Priority = "CRITICAL"
| union (
    Event
    | where Source == "Microsoft-Windows-Eventlog"
    | where EventID == 104
    | project TimeGenerated, Computer, AttackTechnique = "T1685.005",
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
    Fallback skeleton for techniques without a specific rule template.
    The observed process is offered as a commented-out starting point (it may
    be an ART artifact), never an active filter, so the rule does not silently
    encode lab-specific noise.
    """
    process_hint = _extract_field(raw_logs, "Process", default="")

    process_suggestion = (
        f'// | where Process has "{process_hint}"   // observed in lab — verify it is not an ART artifact before enabling'
        if process_hint
        else "// TODO: add a specific process-name or command-line discriminator for this technique"
    )

    kql = f"""// {technique_id} — Generic Process Creation Skeleton
// ATT&CK Tactic: (see MITRE ATT&CK for {technique_id})
// Data source: SecurityEvent (Event ID 4688)
// Confidence: requires_tuning
//
// Auto-generated skeleton. No behavioral discriminator is known for this
// technique yet, so as written it matches all process creation — an analyst
// must add a discriminator (verified against real tradecraft, not the lab
// artifact) before deploying.

SecurityEvent
| where TimeGenerated >= ago(1h)
| where EventID == 4688
{process_suggestion}
| project TimeGenerated, Computer, Account, Process,
          CommandLine, ParentProcessName
| extend AttackTechnique = "{technique_id}"
"""
    return {
        "kql_query":           kql.strip(),
        "confidence":          "requires_tuning",
        "data_source":         "SecurityEvent",
        "false_positive_note": "Generic skeleton with no active discriminator. Add a process "
                               "name, command-line pattern, or parent-process filter — verified "
                               "against real tradecraft, not the lab artifact — before deploying.",
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
    "T1685.005": _gen_T1685_005,
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


def _evidence_grounding(raw_logs: list[dict]) -> str:
    """
    A comment block citing what the run actually observed, so a generated rule
    is transparently tied to real telemetry. This grounds the rule for an
    analyst; it is deliberately NOT fed into the detection logic (see the
    module docstring — the lab's artifacts would overfit the rule).

    Returns "" when no evidence was collected, so rules generated without
    telemetry (e.g. a dry run) carry no misleading "evidence" header.
    """
    if not raw_logs:
        return ""
    process = _extract_field(raw_logs, "Process")
    cmdline = _extract_field(raw_logs, "CommandLine")
    event_ids = sorted({
        str(r["EventID"]) for r in raw_logs
        if isinstance(r, dict) and r.get("EventID") not in (None, "")
    })
    lines = []
    if process:
        lines.append(f"//   process observed: {process}")
    if cmdline:
        lines.append(f"//   command line:     {cmdline[:100]}")
    if event_ids:
        lines.append(f"//   event IDs:        {', '.join(event_ids)}")
    if not lines:
        return ""
    return (
        "// Lab evidence (grounding only — NOT seeded into the logic below):\n"
        + "\n".join(lines)
        + "\n//\n"
    )

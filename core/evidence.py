"""
core/evidence.py
----------------
Separates the telemetry a simulated technique produced from everything else
that happened on the lab VM at the same time.

Why this exists
---------------
The first real run (T1059.003, run 9ac64107) showed that the 4688 events in
the simulation window are mostly *not* the technique:

  python.exe        sentinelbench.py ...                 <- SentinelBench
  powershell.exe    ... Invoke-AtomicTest ... (launcher) <- SentinelBench
  HOSTNAME.EXE x3, whoami.exe                            <- ART's own host checks
  cmd.exe           /c %LOCALAPPDATA:~-3,1%md /c echo ...<- THE TECHNIQUE
  conhost.exe                                            <- console plumbing
  cmd.exe           /c echo Hello, from CMD!             <- THE TECHNIQUE
  msedge.exe, WmiPrvSE.exe, wsqmcons.exe                 <- unrelated background

Taking "the first N events in the window" therefore sampled the harness, not
the attack. Attribution here uses process lineage instead: every process that
descends from the PowerShell launcher of the *execution* step (identified by
the pinned ART GUID on its command line) belongs to the test; ART's known
helper processes are then set aside as harness noise.
"""

# Direct children of the launcher that Invoke-AtomicTest itself spawns to
# collect host details, observed in the first real run. They are the
# framework's, not the technique's.
ART_HELPER_PROCESSES = {"hostname.exe", "whoami.exe"}

# Spawned for any console process; carries no technique information.
PLUMBING_PROCESSES = {"conhost.exe"}

# Flags that mark the non-execution Invoke-AtomicTest calls (their launchers
# must not be mistaken for the execution step's).
_NON_EXEC_FLAGS = ("-GetPrereqs", "-CheckPrereqs", "-Cleanup")


def parse_pid(value) -> int | None:
    """SecurityEvent stores PIDs as hex strings ("0x1a2c"); accept ints too."""
    if value is None or value == "":
        return None
    if isinstance(value, int):
        return value
    try:
        text = str(value).strip()
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except ValueError:
        return None


def _image(row: dict) -> str:
    name = row.get("Process") or row.get("NewProcessName") or ""
    return name.replace("/", "\\").rsplit("\\", 1)[-1].lower()


def attribute_processes(process_rows: list[dict], art_guid: str | None) -> dict:
    """
    Split 4688 process-creation rows into launcher / technique / harness /
    unattributed, using parent-child PIDs (NewProcessId, ProcessId).

    Returns a dict:
      attribution   "lineage" when the launcher was found and PIDs were
                    present, otherwise "unavailable" (everything is then
                    reported as unattributed, never guessed)
      launcher      the execution-step launcher row, or None
      technique     processes descending from the launcher, minus ART
                    helpers and console plumbing, in time order
      technique_pids  set of their PIDs (for matching Sysmon events)
      harness       ART helper processes
      unattributed  everything else in the window
    """
    unavailable = {
        "attribution": "unavailable",
        "launcher": None,
        "technique": [],
        "technique_pids": set(),
        "harness": [],
        "unattributed": list(process_rows),
    }
    if not art_guid:
        return unavailable

    launcher = next(
        (
            r for r in process_rows
            if art_guid in (r.get("CommandLine") or "")
            and not any(f in (r.get("CommandLine") or "") for f in _NON_EXEC_FLAGS)
        ),
        None,
    )
    root = parse_pid(launcher.get("NewProcessId")) if launcher else None
    if root is None:
        return unavailable

    # Walk the process tree in time order: a row belongs to the test if its
    # parent PID is the launcher or an already-attributed descendant.
    # Time order matters because Windows reuses PIDs.
    rows = sorted(process_rows, key=lambda r: str(r.get("TimeGenerated", "")))
    launcher_time = str(launcher.get("TimeGenerated", ""))
    tree = {root}
    technique, harness, unattributed = [], [], []
    for row in rows:
        if row is launcher:
            continue
        pid, ppid = parse_pid(row.get("NewProcessId")), parse_pid(row.get("ProcessId"))
        in_tree = (
            ppid in tree
            and pid is not None
            and str(row.get("TimeGenerated", "")) >= launcher_time
        )
        if not in_tree:
            unattributed.append(row)
            continue
        tree.add(pid)
        image = _image(row)
        if ppid == root and image in ART_HELPER_PROCESSES:
            harness.append(row)
        elif image in PLUMBING_PROCESSES:
            continue
        else:
            technique.append(row)

    return {
        "attribution": "lineage",
        "launcher": launcher,
        "technique": technique,
        "technique_pids": {parse_pid(r.get("NewProcessId")) for r in technique} - {None},
        "harness": harness,
        "unattributed": unattributed,
    }


def evidence_summary(evidence: dict, max_events: int = 20) -> dict:
    """
    JSON-serialisable summary for the results table: the technique's own
    events in full (capped), counts for the rest.
    """
    launcher = evidence.get("launcher") or {}
    return {
        "attribution": evidence.get("attribution", "unavailable"),
        "launcher_command_line": launcher.get("CommandLine"),
        "technique": evidence.get("technique", [])[:max_events],
        "technique_events": evidence.get("technique_events", [])[:max_events],
        "harness_count": len(evidence.get("harness", [])),
        "unattributed_count": len(evidence.get("unattributed", [])),
    }

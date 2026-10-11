"""
Tests for core/evidence.py — process-lineage attribution.

The scenario these lock down is the real one from the module docstring: in the
first live run the 4688 events in the simulation window were mostly *not* the
technique (SentinelBench's own python/powershell, ART's host-detail helpers,
console plumbing, and unrelated Edge/WMI background). Seeding KQL from "the
first N events" therefore sampled the harness. Attribution by process lineage
is what isolates the attack, so these tests guard that it keeps doing so.
"""

from core.evidence import attribute_processes, evidence_summary, parse_pid

GUID = "2a0a08a4-1f45-4089-984d-656e7764f699"


def _row(t, image, pid, ppid, cmd=""):
    # Hex PIDs, as SecurityEvent 4688 actually stores them.
    return {
        "TimeGenerated": f"2026-10-03T10:00:{t:02d}Z",
        "EventID": 4688,
        "NewProcessName": image,
        "NewProcessId": hex(pid),
        "ProcessId": hex(ppid),
        "CommandLine": cmd,
    }


def _real_run_window():
    """The docstring's window: harness + technique + background, interleaved."""
    launcher = 0x100
    return [
        # SentinelBench itself — parented outside the launcher tree.
        _row(1, r"C:\Python\python.exe", 0x90, 0x50, "sentinelbench.py run"),
        # The execution-step launcher: Invoke-AtomicTest carrying the pinned GUID.
        _row(2, r"C:\Windows\powershell.exe", launcher, 0x90,
             f"powershell Invoke-AtomicTest T1059.003 -TestGuids {GUID}"),
        # ART's own host-detail probes: direct children of the launcher.
        _row(3, r"C:\Windows\System32\HOSTNAME.EXE", 0x101, launcher),
        _row(3, r"C:\Windows\System32\whoami.exe", 0x102, launcher),
        # THE TECHNIQUE: cmd.exe spawned by the launcher, and its child cmd.
        _row(4, r"C:\Windows\System32\cmd.exe", 0x103, launcher, "cmd /c echo Hello"),
        _row(5, r"C:\Windows\System32\cmd.exe", 0x105, 0x103, "cmd /c echo nested"),
        # Console plumbing hung off the technique process.
        _row(4, r"C:\Windows\System32\conhost.exe", 0x104, 0x103),
        # Unrelated background, parented outside the tree.
        _row(6, r"C:\Program Files\msedge.exe", 0xA0, 0x01),
        _row(6, r"C:\Windows\System32\wbem\WmiPrvSE.exe", 0xA1, 0x02),
    ]


def test_lineage_isolates_the_technique_from_harness_and_background():
    ev = attribute_processes(_real_run_window(), GUID)

    assert ev["attribution"] == "lineage"
    assert GUID in ev["launcher"]["CommandLine"]

    # Only the two cmd.exe processes are the technique.
    tech_pids = {parse_pid(r["NewProcessId"]) for r in ev["technique"]}
    assert tech_pids == {0x103, 0x105}
    assert ev["technique_pids"] == {0x103, 0x105}

    # ART's host probes are set aside as harness, not credited to the attack.
    assert {parse_pid(r["NewProcessId"]) for r in ev["harness"]} == {0x101, 0x102}

    # conhost is dropped entirely (neither technique nor unattributed).
    all_kept = ev["technique"] + ev["harness"] + ev["unattributed"]
    assert 0x104 not in {parse_pid(r["NewProcessId"]) for r in all_kept}

    # SentinelBench's python and the Edge/WMI background are unattributed.
    assert {parse_pid(r["NewProcessId"]) for r in ev["unattributed"]} == {0x90, 0xA0, 0xA1}


def test_no_guid_attributes_nothing_rather_than_guessing():
    rows = _real_run_window()
    ev = attribute_processes(rows, None)
    assert ev["attribution"] == "unavailable"
    assert ev["launcher"] is None
    assert ev["technique"] == [] and ev["technique_pids"] == set()
    assert ev["unattributed"] == rows  # everything, untouched


def test_prereq_and_cleanup_launchers_are_not_mistaken_for_execution():
    # GetPrereqs / Cleanup invocations carry the same GUID but must not be
    # chosen as the execution launcher, or their children get mis-attributed.
    rows = [
        _row(1, r"C:\Windows\powershell.exe", 0x200, 0x50,
             f"Invoke-AtomicTest T1059.003 -TestGuids {GUID} -GetPrereqs"),
        _row(2, r"C:\Windows\powershell.exe", 0x100, 0x50,
             f"Invoke-AtomicTest T1059.003 -TestGuids {GUID}"),
        _row(3, r"C:\Windows\System32\cmd.exe", 0x101, 0x100, "cmd /c echo real"),
        # A child of the prereq launcher must NOT be attributed to the test.
        _row(1, r"C:\Windows\System32\cmd.exe", 0x201, 0x200, "cmd /c prereq"),
    ]
    ev = attribute_processes(rows, GUID)
    assert parse_pid(ev["launcher"]["NewProcessId"]) == 0x100
    assert ev["technique_pids"] == {0x101}


def test_pid_reuse_before_the_launcher_is_not_attributed():
    # Windows reuses PIDs. A process whose PPID equals the launcher PID but
    # which ran *before* the launcher existed is a different, earlier process
    # and must stay unattributed. Time order is what disambiguates.
    launcher = 0x100
    rows = [
        _row(1, r"C:\Windows\System32\cmd.exe", 0x300, launcher, "earlier reuse"),
        _row(2, r"C:\Windows\powershell.exe", launcher, 0x50,
             f"Invoke-AtomicTest T1059.003 -TestGuids {GUID}"),
        _row(3, r"C:\Windows\System32\cmd.exe", 0x103, launcher, "real technique"),
    ]
    ev = attribute_processes(rows, GUID)
    assert ev["technique_pids"] == {0x103}
    assert 0x300 in {parse_pid(r["NewProcessId"]) for r in ev["unattributed"]}


def test_missing_launcher_pid_degrades_to_unavailable():
    # Launcher matched by GUID but its NewProcessId is blank -> no tree root,
    # so nothing can be attributed; report unavailable instead of inventing.
    rows = [{
        "TimeGenerated": "2026-10-03T10:00:02Z",
        "NewProcessName": r"C:\Windows\powershell.exe",
        "NewProcessId": "",
        "ProcessId": "0x50",
        "CommandLine": f"Invoke-AtomicTest T1059.003 -TestGuids {GUID}",
    }]
    ev = attribute_processes(rows, GUID)
    assert ev["attribution"] == "unavailable"


def test_parse_pid_handles_hex_decimal_and_junk():
    assert parse_pid("0x1a2c") == 0x1A2C
    assert parse_pid("0X10") == 16
    assert parse_pid("4688") == 4688
    assert parse_pid(4688) == 4688
    assert parse_pid("") is None
    assert parse_pid(None) is None
    assert parse_pid("not-a-pid") is None


def test_evidence_summary_caps_events_and_counts_the_rest():
    ev = attribute_processes(_real_run_window(), GUID)
    ev["technique_events"] = [{"EventID": 4697}]
    summary = evidence_summary(ev, max_events=1)
    assert summary["attribution"] == "lineage"
    assert GUID in summary["launcher_command_line"]
    assert len(summary["technique"]) == 1       # capped
    assert summary["technique_events"] == [{"EventID": 4697}]
    assert summary["harness_count"] == 2
    assert summary["unattributed_count"] == 3

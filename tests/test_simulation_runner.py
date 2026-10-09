import re
from pathlib import Path

import pytest
import yaml

from core import simulation_runner as sr
from core.simulation_runner import TECHNIQUES, V1_SUITE_ORDER, _build_art_command

GUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
ATTACK_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


# ── registry integrity ─────────────────────────────────────────────────────────

def test_suite_order_covers_every_technique_exactly_once():
    assert sorted(V1_SUITE_ORDER) == sorted(TECHNIQUES)
    assert len(V1_SUITE_ORDER) == len(set(V1_SUITE_ORDER)) == 15


def test_log_clearing_runs_last():
    # It destroys host-side evidence of everything that ran before it.
    assert V1_SUITE_ORDER[-1] == "T1685.005"


def test_defence_tampering_runs_after_every_other_technique():
    # If stopping Defender ever succeeded, later techniques would be measured
    # on a host without AV. Only log clearing may follow it.
    assert V1_SUITE_ORDER[-2:] == ["T1685", "T1685.005"]


@pytest.mark.parametrize("tid", list(TECHNIQUES))
def test_registry_entry_is_well_formed(tid):
    meta = TECHNIQUES[tid]
    assert GUID_RE.match(meta["art_guid"]), "tests must be pinned by GUID"
    assert ATTACK_RE.match(meta["art_technique"])
    assert meta["match_ids"], "alert matching needs at least one ID"
    assert all(ATTACK_RE.match(m) for m in meta["match_ids"])
    assert tid in meta["match_ids"]
    assert meta["atomics"] in ("upstream", "custom")
    assert meta["severity_expected"] in ("Informational", "Low", "Medium", "High")


def test_art_guids_are_unique():
    guids = [m["art_guid"] for m in TECHNIQUES.values()]
    assert len(guids) == len(set(guids))


@pytest.mark.parametrize(
    "tid", [t for t, m in TECHNIQUES.items() if m["atomics"] == "custom"]
)
def test_custom_atomics_exist_and_match_registry(tid):
    meta = TECHNIQUES[tid]
    path = sr.CUSTOM_ATOMICS_DIR / meta["art_technique"] / f"{meta['art_technique']}.yaml"
    assert path.exists(), f"missing custom atomic {path}"
    doc = yaml.safe_load(path.read_text())
    assert doc["attack_technique"] == meta["art_technique"]
    test = next(t for t in doc["atomic_tests"] if t["auto_generated_guid"] == meta["art_guid"])
    assert "windows" in test["supported_platforms"]


# ── command construction ───────────────────────────────────────────────────────

def _script(cmd):
    assert cmd[:2] == ["powershell.exe", "-NoProfile"]
    return cmd[-1]


def test_command_selects_test_by_guid_and_folder():
    script = _script(_build_art_command(
        "T1685.005", "e6abb60e-26b8-41da-8aae-0c35174b0967",
        atomics_dir=r"C:\AtomicRedTeam\atomics", module_path=r"C:\m.psd1",
    ))
    assert "Invoke-AtomicTest T1685.005 -TestGuids e6abb60e-26b8-41da-8aae-0c35174b0967" in script
    assert r"-PathToAtomicsFolder 'C:\AtomicRedTeam\atomics'" in script
    assert "-TestNumbers" not in script


def test_input_args_are_single_quoted_and_escaped():
    script = _script(_build_art_command(
        "T1", "g", "a", "m", input_args={"log_name": "Security", "evil": "x'; rm -r C:\\"},
    ))
    assert "-InputArgs @{ log_name = 'Security'; evil = 'x''; rm -r C:\\' }" in script


def test_unknown_flag_is_rejected():
    with pytest.raises(ValueError):
        _build_art_command("T1", "g", "a", "m", flag="-Force; Remove-Item")


def test_custom_atomics_use_repo_folder():
    runner = sr.SimulationRunner(dry_run=True)
    script = _script(runner._command(TECHNIQUES["T1110.001"]))
    assert str(Path(sr.CUSTOM_ATOMICS_DIR)) in script


# ── execution verification ─────────────────────────────────────────────────────

class FakePowerShell:
    """Records commands and replies based on which Invoke-AtomicTest flag was used."""

    def __init__(self, execute_stdout="Executing test: T1112-1 ...\nDone executing test",
                 prereq_stdout="Prerequisites met: x", execute_ok=True):
        self.calls = []
        self.execute_stdout = execute_stdout
        self.prereq_stdout = prereq_stdout
        self.execute_ok = execute_ok

    def __call__(self, cmd, timeout=120):
        script = cmd[-1]
        self.calls.append(script)
        if "-CheckPrereqs" in script:
            return {"success": True, "stdout": self.prereq_stdout, "stderr": "", "error": None}
        if "-GetPrereqs" in script or "-Cleanup" in script:
            return {"success": True, "stdout": "", "stderr": "", "error": None}
        return {"success": self.execute_ok, "stdout": self.execute_stdout, "stderr": "",
                "error": None if self.execute_ok else "exit code 1"}


@pytest.fixture
def live_runner(monkeypatch):
    monkeypatch.setattr(sr, "_assert_windows", lambda: None)
    return sr.SimulationRunner(dry_run=False)


def test_successful_run_executes_then_cleans_up(monkeypatch, live_runner):
    fake = FakePowerShell()
    monkeypatch.setattr(sr, "_run_powershell", fake)
    result = live_runner.run_technique("T1112")
    assert result["success"] is True
    assert ["-GetPrereqs" in c for c in fake.calls] == [True, False, False, False]
    assert "-CheckPrereqs" in fake.calls[1]
    assert "-Cleanup" in fake.calls[3]


def test_exit_zero_without_execution_marker_is_a_failure(monkeypatch, live_runner):
    # Invoke-AtomicTest exits 0 when it skips a test (e.g. wrong platform).
    fake = FakePowerShell(execute_stdout="PathToAtomicsFolder = C:\\AtomicRedTeam\\atomics\n")
    monkeypatch.setattr(sr, "_run_powershell", fake)
    result = live_runner.run_technique("T1112")
    assert result["success"] is False
    assert "did not execute" in result["error"]
    assert not any("-Cleanup" in c for c in fake.calls)


def test_unmet_prerequisites_stop_before_execution(monkeypatch, live_runner):
    fake = FakePowerShell(prereq_stdout="Prerequisites not met: Edge must be installed")
    monkeypatch.setattr(sr, "_run_powershell", fake)
    result = live_runner.run_technique("T1555.003")
    assert result["success"] is False
    assert result["error"] == "ART prerequisites not met"
    assert len(fake.calls) == 2  # GetPrereqs + CheckPrereqs, never the test itself


def test_exec_timestamp_is_taken_after_prerequisites(monkeypatch, live_runner):
    events = []
    fake = FakePowerShell()

    def recording_ps(cmd, timeout=120):
        events.append("ps:" + ("prereq" if "Prereqs" in cmd[-1] else
                               "cleanup" if "-Cleanup" in cmd[-1] else "exec"))
        return fake(cmd, timeout)

    def recording_now():
        events.append("now")
        return f"t{events.count('now')}"

    monkeypatch.setattr(sr, "_run_powershell", recording_ps)
    monkeypatch.setattr(sr, "_now", recording_now)
    result = live_runner.run_technique("T1112")
    assert events[:5] == ["ps:prereq", "ps:prereq", "now", "ps:exec", "now"]
    assert result["timestamp_exec"] == "t1"
    assert result["timestamp_exec_end"] == "t2"


# ── _run_powershell robustness (the 13-hour-hang regression) ────────────────────

def test_run_powershell_times_out_promptly_and_kills_the_tree(tmp_path):
    # A real child that would otherwise run far longer than the timeout. The
    # call must return at ~timeout, not hang (the brute-force regression).
    import time
    start = time.monotonic()
    result = sr._run_powershell(
        ["python3", "-c", "import time; time.sleep(60)"], timeout=2
    )
    elapsed = time.monotonic() - start
    assert result["success"] is False
    assert "Timed out" in result["error"]
    assert elapsed < 20, f"timeout did not return promptly ({elapsed:.1f}s)"


def test_run_powershell_closes_stdin_so_prompts_do_not_block():
    # A child that reads stdin must get EOF immediately, not block forever.
    result = sr._run_powershell(
        ["python3", "-c", "import sys; sys.stdin.read(); print('done')"], timeout=5
    )
    assert "Timed out" not in (result["error"] or "")


def test_run_powershell_reports_exit_code():
    ok = sr._run_powershell(["python3", "-c", "print('hi')"], timeout=10)
    assert ok["success"] is True and "hi" in ok["stdout"]
    bad = sr._run_powershell(["python3", "-c", "import sys; sys.exit(3)"], timeout=10)
    assert bad["success"] is False and bad["error"] == "exit code 3"


def test_brute_force_atomic_targets_a_real_account_without_net_use():
    # The net use loop hung the first suite run, so no net use. The target
    # account must be created (and cleaned up) so valid-account brute-force
    # rules apply.
    import yaml
    doc = yaml.safe_load(
        (sr.CUSTOM_ATOMICS_DIR / "T1110.001" / "T1110.001.yaml").read_text()
    )
    test = doc["atomic_tests"][0]
    assert test["auto_generated_guid"] == TECHNIQUES["T1110.001"]["art_guid"]
    command = test["executor"]["command"]
    assert "net use \\\\" not in command   # no SMB loop (the hang)
    assert "127.0.0.1" not in command
    assert "LogonUser" in command
    assert "net user" in command and "/add" in command        # creates the account
    assert "/delete" in test["executor"]["cleanup_command"]    # and removes it
    assert TECHNIQUES["T1110.001"]["cleanup"] is True

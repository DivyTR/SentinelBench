import pytest

from core import TECHNIQUES, KQLGenerator


@pytest.mark.parametrize("tid", list(TECHNIQUES))
@pytest.mark.parametrize("raw_logs", [[], [{"Process": "C:\\x.exe", "CommandLine": "x -y"}]])
def test_every_technique_produces_a_storable_suggestion(tid, raw_logs):
    s = KQLGenerator().generate(tid, raw_logs)
    # Must satisfy the kql_suggestions CHECK constraint.
    assert s["confidence"] in ("high", "medium", "requires_tuning")
    assert s["kql_query"].strip()
    assert s["data_source"]
    assert tid in s["kql_query"]


def _active_lines(kql: str) -> list[str]:
    """KQL lines that are real query logic, not comments."""
    return [ln for ln in kql.splitlines() if not ln.strip().startswith("//")]


def test_grounding_comment_present_with_evidence_absent_without():
    gen = KQLGenerator()
    with_ev = gen.generate("T1059.003", [{"EventID": 4688, "Process": "cmd.exe"}])["kql_query"]
    without = gen.generate("T1059.003", [])["kql_query"]
    assert "Lab evidence" in with_ev
    assert "Lab evidence" not in without


@pytest.mark.parametrize("tid", ["T1059.001", "T1552.001"])  # dedicated + generic-fallback
def test_lab_artifacts_are_grounded_not_seeded_into_logic(tid):
    # The whole point of option A: an observed ART artifact may be cited in a
    # comment, but must never land in an active detection filter, or the rule
    # overfits to the lab instead of catching the technique.
    raw = [{"EventID": 4688, "Process": r"C:\ART_ARTIFACT.exe",
            "CommandLine": "SECRET_LAB_TOKEN_123 -z"}]
    kql = KQLGenerator().generate(tid, raw)["kql_query"]
    assert "SECRET_LAB_TOKEN_123" in kql            # grounded (cited in a comment)
    for line in _active_lines(kql):                 # but never in active logic
        assert "SECRET_LAB_TOKEN_123" not in line
        assert "ART_ARTIFACT" not in line


def test_powershell_rule_is_behavioral_not_command_seeded():
    # Regression: T1059.001 used to paste the first 60 chars of the observed
    # command line into its CommandLine filter.
    raw = [{"EventID": 4688, "Process": "powershell.exe",
            "CommandLine": "powershell -nop -w hidden LEAKED_COMMAND"}]
    kql = KQLGenerator().generate("T1059.001", raw)["kql_query"]
    assert all("LEAKED_COMMAND" not in ln for ln in _active_lines(kql))
    # still a working behavioral rule
    assert any("-EncodedCommand" in ln for ln in _active_lines(kql))

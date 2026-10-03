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

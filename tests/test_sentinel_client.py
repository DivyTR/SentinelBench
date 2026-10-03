from datetime import datetime, timedelta, timezone

import pytest

from core import sentinel_client as sc

T0 = datetime(2026, 10, 3, 10, 0, tzinfo=timezone.utc)


class RecordingClient(sc.SentinelClient):
    def __init__(self, responses=None):
        self.calls = []
        self.responses = list(responses or [])

    def query(self, kql, timespan="PT1H"):
        self.calls.append((kql, timespan))
        return self.responses.pop(0) if self.responses else []


def test_parse_response_zips_columns_and_rows():
    data = {"tables": [{"name": "PrimaryResult",
                        "columns": [{"name": "A"}, {"name": "B"}],
                        "rows": [[1, "x"], [2, "y"]]}]}
    assert sc._parse_response(data) == [{"A": 1, "B": "x"}, {"A": 2, "B": "y"}]
    assert sc._parse_response({"tables": []}) == []


def test_kql_datetime_requires_timezone_and_converts_to_utc():
    with pytest.raises(ValueError):
        sc._kql_datetime(datetime(2026, 10, 3, 10, 0))
    ist = timezone(timedelta(hours=5, minutes=30))
    assert sc._kql_datetime(datetime(2026, 10, 3, 15, 30, tzinfo=ist)) == "2026-10-03T10:00:00.000000Z"


@pytest.mark.parametrize("bad", ['T1003" or 1==1 //', "t1003", "T10031", "T1003.1", ""])
def test_attack_id_list_rejects_malformed_ids(bad):
    with pytest.raises(ValueError):
        sc._kql_dynamic_list([bad])


@pytest.mark.parametrize("bad", ['host"; drop', "a b", "", "x" * 300])
def test_host_validation_rejects_injection(bad):
    with pytest.raises(ValueError):
        sc._validate_host(bad)


def test_alert_query_matches_exact_ids_from_techniques_column():
    client = RecordingClient()
    client.check_alert_for_technique(["T1003.001", "T1003"], T0, T0 + timedelta(minutes=5))
    kql, timespan = client.calls[0]
    assert "tostring(Techniques)" in kql
    assert 'set_intersect(AttackIds, dynamic(["T1003.001", "T1003"]))' in kql
    # The old bug: Tactics holds tactic names, never technique IDs.
    assert "Tactics has" not in kql
    assert "summarize arg_min(TimeGenerated, *) by SystemAlertId" in kql
    assert timespan == "2026-10-03T10:00:00.000000Z/2026-10-03T10:05:00.000000Z"


def test_alert_query_filters_by_host_only_when_given():
    client = RecordingClient()
    client.check_alert_for_technique(["T1112"], T0, T0 + timedelta(minutes=5), host="sb-lab")
    client.check_alert_for_technique(["T1112"], T0, T0 + timedelta(minutes=5))
    assert 'CompromisedEntity has "sb-lab"' in client.calls[0][0]
    assert "CompromisedEntity has" not in client.calls[2][0]


def test_falls_back_to_incidents_and_labels_source():
    incident = {"CreatedTime": "2026-10-03T10:04:00Z", "Title": "x", "Severity": "High"}
    client = RecordingClient(responses=[[], [incident]])
    row = client.check_alert_for_technique(["T1112"], T0, T0 + timedelta(minutes=5))
    assert "SecurityIncident" in client.calls[1][0]
    assert row["SourceTable"] == "SecurityIncident"


def test_alert_hit_skips_incident_query():
    client = RecordingClient(responses=[[{"TimeGenerated": "2026-10-03T10:01:00Z"}]])
    row = client.check_alert_for_technique(["T1112"], T0, T0 + timedelta(minutes=5))
    assert row["SourceTable"] == "SecurityAlert"
    assert len(client.calls) == 1


def test_raw_log_query_uses_sysmon_source_for_event_table():
    client = RecordingClient()
    client.fetch_raw_logs("T1547.001", T0, window_minutes=5, host="sb-lab")
    kql = client.calls[0][0]
    assert 'Source == "Microsoft-Windows-Sysmon"' in kql
    assert 'Computer startswith "sb-lab"' in kql

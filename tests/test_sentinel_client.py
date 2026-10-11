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
        sc._kql_datetime(datetime(2026, 10, 3, 10, 0))  # noqa: DTZ001 - naive on purpose
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
    # Regression: matching ExtendedProperties pulled the technique ID out of
    # the harness command line ("Invoke-AtomicTest T1552.001 ..."), crediting
    # one broadly-firing rule as a detection for a dozen techniques. Match the
    # rule's declared Techniques only.
    assert "ExtendedProperties" not in kql
    # Breadth guard: a rule tagged with dozens of techniques (e.g. the Empire
    # cmdlet rule, 51 techniques) is a catch-all, not a per-technique
    # detection, and must be ignored for attribution.
    assert "array_length(AttackIds) <= 8" in kql
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


# ── evidence collection (process lineage + technique events) ─────────────────────

GUID = "2a0a08a4-1f45-4089-984d-656e7764f699"


def _proc(image, pid, ppid, cmd=""):
    return {"TimeGenerated": "2026-10-03T10:00:01Z", "NewProcessName": image,
            "NewProcessId": pid, "ProcessId": ppid, "CommandLine": cmd}


def test_collect_evidence_for_4688_only_technique_runs_one_query_and_attributes():
    # T1059.003 hints only 4688, so there is no separate technique-events query.
    launcher = _proc("powershell.exe", "0x100", "0x50",
                     f"Invoke-AtomicTest T1059.003 -TestGuids {GUID}")
    technique = _proc("cmd.exe", "0x101", "0x100", "cmd /c echo hi")
    client = RecordingClient(responses=[[launcher, technique]])
    ev = client.collect_evidence("T1059.003", GUID, T0, host="sb-lab")

    assert len(client.calls) == 1
    assert "EventID == 4688" in client.calls[0][0]
    assert ev["attribution"] == "lineage"
    assert ev["technique_pids"] == {0x101}
    assert ev["technique_events"] == []


def test_collect_evidence_adds_hinted_non_4688_events():
    # T1569.002 hints 4697 (service install): a second query, kept separate
    # from the process lineage, lands in technique_events.
    launcher = _proc("powershell.exe", "0x100", "0x50",
                     f"Invoke-AtomicTest T1569.002 -TestGuids {GUID}")
    svc_event = {"TimeGenerated": "2026-10-03T10:00:02Z", "EventID": 4697,
                 "Process": "services.exe"}
    client = RecordingClient(responses=[[launcher], [svc_event]])
    ev = client.collect_evidence("T1569.002", GUID, T0, host="sb-lab")

    assert len(client.calls) == 2
    assert "EventID == 4688" in client.calls[0][0]
    assert "EventID == 4697" in client.calls[1][0]
    assert ev["technique_events"] == [svc_event]


# ── authentication ─────────────────────────────────────────────────────────────

class FakeResponse:
    def __init__(self, status, payload):
        self.status_code, self._payload, self.text = status, payload, str(payload)

    def json(self):
        return self._payload


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for v in ("SENTINEL_AUTH", "SENTINEL_TENANT_ID", "SENTINEL_CLIENT_ID",
              "SENTINEL_CLIENT_SECRET"):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setenv("SENTINEL_WORKSPACE_ID", "ws")
    sc._token_cache.clear()


def test_auth_mode_is_required_without_client_secret_vars():
    with pytest.raises(sc.SentinelClientError, match="SENTINEL_AUTH"):
        sc.SentinelClient()


def test_client_secret_is_the_default_when_its_vars_are_set(monkeypatch):
    for v in ("SENTINEL_TENANT_ID", "SENTINEL_CLIENT_ID", "SENTINEL_CLIENT_SECRET"):
        monkeypatch.setenv(v, "x")
    assert sc.SentinelClient().auth == "client_secret"


def test_unknown_auth_mode_is_rejected(monkeypatch):
    monkeypatch.setenv("SENTINEL_AUTH", "password")
    with pytest.raises(sc.SentinelClientError):
        sc.SentinelClient()


def test_managed_identity_uses_imds_without_proxy_and_caches(monkeypatch):
    calls = []

    class FakeSession:
        trust_env = True

        def get(self, url, params, headers, timeout):
            calls.append((url, params, headers, self.trust_env))
            return FakeResponse(200, {"access_token": "mi-token", "expires_in": "3599"})

    monkeypatch.setattr(sc.requests, "Session", FakeSession)
    client = sc.SentinelClient(auth="managed_identity")
    assert client.get_token() == "mi-token"
    assert client.get_token() == "mi-token"
    assert len(calls) == 1
    url, params, headers, trust_env = calls[0]
    assert url == sc.IMDS_TOKEN_URL
    assert params["resource"] == "https://api.loganalytics.io"
    assert headers == {"Metadata": "true"}
    assert trust_env is False


def test_azure_cli_token(monkeypatch):
    monkeypatch.setattr(sc.shutil, "which", lambda name: "/usr/bin/az")

    class Proc:
        returncode = 0
        stdout = '{"accessToken": "cli-token", "expires_on": 4102444800}'
        stderr = ""

    seen = {}
    monkeypatch.setattr(sc.subprocess, "run", lambda cmd, **kw: seen.setdefault("cmd", cmd) and Proc())
    assert sc.SentinelClient(auth="azure_cli").get_token() == "cli-token"
    assert "https://api.loganalytics.io" in seen["cmd"]


def test_azure_cli_missing_gives_clear_error(monkeypatch):
    monkeypatch.setattr(sc.shutil, "which", lambda name: None)
    with pytest.raises(sc.SentinelClientError, match="not on PATH"):
        sc.SentinelClient(auth="azure_cli").get_token()



def test_breadth_guard_threshold_is_configurable():
    from core import sentinel_client as _sc
    assert _sc.MAX_ALERT_TECHNIQUES == 8
    client = RecordingClient()
    client.check_alert_for_technique(["T1040"], T0, T0 + timedelta(minutes=5), max_techniques=3)
    assert "array_length(AttackIds) <= 3" in client.calls[0][0]

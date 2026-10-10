import json

import pytest

from core.rule_deployer import (
    RULE_LABEL,
    RULE_PREFIX,
    RuleDeployer,
    RuleDeployerError,
)


class FakeResponse:
    def __init__(self, status_code, payload=None):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self.text = json.dumps(self._payload)

    def json(self):
        return self._payload


class FakeSession:
    """Records calls; returns canned responses. Never touches the network."""

    def __init__(self, list_payload=None):
        self.calls = []
        self._list_payload = list_payload if list_payload is not None else {"value": []}

    def put(self, url, headers=None, json=None, timeout=None):
        self.calls.append(("PUT", url, headers, json))
        return FakeResponse(201, {"id": url})

    def get(self, url, headers=None, timeout=None):
        self.calls.append(("GET", url, headers, None))
        return FakeResponse(200, self._list_payload)

    def delete(self, url, headers=None, timeout=None):
        self.calls.append(("DELETE", url, headers, None))
        return FakeResponse(200, {})


def _deployer(session=None):
    return RuleDeployer(
        subscription_id="sub-123",
        resource_group="rg-sbench-lab",
        workspace_name="ws-sbench",
        auth="managed_identity",
        token_provider=lambda: "faketoken",
        session=session,
    )


def _suggestion(tid="T1059.003", confidence="medium", kql="SecurityEvent | take 1"):
    return {"technique_id": tid, "kql_query": kql, "confidence": confidence,
            "data_source": "SecurityEvent", "false_positive_note": "tune me"}


# ── payload construction ─────────────────────────────────────────────────────

def test_build_payload_is_a_scheduled_sbc_rule():
    p = _deployer().build_rule_payload(_suggestion())
    assert p["kind"] == "Scheduled"
    props = p["properties"]
    assert props["displayName"].startswith(f"{RULE_PREFIX}T1059.003")
    assert props["query"] == "SecurityEvent | take 1"
    assert props["enabled"] is True
    assert props["triggerOperator"] == "GreaterThan" and props["triggerThreshold"] == 0
    assert props["suppressionEnabled"] is True and props["suppressionDuration"] == "PT5H"
    assert RULE_LABEL in props["labels"]
    # Tagged so the config C re-run can credit it via the Techniques column.
    assert props["techniques"] == ["T1059"]
    assert props["subTechniques"] == ["T1059.003"]


def test_severity_comes_from_the_technique_registry():
    assert _deployer().build_rule_payload(
        _suggestion("T1003.001"))["properties"]["severity"] == "High"
    assert _deployer().build_rule_payload(
        _suggestion("T1059.003"))["properties"]["severity"] == "Medium"


def test_base_technique_has_no_subtechniques_field():
    props = _deployer().build_rule_payload(_suggestion("T1040"))["properties"]
    assert props["techniques"] == ["T1040"]
    assert "subTechniques" not in props


def test_attack_mapping_can_be_omitted():
    props = _deployer().build_rule_payload(
        _suggestion(), include_attack_mapping=False)["properties"]
    assert "techniques" not in props and "subTechniques" not in props


def test_rule_id_is_deterministic_and_per_technique():
    assert RuleDeployer.rule_id_for("T1059.003") == RuleDeployer.rule_id_for("T1059.003")
    assert RuleDeployer.rule_id_for("T1059.003") != RuleDeployer.rule_id_for("T1059.001")


# ── deploy ───────────────────────────────────────────────────────────────────

def test_dry_run_builds_the_request_without_calling_arm():
    sess = FakeSession()
    result = _deployer(sess).deploy_suggestion(_suggestion(), dry_run=True)
    assert result["action"] == "dry_run" and result["method"] == "PUT"
    assert "sub-123" in result["url"] and result["rule_id"] in result["url"]
    assert result["payload"]["kind"] == "Scheduled"
    assert sess.calls == []            # nothing sent


def test_live_deploy_puts_to_arm_with_bearer_token():
    sess = FakeSession()
    result = _deployer(sess).deploy_suggestion(_suggestion(), dry_run=False)
    assert result["action"] == "deployed" and result["status_code"] == 201
    assert len(sess.calls) == 1
    method, _url, headers, body = sess.calls[0]
    assert method == "PUT"
    assert headers["Authorization"] == "Bearer faketoken"
    assert body["properties"]["displayName"].startswith(RULE_PREFIX)


def test_deploy_run_skips_requires_tuning_skeletons(monkeypatch):
    fake = [_suggestion("T1552.001", confidence="requires_tuning"),
            _suggestion("T1059.003", confidence="medium")]
    monkeypatch.setattr("core.db.get_kql_for_run", lambda run_id, *a, **k: fake)
    report = _deployer(FakeSession()).deploy_run("run-1", dry_run=True)
    skipped = [r for r in report if r.get("action") == "skipped"]
    planned = [r for r in report if r.get("action") == "dry_run"]
    assert [r["technique_id"] for r in skipped] == ["T1552.001"]
    assert [r["technique_id"] for r in planned] == ["T1059.003"]


# ── list / teardown ──────────────────────────────────────────────────────────

def test_list_and_teardown_target_only_sbc_rules():
    payload = {"value": [
        {"name": "id-ours", "properties": {"displayName": f"{RULE_PREFIX}T1059.003 - x"}},
        {"name": "id-builtin", "properties": {"displayName": "Powershell Empire Cmdlets"}},
    ]}
    sess = FakeSession(list_payload=payload)
    dep = _deployer(sess)

    found = dep.list_sb_rules()
    assert [r["name"] for r in found] == ["id-ours"]

    dep.teardown(dry_run=False)
    deletes = [c for c in sess.calls if c[0] == "DELETE"]
    assert len(deletes) == 1 and "id-ours" in deletes[0][1]


# ── config / errors ──────────────────────────────────────────────────────────

def test_missing_required_env_raises(monkeypatch):
    for v in ("SENTINEL_SUBSCRIPTION_ID", "SENTINEL_RESOURCE_GROUP", "SENTINEL_WORKSPACE_NAME"):
        monkeypatch.delenv(v, raising=False)
    with pytest.raises(RuleDeployerError, match="SENTINEL_SUBSCRIPTION_ID"):
        RuleDeployer(auth="managed_identity", token_provider=lambda: "x")


def test_bad_status_code_raises():
    class ErrSession(FakeSession):
        def put(self, url, headers=None, json=None, timeout=None):
            return FakeResponse(403, {"error": "Forbidden - needs Sentinel Contributor"})
    with pytest.raises(RuleDeployerError, match="403"):
        _deployer(ErrSession()).deploy_suggestion(_suggestion(), dry_run=False)

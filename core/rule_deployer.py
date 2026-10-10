"""
core/rule_deployer.py
---------------------
Deploys SentinelBench's generated detection rules into Microsoft Sentinel as
scheduled analytics rules — the "deploy" half of the config C closed loop
(generate -> deploy -> re-measure -> show the gaps close).

Why this is a separate module from sentinel_client.py
-----------------------------------------------------
SentinelClient talks to the **Log Analytics query** API
(`api.loganalytics.io`), addresses the workspace by its **GUID**, and only
needs read access. Creating analytics rules is a different world:

  * a different token audience — the **Azure Resource Manager** API
    (`management.azure.com`), so a second token scope;
  * the workspace is addressed by its full ARM resource path
    (subscription / resource group / workspace **name**), not the query GUID;
  * it needs **write** access — the "Microsoft Sentinel Contributor" role, not
    the "Log Analytics Reader" the lab VM's managed identity has today. THIS IS
    A PREREQUISITE: until the identity is granted that role (a terraform
    change), live deploys will 403. The module is still fully usable in
    `dry_run` mode without it.

Keeping deployment out of the measurement client keeps the crown-jewel query
path untouched. The ARM token logic below is deliberately a small, self-
contained copy of the three auth modes in sentinel_client rather than a shared
abstraction; if that duplication ever bites, refactor behind green tests.

Configuration (environment)
---------------------------
  SENTINEL_SUBSCRIPTION_ID   Azure subscription GUID
  SENTINEL_RESOURCE_GROUP    resource group holding the workspace (rg-sbench-lab)
  SENTINEL_WORKSPACE_NAME    workspace *name* (not the query GUID)
  SENTINEL_AUTH              same selector as sentinel_client
                             (managed_identity | azure_cli | client_secret)

Safety
------
Everything defaults to **dry_run=True**: build the exact ARM request and return
it without sending. Nothing touches the live workspace until a caller passes
`dry_run=False`. Every rule this module creates is prefixed `[SB-C] ` in its
display name and carries the `SentinelBench:configC` label, so teardown can
find and remove exactly what we deployed and nothing else.
"""

import json
import os
import shutil
import subprocess
import time
import uuid

import requests

from .simulation_runner import TECHNIQUES

ARM_RESOURCE = "https://management.azure.com"
ARM_SCOPE = ARM_RESOURCE + "/.default"
IMDS_TOKEN_URL = "http://169.254.169.254/metadata/identity/oauth2/token"
TOKEN_URL_TEMPLATE = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"

DEFAULT_API_VERSION = "2023-02-01"
AUTH_MODES = ("managed_identity", "azure_cli", "client_secret")

# Everything this module creates is prefixed and labelled so teardown targets
# exactly our rules. Changing these orphans previously-deployed rules.
RULE_PREFIX = "[SB-C] "
RULE_LABEL = "SentinelBench:configC"
# Stable namespace so a technique always maps to the same ARM rule id: a
# redeploy updates the rule in place instead of creating duplicates.
_RULE_NAMESPACE = uuid.UUID("5b3c0d9e-1a2b-4c6d-8e7f-000000005bc0")

# Per-process ARM token cache, keyed by auth mode. Separate from
# sentinel_client's cache so an LA token and an ARM token for the same auth
# mode never collide.
_arm_token_cache: dict = {}

# Sentinel alert severities (ARM enum). Our expected severities are a subset.
_VALID_SEVERITIES = ("Informational", "Low", "Medium", "High")


class RuleDeployerError(Exception):
    pass


class RuleDeployer:
    """
    Creates / updates / removes SentinelBench scheduled analytics rules.

    Usage
    -----
        dep = RuleDeployer()                       # reads env, dry-run by default
        plan = dep.deploy_run("<run-id>")          # what it WOULD deploy
        dep.deploy_run("<run-id>", dry_run=False)  # actually deploy
        dep.teardown(dry_run=False)                # remove all [SB-C] rules
    """

    def __init__(
        self,
        subscription_id: str | None = None,
        resource_group: str | None = None,
        workspace_name: str | None = None,
        auth: str | None = None,
        api_version: str = DEFAULT_API_VERSION,
        # Injectable seams for tests — never used in production.
        token_provider=None,
        session=None,
    ):
        self.subscription_id = subscription_id or _require_env("SENTINEL_SUBSCRIPTION_ID")
        self.resource_group  = resource_group  or _require_env("SENTINEL_RESOURCE_GROUP")
        self.workspace_name  = workspace_name  or _require_env("SENTINEL_WORKSPACE_NAME")
        self.auth = auth or os.environ.get("SENTINEL_AUTH") or _default_auth_mode()
        if self.auth not in AUTH_MODES:
            raise RuleDeployerError(
                f"SENTINEL_AUTH must be one of {', '.join(AUTH_MODES)} (got {self.auth!r})"
            )
        self.api_version = api_version
        self._token_provider = token_provider
        self._session = session or requests

    # ── ARM resource addressing ─────────────────────────────────────────────────

    def _collection_url(self) -> str:
        return (
            f"{ARM_RESOURCE}/subscriptions/{self.subscription_id}"
            f"/resourceGroups/{self.resource_group}"
            f"/providers/Microsoft.OperationalInsights/workspaces/{self.workspace_name}"
            f"/providers/Microsoft.SecurityInsights/alertRules"
        )

    def _rule_url(self, rule_id: str) -> str:
        return f"{self._collection_url()}/{rule_id}?api-version={self.api_version}"

    @staticmethod
    def rule_id_for(technique_id: str) -> str:
        """Deterministic ARM rule id for a technique (idempotent redeploys)."""
        return str(uuid.uuid5(_RULE_NAMESPACE, f"sbench-c-{technique_id}"))

    # ── rule construction (pure; the testable core) ─────────────────────────────

    def build_rule_payload(
        self,
        suggestion: dict,
        *,
        query_frequency: str = "PT5M",
        query_period: str = "PT1H",
        suppression_duration: str = "PT5H",
        include_attack_mapping: bool = True,
    ) -> dict:
        """
        Turn a stored KQL suggestion (a `kql_suggestions` row) into an ARM
        scheduled-rule payload.

        Severity comes from the technique's expected severity (the whole point
        of the benchmark is whether the *right* severity fires), falling back to
        Medium. The rule is tagged with the technique so the config C re-run's
        matcher can credit it via the SecurityAlert `Techniques` column, exactly
        like any built-in rule — no special-casing of our own rules.
        """
        technique_id = suggestion["technique_id"]
        meta = TECHNIQUES.get(technique_id, {})
        name = meta.get("name", technique_id)
        severity = _as_severity(meta.get("severity_expected"))

        props = {
            "displayName": f"{RULE_PREFIX}{technique_id} - {name}"[:256],
            "description": (
                f"SentinelBench config C candidate for {technique_id}. "
                f"{suggestion.get('false_positive_note', '')}"
            ).strip()[:5000],
            "severity": severity,
            "enabled": True,
            "query": suggestion["kql_query"],
            "queryFrequency": query_frequency,
            "queryPeriod": query_period,
            "triggerOperator": "GreaterThan",
            "triggerThreshold": 0,
            "suppressionEnabled": True,
            "suppressionDuration": suppression_duration,
            "labels": [RULE_LABEL],
        }
        if include_attack_mapping:
            techniques, sub_techniques = _attack_fields(technique_id)
            props["techniques"] = techniques
            if sub_techniques:
                props["subTechniques"] = sub_techniques
        return {"kind": "Scheduled", "properties": props}

    # ── deploy / list / teardown ────────────────────────────────────────────────

    def deploy_suggestion(self, suggestion: dict, *, dry_run: bool = True, **payload_kw) -> dict:
        """Build and PUT one rule. Returns a small result record."""
        technique_id = suggestion["technique_id"]
        rule_id = self.rule_id_for(technique_id)
        payload = self.build_rule_payload(suggestion, **payload_kw)
        url = self._rule_url(rule_id)
        if dry_run:
            return {"technique_id": technique_id, "rule_id": rule_id,
                    "action": "dry_run", "method": "PUT", "url": url, "payload": payload}
        resp = self._put(url, payload)
        return {"technique_id": technique_id, "rule_id": rule_id,
                "action": "deployed", "status_code": resp.status_code,
                "displayName": payload["properties"]["displayName"]}

    def deploy_run(
        self,
        run_id: str,
        *,
        dry_run: bool = True,
        skip_requires_tuning: bool = True,
        db_path=None,
        **payload_kw,
    ) -> list[dict]:
        """
        Deploy a rule for every stored KQL suggestion of a run's misses.

        By default the `requires_tuning` skeletons (the generic fallback, which
        has no discriminator and would match all process creation) are skipped —
        deploying them would create a deliberately-noisy rule. Only real
        behavioral candidates (high / medium) are deployed.
        """
        from . import db
        suggestions = (
            db.get_kql_for_run(run_id, db_path) if db_path
            else db.get_kql_for_run(run_id)
        )
        report = []
        for s in suggestions:
            if skip_requires_tuning and s.get("confidence") == "requires_tuning":
                report.append({"technique_id": s["technique_id"],
                               "action": "skipped", "reason": "requires_tuning"})
                continue
            report.append(self.deploy_suggestion(s, dry_run=dry_run, **payload_kw))
        return report

    def list_sb_rules(self) -> list[dict]:
        """Return the [SB-C] rules currently in the workspace (name + displayName)."""
        url = f"{self._collection_url()}?api-version={self.api_version}"
        data = self._get(url)
        out = []
        for rule in data.get("value", []):
            display = (rule.get("properties") or {}).get("displayName", "")
            if display.startswith(RULE_PREFIX):
                out.append({"name": rule.get("name"), "displayName": display})
        return out

    def teardown(self, *, dry_run: bool = True) -> list[dict]:
        """Delete every [SB-C] rule. Dry-run lists what it would remove."""
        report = []
        for rule in self.list_sb_rules():
            url = self._rule_url(rule["name"])
            if dry_run:
                report.append({**rule, "action": "dry_run", "method": "DELETE"})
            else:
                resp = self._delete(url)
                report.append({**rule, "action": "deleted", "status_code": resp.status_code})
        return report

    # ── HTTP ────────────────────────────────────────────────────────────────────

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self._get_token()}",
                "Content-Type": "application/json"}

    def _put(self, url: str, payload: dict):
        resp = self._session.put(url, headers=self._headers(), json=payload, timeout=30)
        return _check(resp, (200, 201), "create/update rule")

    def _get(self, url: str) -> dict:
        resp = self._session.get(url, headers=self._headers(), timeout=30)
        return _check(resp, (200,), "list rules").json()

    def _delete(self, url: str):
        resp = self._session.delete(url, headers=self._headers(), timeout=30)
        return _check(resp, (200, 204), "delete rule")

    # ── ARM authentication (self-contained; see module docstring) ───────────────

    def _get_token(self) -> str:
        if self._token_provider is not None:
            return self._token_provider()
        cached = _arm_token_cache.get(self.auth)
        if cached and time.time() < cached["expires_at"] - 60:
            return cached["token"]
        token, expires_at = {
            "managed_identity": self._token_managed_identity,
            "azure_cli":        self._token_azure_cli,
            "client_secret":    self._token_client_secret,
        }[self.auth]()
        _arm_token_cache[self.auth] = {"token": token, "expires_at": expires_at}
        return token

    def _token_managed_identity(self) -> tuple[str, float]:
        session = requests.Session()
        session.trust_env = False  # IMDS is link-local; never via a proxy
        try:
            resp = session.get(
                IMDS_TOKEN_URL,
                params={"api-version": "2018-02-01", "resource": ARM_RESOURCE},
                headers={"Metadata": "true"},
                timeout=5,
            )
        except requests.RequestException as exc:
            raise RuleDeployerError(
                f"Managed identity endpoint unreachable ({exc}); only works on an Azure VM."
            ) from exc
        if resp.status_code != 200:
            raise RuleDeployerError(
                f"Managed identity token request failed: {resp.status_code} - {resp.text[:300]}"
            )
        data = resp.json()
        return data["access_token"], time.time() + int(data.get("expires_in", 3600))

    def _token_azure_cli(self) -> tuple[str, float]:
        az = shutil.which("az")
        if not az:
            raise RuleDeployerError("azure_cli auth selected but the 'az' CLI is not on PATH")
        proc = subprocess.run(
            [az, "account", "get-access-token", "--resource", ARM_RESOURCE, "--output", "json"],
            capture_output=True, text=True, timeout=60, check=False,
        )
        if proc.returncode != 0:
            raise RuleDeployerError(
                f"az account get-access-token failed (run 'az login'?): {proc.stderr.strip()[:300]}"
            )
        data = json.loads(proc.stdout)
        return data["accessToken"], float(data.get("expires_on") or time.time() + 300)

    def _token_client_secret(self) -> tuple[str, float]:
        tenant_id     = _require_env("SENTINEL_TENANT_ID")
        client_id     = _require_env("SENTINEL_CLIENT_ID")
        client_secret = _require_env("SENTINEL_CLIENT_SECRET")
        resp = requests.post(
            TOKEN_URL_TEMPLATE.format(tenant_id=tenant_id),
            data={"grant_type": "client_credentials", "client_id": client_id,
                  "client_secret": client_secret, "scope": ARM_SCOPE},
            timeout=15,
        )
        if resp.status_code != 200:
            raise RuleDeployerError(f"Token request failed: {resp.status_code} - {resp.text[:300]}")
        data = resp.json()
        return data["access_token"], time.time() + int(data.get("expires_in", 3600))


# ── helpers ──────────────────────────────────────────────────────────────────

def _attack_fields(technique_id: str) -> tuple[list[str], list[str]]:
    """
    Split a technique id into ARM's `techniques` (parent) and `subTechniques`
    (full) fields. ARM's `techniques` enum expects parent IDs; the sub-id goes
    in `subTechniques`. Our suite's match_ids already include both the full and
    the parent id, so the SecurityAlert `Techniques` column matches either way.
    """
    parent = technique_id.split(".")[0]
    sub = [technique_id] if "." in technique_id else []
    return [parent], sub


def _as_severity(value) -> str:
    if value and str(value).strip().title() in _VALID_SEVERITIES:
        return str(value).strip().title()
    return "Medium"


def _check(resp, ok_codes, what: str):
    if resp.status_code not in ok_codes:
        raise RuleDeployerError(
            f"Failed to {what} ({resp.status_code}): {getattr(resp, 'text', '')[:500]}"
        )
    return resp


def _require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuleDeployerError(f"Required environment variable {name} is not set")
    return value


def _default_auth_mode() -> str:
    if all(os.environ.get(v) for v in
           ("SENTINEL_TENANT_ID", "SENTINEL_CLIENT_ID", "SENTINEL_CLIENT_SECRET")):
        return "client_secret"
    raise RuleDeployerError(
        "SENTINEL_AUTH is not set and no client-secret vars are present. "
        "Set SENTINEL_AUTH to one of: " + ", ".join(AUTH_MODES)
    )

"""
core/sentinel_client.py
-----------------------
Microsoft Sentinel / Log Analytics API client.

Authentication
--------------
SENTINEL_AUTH selects how the client gets a Log Analytics token:

  managed_identity  The Azure VM's system-assigned identity, via the Instance
                    Metadata Service. The default on the lab VM built by
                    infra/terraform: no secret exists anywhere.
  azure_cli         Whatever `az login` session is active. Convenient for
                    querying from a laptop.
  client_secret     App registration + secret (OAuth client-credentials).
                    Needs SENTINEL_TENANT_ID, SENTINEL_CLIENT_ID and
                    SENTINEL_CLIENT_SECRET.

If SENTINEL_AUTH is unset, client_secret is used when its three variables
are present (the original behaviour).

Whichever identity is used needs the "Log Analytics Reader" role on the
workspace. SENTINEL_WORKSPACE_ID is always required.
"""

import json
import os
import re
import shutil
import subprocess
import time
from datetime import datetime, timedelta, timezone

import requests

# ── token cache (in-memory, per-process, per auth mode) ──────────────────────

_token_cache: dict = {}

TOKEN_URL_TEMPLATE = (
    "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
)
LOG_ANALYTICS_RESOURCE = "https://api.loganalytics.io"
RESOURCE_SCOPE = LOG_ANALYTICS_RESOURCE + "/.default"
IMDS_TOKEN_URL = "http://169.254.169.254/metadata/identity/oauth2/token"
QUERY_URL_TEMPLATE = (
    "https://api.loganalytics.io/v1/workspaces/{workspace_id}/query"
)

AUTH_MODES = ("managed_identity", "azure_cli", "client_secret")


class SentinelClientError(Exception):
    pass


# ── public interface ──────────────────────────────────────────────────────────

class SentinelClient:
    """
    Thin wrapper around the Log Analytics REST API.

    Usage
    -----
        client = SentinelClient()
        rows = client.query("SecurityEvent | where EventID == 4688 | take 5")
    """

    def __init__(
        self,
        workspace_id: str | None = None,
        auth: str | None = None,
        tenant_id: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
    ):
        self.workspace_id = workspace_id or _require_env("SENTINEL_WORKSPACE_ID")
        self.auth = auth or os.environ.get("SENTINEL_AUTH") or _default_auth_mode()
        if self.auth not in AUTH_MODES:
            raise SentinelClientError(
                f"SENTINEL_AUTH must be one of {', '.join(AUTH_MODES)} (got {self.auth!r})"
            )
        if self.auth == "client_secret":
            self.tenant_id     = tenant_id     or _require_env("SENTINEL_TENANT_ID")
            self.client_id     = client_id     or _require_env("SENTINEL_CLIENT_ID")
            self.client_secret = client_secret or _require_env("SENTINEL_CLIENT_SECRET")

    # ── authentication ────────────────────────────────────────────────────────

    def get_token(self) -> str:
        """
        Return a valid bearer token, fetching a new one if the cached token
        expires within 60 seconds.
        """
        cached = _token_cache.get(self.auth)
        if cached and time.time() < cached["expires_at"] - 60:
            return cached["token"]

        fetch = {
            "managed_identity": self._token_from_managed_identity,
            "azure_cli":        self._token_from_azure_cli,
            "client_secret":    self._token_from_client_secret,
        }[self.auth]
        token, expires_at = fetch()
        _token_cache[self.auth] = {"token": token, "expires_at": expires_at}
        return token

    def _token_from_client_secret(self) -> tuple[str, float]:
        resp = requests.post(
            TOKEN_URL_TEMPLATE.format(tenant_id=self.tenant_id),
            data={
                "grant_type":    "client_credentials",
                "client_id":     self.client_id,
                "client_secret": self.client_secret,
                "scope":         RESOURCE_SCOPE,
            },
            timeout=15,
        )
        if resp.status_code != 200:
            raise SentinelClientError(
                f"Token request failed: {resp.status_code} — {resp.text[:300]}"
            )
        data = resp.json()
        return data["access_token"], time.time() + int(data.get("expires_in", 3600))

    def _token_from_managed_identity(self) -> tuple[str, float]:
        # IMDS is link-local: never route it through an HTTP proxy.
        session = requests.Session()
        session.trust_env = False
        try:
            resp = session.get(
                IMDS_TOKEN_URL,
                params={"api-version": "2018-02-01", "resource": LOG_ANALYTICS_RESOURCE},
                headers={"Metadata": "true"},
                timeout=5,
            )
        except requests.RequestException as exc:
            raise SentinelClientError(
                f"Managed identity endpoint unreachable ({exc}). "
                "managed_identity only works on an Azure VM with an identity assigned."
            ) from exc
        if resp.status_code != 200:
            raise SentinelClientError(
                f"Managed identity token request failed: {resp.status_code} — {resp.text[:300]}"
            )
        data = resp.json()
        return data["access_token"], time.time() + int(data.get("expires_in", 3600))

    def _token_from_azure_cli(self) -> tuple[str, float]:
        az = shutil.which("az")
        if not az:
            raise SentinelClientError("azure_cli auth selected but the 'az' CLI is not on PATH")
        proc = subprocess.run(
            [az, "account", "get-access-token",
             "--resource", LOG_ANALYTICS_RESOURCE, "--output", "json"],
            capture_output=True, text=True, timeout=60, check=False,
        )
        if proc.returncode != 0:
            raise SentinelClientError(
                f"az account get-access-token failed (run 'az login'?): {proc.stderr.strip()[:300]}"
            )
        data = json.loads(proc.stdout)
        # Newer CLI versions return expires_on as epoch seconds; fall back to
        # a conservative 5 minutes if it is missing.
        expires_at = float(data.get("expires_on") or time.time() + 300)
        return data["accessToken"], expires_at

    # ── query ─────────────────────────────────────────────────────────────────

    def query(self, kql: str, timespan: str = "PT1H") -> list[dict]:
        """
        Execute a KQL query against the workspace and return rows as dicts.

        Parameters
        ----------
        kql      : KQL query string
        timespan : ISO 8601 duration or interval string (default: last 1 hour)
                   Examples: "PT1H", "PT30M", "P1D"

        Returns
        -------
        List of row dicts, empty list if no results.
        """
        url = QUERY_URL_TEMPLATE.format(workspace_id=self.workspace_id)
        headers = {
            "Authorization": f"Bearer {self.get_token()}",
            "Content-Type":  "application/json",
        }
        body = {"query": kql, "timespan": timespan}

        resp = requests.post(url, headers=headers, json=body, timeout=30)

        if resp.status_code == 401:
            # Token may have expired mid-run; invalidate cache and retry once
            _token_cache.pop(self.auth, None)
            headers["Authorization"] = f"Bearer {self.get_token()}"
            resp = requests.post(url, headers=headers, json=body, timeout=30)

        if resp.status_code != 200:
            raise SentinelClientError(
                f"Query failed ({resp.status_code}): {resp.text[:500]}"
            )

        return _parse_response(resp.json())

    # ── detection-specific helpers ────────────────────────────────────────────

    def check_alert_for_technique(
        self,
        match_ids: list[str],
        since: datetime,
        until: datetime,
        host: str | None = None,
    ) -> dict | None:
        """
        Return the earliest Sentinel alert created in [since, until] that is
        tagged with one of `match_ids`, or None.

        How matching works
        ------------------
        We match ONLY on the alert's declared MITRE mapping: the `Techniques`
        column on SecurityAlert (a JSON array of ATT&CK IDs set by the rule).
        We require an EXACT id match against match_ids. A plain `has "T1059"`
        would also match alerts tagged T1059.003 and credit the wrong
        technique.

        We deliberately do NOT read ExtendedProperties or any other field that
        carries the raw event that triggered the rule. Those fields contain the
        offending command line, and SentinelBench launches every technique with
        a harness command that names the technique ("Invoke-AtomicTest
        T1552.001 ..."). Extracting IDs from that text matched a technique to
        its own harness invocation, so a single broadly-firing rule was
        credited as a detection for a dozen unrelated techniques. Matching only
        the rule's declared Techniques removes that false attribution.

        If `host` is given, the alert must name it in CompromisedEntity or
        Entities, so alerts from other machines in the workspace are ignored.

        SecurityAlert receives a new row each time an alert's status changes;
        arg_min per SystemAlertId keeps the row from when it was first created.
        Falls back to SecurityIncident when no alert row matches.
        """
        ids = _kql_dynamic_list(match_ids)
        since_str, until_str = _kql_datetime(since), _kql_datetime(until)
        host_filter = ""
        if host:
            h = _validate_host(host)
            host_filter = (
                f'| where CompromisedEntity has "{h}" or tostring(Entities) has "{h}"\n'
            )

        kql = f"""
SecurityAlert
| where TimeGenerated between (datetime({since_str}) .. datetime({until_str}))
| extend IngestedAt = ingestion_time()
| extend AttackIds = extract_all(@"(T\\d{{4}}(?:\\.\\d{{3}})?)", tostring(Techniques))
| extend MatchedIds = set_intersect(AttackIds, {ids})
| where array_length(MatchedIds) > 0
{host_filter}| summarize arg_min(TimeGenerated, *) by SystemAlertId
| project TimeGenerated, IngestedAt, StartTime, AlertName, AlertSeverity,
          ProviderName, CompromisedEntity, MatchedIds, SystemAlertId
| order by TimeGenerated asc
| take 1
"""
        timespan = f"{since_str}/{until_str}"
        rows = self.query(kql, timespan=timespan)
        if rows:
            return {**rows[0], "SourceTable": "SecurityAlert"}

        # Fallback: SecurityIncident (aggregated alerts -> incidents). Read the
        # incident's own techniques field, not the whole AdditionalData blob,
        # for the same reason as above.
        kql_incident = f"""
SecurityIncident
| where CreatedTime between (datetime({since_str}) .. datetime({until_str}))
| extend AttackIds = extract_all(@"(T\\d{{4}}(?:\\.\\d{{3}})?)",
                                 tostring(parse_json(tostring(AdditionalData)).techniques))
| extend MatchedIds = set_intersect(AttackIds, {ids})
| where array_length(MatchedIds) > 0
| summarize arg_min(CreatedTime, *) by IncidentNumber
| project CreatedTime, Title, Severity, ProviderName, MatchedIds, IncidentNumber
| order by CreatedTime asc
| take 1
"""
        rows = self.query(kql_incident, timespan=timespan)
        return {**rows[0], "SourceTable": "SecurityIncident"} if rows else None

    def fetch_raw_logs(
        self,
        technique_id: str,
        exec_time: datetime,
        window_minutes: int = 5,
        host: str | None = None,
    ) -> list[dict]:
        """
        Pull the raw Windows Security Event / Sysmon logs generated during
        the simulation window so the KQL generator can seed its output with
        real process names, EventIDs, and command-line arguments.

        Uses technique-specific EventID hints defined in TECHNIQUE_EVENT_HINTS.
        """
        since_str = _kql_datetime(exec_time)
        until_str = _kql_datetime(_add_minutes(exec_time, window_minutes))

        hints = TECHNIQUE_EVENT_HINTS.get(technique_id, {})
        event_ids = hints.get("event_ids", [4688])  # default: process creation
        table = hints.get("table", "SecurityEvent")

        event_id_filter = " or ".join(f"EventID == {e}" for e in event_ids)
        host_filter = f'| where Computer startswith "{_validate_host(host)}"\n' if host else ""

        if table == "Event":
            # Sysmon events — structured fields are inside EventData XML
            kql = f"""
{table}
| where TimeGenerated between (datetime({since_str}) .. datetime({until_str}))
| where Source == "Microsoft-Windows-Sysmon"
| where {event_id_filter}
{host_filter}| extend EventDataParsed = parse_xml(EventData)
| project TimeGenerated, EventID, Computer,
          Process       = tostring(EventDataParsed.DataItem.Image),
          CommandLine   = tostring(EventDataParsed.DataItem.CommandLine),
          TargetObject  = tostring(EventDataParsed.DataItem.TargetObject),
          Details       = tostring(EventDataParsed.DataItem.Details)
| order by TimeGenerated asc
| take 20
"""
        else:
            kql = f"""
{table}
| where TimeGenerated between (datetime({since_str}) .. datetime({until_str}))
| where {event_id_filter}
{host_filter}| project TimeGenerated, EventID, Computer, Account, Process, CommandLine,
          ParentProcessName, SubjectUserName, TargetUserName
| order by TimeGenerated asc
| take 20
"""
        return self.query(kql, timespan=f"{since_str}/{until_str}")

    def test_connection(self) -> bool:
        """
        Verify credentials and workspace connectivity.
        Returns True on success, raises SentinelClientError on failure.
        """
        self.query("Heartbeat | take 1", timespan="PT5M")
        return True  # if query() didn't raise, we're connected


# ── technique → event ID mapping ─────────────────────────────────────────────
# Maps each v1 technique to the Windows EventIDs and log table most
# likely to contain evidence of its execution.

TECHNIQUE_EVENT_HINTS: dict[str, dict] = {
    # Execution
    "T1059.001": {"table": "SecurityEvent",  "event_ids": [4688]},        # powershell.exe process creation
    "T1059.003": {"table": "SecurityEvent",  "event_ids": [4688]},        # cmd.exe
    "T1569.002": {"table": "SecurityEvent",  "event_ids": [4697]},        # Service install (7045 is in the System log -> Event table)

    # Persistence
    "T1547.001": {"table": "Event",          "event_ids": [13, 14]},      # Sysmon reg events (Event table)
    "T1053.005": {"table": "SecurityEvent",  "event_ids": [4698, 4702]},  # Scheduled task
    "T1136.001": {"table": "SecurityEvent",  "event_ids": [4720]},        # Account created

    # Credential Access
    "T1003.001": {"table": "Event",          "event_ids": [10]},          # Sysmon ProcessAccess on lsass (4656 needs a SACL the lab does not set)
    "T1110.001": {"table": "SecurityEvent",  "event_ids": [4625, 4771]},  # Failed logons
    "T1552.001": {"table": "SecurityEvent",  "event_ids": [4663, 4688]},  # File access
    "T1555.003": {"table": "SecurityEvent",  "event_ids": [4688]},        # Browser proc
    "T1040":     {"table": "SecurityEvent",  "event_ids": [4688]},        # Network sniffer

    # Stealth / Defense Impairment
    "T1685.005": {"table": "SecurityEvent",  "event_ids": [1102]},        # Security log cleared
    "T1685":     {"table": "SecurityEvent",  "event_ids": [4688]},        # sc.exe stop WinDefend
    "T1027":     {"table": "SecurityEvent",  "event_ids": [4688]},        # Obfuscated exec
    "T1112":     {"table": "Event",          "event_ids": [13, 14]},      # Sysmon reg modification (Event table)
}


# ── internal helpers ───────────────────────────────────────────────────────────

def _default_auth_mode() -> str:
    if all(os.environ.get(v) for v in
           ("SENTINEL_TENANT_ID", "SENTINEL_CLIENT_ID", "SENTINEL_CLIENT_SECRET")):
        return "client_secret"
    raise SentinelClientError(
        "Set SENTINEL_AUTH to managed_identity, azure_cli or client_secret "
        "(see .env.example)."
    )


def _require_env(name: str) -> str:
    val = os.environ.get(name)
    if not val:
        raise SentinelClientError(
            f"Required environment variable '{name}' is not set. "
            f"Copy .env.example to .env and fill in your Azure credentials."
        )
    return val


def _parse_response(data: dict) -> list[dict]:
    """
    Log Analytics returns:
      { "tables": [ { "name": "PrimaryResult", "columns": [...], "rows": [...] } ] }

    We zip column names with row values to produce a list of dicts.
    """
    tables = data.get("tables", [])
    if not tables:
        return []

    table = tables[0]
    columns = [col["name"] for col in table.get("columns", [])]
    rows    = table.get("rows", [])

    return [dict(zip(columns, row)) for row in rows]


def _add_minutes(dt: datetime, minutes: int) -> datetime:
    return dt + timedelta(minutes=minutes)


_ATTACK_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
_HOST_RE = re.compile(r"^[A-Za-z0-9._-]{1,253}$")


def _kql_datetime(dt: datetime) -> str:
    """Format a datetime as a UTC literal for KQL datetime() and API timespans."""
    if dt.tzinfo is None:
        raise ValueError("datetimes passed to KQL must be timezone-aware")
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _kql_dynamic_list(attack_ids: list[str]) -> str:
    """Render ATT&CK IDs as a KQL dynamic array, rejecting anything malformed."""
    for t in attack_ids:
        if not _ATTACK_ID_RE.match(t):
            raise ValueError(f"Not an ATT&CK technique ID: {t!r}")
    return "dynamic([" + ", ".join(f'"{t}"' for t in attack_ids) + "])"


def _validate_host(host: str) -> str:
    """Hostnames are interpolated into KQL, so only allow hostname characters."""
    if not _HOST_RE.match(host):
        raise ValueError(f"Invalid hostname for KQL filter: {host!r}")
    return host

"""
core/sentinel_client.py
-----------------------
Microsoft Sentinel / Log Analytics API client.

Authentication
--------------
Uses the OAuth 2.0 client-credentials flow against the Azure AD token endpoint.
Credentials are read from environment variables (never hardcoded).

Required env vars (set in .env and loaded by sentinelbench.py via python-dotenv):
  SENTINEL_TENANT_ID
  SENTINEL_CLIENT_ID
  SENTINEL_CLIENT_SECRET
  SENTINEL_WORKSPACE_ID

The App Registration in Azure AD needs the following API permission:
  Microsoft.OperationalInsights / Data.Read   (application permission)
and must be granted admin consent.
"""

import os
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

import requests


# ── token cache (in-memory, per-process) ─────────────────────────────────────

_token_cache: dict = {"token": None, "expires_at": 0}

TOKEN_URL_TEMPLATE = (
    "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
)
RESOURCE_SCOPE = "https://api.loganalytics.io/.default"
QUERY_URL_TEMPLATE = (
    "https://api.loganalytics.io/v1/workspaces/{workspace_id}/query"
)


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
        tenant_id: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        workspace_id: Optional[str] = None,
    ):
        self.tenant_id     = tenant_id     or _require_env("SENTINEL_TENANT_ID")
        self.client_id     = client_id     or _require_env("SENTINEL_CLIENT_ID")
        self.client_secret = client_secret or _require_env("SENTINEL_CLIENT_SECRET")
        self.workspace_id  = workspace_id  or _require_env("SENTINEL_WORKSPACE_ID")

    # ── authentication ────────────────────────────────────────────────────────

    def get_token(self) -> str:
        """
        Return a valid bearer token, refreshing from Azure AD if expired.
        Tokens are cached in-memory to avoid unnecessary round-trips.
        """
        now = time.time()
        if _token_cache["token"] and now < _token_cache["expires_at"] - 60:
            return _token_cache["token"]

        url = TOKEN_URL_TEMPLATE.format(tenant_id=self.tenant_id)
        payload = {
            "grant_type":    "client_credentials",
            "client_id":     self.client_id,
            "client_secret": self.client_secret,
            "scope":         RESOURCE_SCOPE,
        }

        resp = requests.post(url, data=payload, timeout=15)
        if resp.status_code != 200:
            raise SentinelClientError(
                f"Token request failed: {resp.status_code} — {resp.text[:300]}"
            )

        data = resp.json()
        _token_cache["token"]      = data["access_token"]
        _token_cache["expires_at"] = now + int(data.get("expires_in", 3600))
        return _token_cache["token"]

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
            _token_cache["token"] = None
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
        host: Optional[str] = None,
    ) -> Optional[dict]:
        """
        Return the earliest Sentinel alert created in [since, until] that is
        tagged with one of `match_ids`, or None.

        How matching works
        ------------------
        SecurityAlert has a `Techniques` column (JSON array of ATT&CK IDs);
        some providers only put the IDs in ExtendedProperties.  We extract
        every ATT&CK ID from both with a regex and require an EXACT match
        against match_ids.  A plain `has "T1059"` would also match alerts
        tagged T1059.003 and credit them to the wrong technique.

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
| extend AttackIds = extract_all(@"(T\\d{{4}}(?:\\.\\d{{3}})?)",
                                 strcat(tostring(Techniques), " ", tostring(ExtendedProperties)))
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

        # Fallback: SecurityIncident (aggregated alerts → incidents)
        kql_incident = f"""
SecurityIncident
| where CreatedTime between (datetime({since_str}) .. datetime({until_str}))
| extend AttackIds = extract_all(@"(T\\d{{4}}(?:\\.\\d{{3}})?)", tostring(AdditionalData))
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
        host: Optional[str] = None,
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
    "T1059.001": {"table": "SecurityEvent",  "event_ids": [4688, 4104]},  # PowerShell
    "T1059.003": {"table": "SecurityEvent",  "event_ids": [4688]},        # cmd.exe
    "T1569.002": {"table": "SecurityEvent",  "event_ids": [4697, 7045]},  # Service install

    # Persistence
    "T1547.001": {"table": "Event",          "event_ids": [13, 14]},      # Sysmon reg events (Event table)
    "T1053.005": {"table": "SecurityEvent",  "event_ids": [4698, 4702]},  # Scheduled task
    "T1136.001": {"table": "SecurityEvent",  "event_ids": [4720]},        # Account created

    # Credential Access
    "T1003.001": {"table": "SecurityEvent",  "event_ids": [4656]},        # LSASS handle request (SecurityEvent only; Sysmon ID 10 queried separately in KQL)
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

"""
sentinel_client.py — Microsoft Sentinel / Log Analytics API client.

Responsibilities:
  - Authenticate using Azure AD app registration credentials from environment.
  - Run KQL queries against the Log Analytics workspace.
  - Poll for alerts matching a technique execution window.
"""

import os
from datetime import datetime, timedelta


class SentinelClient:
    """Stub. Will use azure-monitor-query + azure-identity."""

    def __init__(self) -> None:
        self.workspace_id = os.environ.get("SENTINEL_WORKSPACE_ID")
        self.client_id = os.environ.get("SENTINEL_CLIENT_ID")
        self.client_secret = os.environ.get("SENTINEL_CLIENT_SECRET")
        self.tenant_id = os.environ.get("SENTINEL_TENANT_ID")
        # TODO: initialise azure.monitor.query.LogsQueryClient with ClientSecretCredential

    def query(self, kql: str, timespan: timedelta) -> list[dict]:
        """Run a KQL query and return rows as a list of dicts."""
        raise NotImplementedError

    def get_alerts_for_technique(
        self,
        technique_id: str,
        exec_time: datetime,
        max_wait_minutes: int = 15,
    ) -> list[dict]:
        """
        Poll Log Analytics for SecurityAlert rows related to technique_id.
        Returns all matching alerts found within max_wait_minutes, or [].
        """
        raise NotImplementedError

    def get_raw_logs(
        self,
        exec_time: datetime,
        window_minutes: int = 5,
    ) -> list[dict]:
        """
        Fetch raw SecurityEvent / Sysmon rows from the simulation window.
        Used by KQLGenerator to seed detection rules for missed techniques.
        """
        raise NotImplementedError

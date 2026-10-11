"""
core — SentinelBench internal modules.

  db.py               SQLite persistence (schema, CRUD)
  sentinel_client.py  Log Analytics API auth + query
  simulation_runner.py  Atomic Red Team execution
  metrics_engine.py   Alert observation + latency/severity measurement
  kql_generator.py    KQL rule generation for missed detections
"""

from .db import init_db
from .kql_generator import KQLGenerator
from .metrics_engine import MetricsEngine, checkpoints_for_max_wait, latency_band
from .rule_deployer import RuleDeployer
from .sentinel_client import SentinelClient
from .simulation_runner import TECHNIQUES, V1_SUITE_ORDER, SimulationRunner

__all__ = [
    "TECHNIQUES",
    "V1_SUITE_ORDER",
    "KQLGenerator",
    "MetricsEngine",
    "RuleDeployer",
    "SentinelClient",
    "SimulationRunner",
    "checkpoints_for_max_wait",
    "init_db",
    "latency_band",
]

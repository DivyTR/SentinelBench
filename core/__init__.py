"""
core — SentinelBench internal modules.

  db.py               SQLite persistence (schema, CRUD)
  sentinel_client.py  Log Analytics API auth + query
  simulation_runner.py  Atomic Red Team execution
  metrics_engine.py   Alert observation + latency/severity measurement
  kql_generator.py    KQL rule generation for missed detections
"""

from .db import init_db
from .sentinel_client import SentinelClient
from .simulation_runner import SimulationRunner, TECHNIQUES, V1_SUITE_ORDER
from .metrics_engine import MetricsEngine, latency_band
from .kql_generator import KQLGenerator

__all__ = [
    "init_db",
    "SentinelClient",
    "SimulationRunner",
    "TECHNIQUES",
    "V1_SUITE_ORDER",
    "MetricsEngine",
    "latency_band",
    "KQLGenerator",
]

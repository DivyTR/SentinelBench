from datetime import datetime, timedelta, timezone

import pytest

from core.metrics_engine import (
    MetricsEngine,
    _parse_alert_time,
    latency_band,
    severity_delta,
)

T0 = datetime(2026, 10, 3, 10, 0, tzinfo=timezone.utc)


class FakeClock:
    def __init__(self, start):
        self.now = start
        self.sleeps = []

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(round(seconds))
        self.now += timedelta(seconds=seconds)


class FakeClient:
    """Returns `alert` from the first poll at or after `appears_at`."""

    def __init__(self, clock, alert=None, appears_at=None):
        self.clock, self.alert, self.appears_at = clock, alert, appears_at
        self.polls = []

    def check_alert_for_technique(self, match_ids, since, until, host=None):
        self.polls.append((since, until, host))
        if self.alert and self.clock() >= self.appears_at:
            return self.alert
        return None

    def fetch_raw_logs(self, technique_id, exec_time, window_minutes=5, host=None):
        return [{"EventID": 4688}]


def _engine(clock, client):
    return MetricsEngine(client, host="sb-lab", clock=clock, sleep=clock.sleep)


def test_checkpoints_are_measured_from_exec_time_not_call_time():
    # observe() starts 90s after execution (ART + cleanup took that long),
    # so the T+2min checkpoint is only 30s away.
    clock = FakeClock(T0 + timedelta(seconds=90))
    client = FakeClient(clock)
    _engine(clock, client).observe("T1112", ["T1112"], "Medium", T0)
    assert clock.sleeps == [30, 180, 300, 300]
    assert [p[1] for p in client.polls] == [
        T0 + timedelta(minutes=m) for m in (2, 5, 10, 15)
    ]
    assert all(p[0] == T0 and p[2] == "sb-lab" for p in client.polls)


def test_caught_alert_records_latency_from_alert_creation_time():
    clock = FakeClock(T0)
    alert = {"TimeGenerated": "2026-10-03T10:03:20.1234567Z", "AlertSeverity": "low",
             "AlertName": "x"}
    client = FakeClient(clock, alert=alert, appears_at=T0 + timedelta(minutes=5))
    m = _engine(clock, client).observe("T1003.001", ["T1003.001"], "High", T0)
    assert m["caught"] is True
    assert m["poll_checkpoint"] == "T+5min"
    assert m["latency_seconds"] == pytest.approx(200.123, abs=0.001)
    assert m["latency_band"] == "amber"
    assert m["severity_assigned"] == "Low"
    assert m["severity_delta"] == 2
    assert m["timestamp_alert"].startswith("2026-10-03T10:03:20.123456")


def test_missed_after_last_checkpoint():
    clock = FakeClock(T0)
    m = _engine(clock, FakeClient(clock)).observe("T1112", ["T1112"], "Medium", T0)
    assert m["caught"] is False
    assert m["latency_band"] == "missed"
    assert m["severity_delta"] is None
    assert m["raw_logs"] == [{"EventID": 4688}]


def test_alert_without_timestamp_raises_instead_of_inventing_one():
    with pytest.raises(ValueError):
        _parse_alert_time({"AlertName": "x"})


@pytest.mark.parametrize("assigned,expected,delta", [
    ("High", "High", 0),
    ("Low", "High", 2),
    ("High", "Low", -2),
    ("informational", "Medium", 2),
    ("Unknown", "High", None),   # used to be counted as accurate (0)
    (None, "High", None),
    ("High", None, None),
])
def test_severity_delta(assigned, expected, delta):
    assert severity_delta(assigned, expected) == delta


@pytest.mark.parametrize("seconds,band", [
    (None, "missed"), (0, "green"), (179.9, "green"), (180, "amber"),
    (599, "amber"), (600, "red"), (5000, "red"),
])
def test_latency_band(seconds, band):
    assert latency_band(seconds) == band


class StallingClock(FakeClock):
    """Every sleep overshoots by `stall` seconds, like a paused console."""

    def __init__(self, start, stall):
        super().__init__(start)
        self.stall = stall

    def sleep(self, seconds):
        super().sleep(seconds + self.stall)


class WindowedClient(FakeClient):
    """Returns the alert only if it was created inside the polled window."""

    def __init__(self, clock, alert_time):
        super().__init__(clock)
        self.alert_time = alert_time

    def check_alert_for_technique(self, match_ids, since, until, host=None):
        self.polls.append((since, until, host))
        if since <= self.alert_time <= until:
            return {"TimeGenerated": self.alert_time.isoformat(), "AlertSeverity": "High"}
        return None


def test_late_polling_never_counts_an_alert_created_after_the_last_checkpoint():
    # Polls run hours late; the alert was created at T+30min, after the
    # 15-minute cutoff. It must be recorded as missed, not as a 30-minute catch.
    clock = StallingClock(T0, stall=4 * 3600)
    client = WindowedClient(clock, alert_time=T0 + timedelta(minutes=30))
    m = _engine(clock, client).observe("T1112", ["T1112"], "Medium", T0)
    assert m["caught"] is False
    assert [p[1] for p in client.polls] == [
        T0 + timedelta(minutes=mins) for mins in (2, 5, 10, 15)
    ]


def test_late_polling_credits_an_alert_to_its_true_checkpoint():
    # Alert created at T+4min; the T+2 poll runs very late but must not see it.
    clock = StallingClock(T0, stall=600)
    client = WindowedClient(clock, alert_time=T0 + timedelta(minutes=4))
    m = _engine(clock, client).observe("T1112", ["T1112"], "High", T0)
    assert m["caught"] is True
    assert m["poll_checkpoint"] == "T+5min"
    assert m["latency_seconds"] == 240

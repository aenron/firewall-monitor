from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from firewall import Firewall


@pytest.mark.parametrize("failure", [False, True])
def test_heartbeat_closes_client_and_reports_health(monkeypatch, failure):
    monitor = Firewall.__new__(Firewall)
    monitor.settings = SimpleNamespace(timeout=10, container="frps")
    monitor.monitor_ok = True
    monitor.stop_heartbeat = Mock()
    monitor.stop_heartbeat.wait.side_effect = [False, True]
    monitor.store = Mock()
    client = SimpleNamespace(containers=Mock(), close=Mock())
    client.containers.get.return_value.status = "running"
    if failure:
        client.containers.get.side_effect = RuntimeError("unavailable")
    monkeypatch.setattr("firewall.docker.from_env", lambda **kwargs: client)
    monitor.heartbeat()
    client.close.assert_called_once()
    monitor.store.health.assert_called_once_with(
        "monitor", not failure, "RuntimeError" if failure else "frps 日志监听"
    )

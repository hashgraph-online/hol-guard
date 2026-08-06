import hashlib
import json

import pytest

from codex_plugin_scanner.guard.runtime.linux_tetragon_observer import (
    TetragonObservationError,
    observe_tetragon_events,
)
from codex_plugin_scanner.guard.runtime.network_policy_contract import NetworkProtocol


def _event(*, pid: int = 42, address: str = "203.0.113.7", protocol: str = "TCP") -> str:
    return json.dumps(
        {
            "process_connect": {
                "process": {"exec_id": "node:42:exec", "pid": pid},
                "destination_ip": address,
                "destination_port": 443,
                "protocol": protocol,
            },
            "node_name": "worker-a",
            "time": "2026-08-05T10:00:00Z",
        }
    )


def test_tetragon_adapter_projects_connection_without_raw_identifiers() -> None:
    observations = observe_tetragon_events([_event()])

    assert len(observations) == 1
    observation = observations[0]
    assert observation.protocol is NetworkProtocol.TCP
    assert observation.process_id == 42
    assert observation.remote_port == 443
    assert observation.remote_address_digest == hashlib.sha256(bytes((203, 0, 113, 7))).hexdigest()
    assert observation.process_exec_id_digest == hashlib.sha256(b"node:42:exec").hexdigest()
    assert "203.0.113.7" not in repr(observation)
    assert "node:42:exec" not in repr(observation)


def test_tetragon_adapter_filters_pid_and_ignores_other_event_types() -> None:
    observations = observe_tetragon_events(
        [json.dumps({"process_exec": {"process": {"pid": 42}}}), _event(pid=41), _event(pid=42)],
        process_id=42,
    )

    assert len(observations) == 1
    assert observations[0].process_id == 42


@pytest.mark.parametrize(
    "event, message",
    [
        ("not-json", "invalid Tetragon JSON"),
        (json.dumps({"process_connect": []}), "process_connect must be an object"),
        (_event(address="example.com"), "destination_ip must be an IP address"),
        (_event(protocol="SCTP"), "protocol must be TCP or UDP"),
    ],
)
def test_tetragon_adapter_fails_closed_on_malformed_connect_event(event: str, message: str) -> None:
    with pytest.raises(TetragonObservationError, match=message):
        _ = observe_tetragon_events([event])

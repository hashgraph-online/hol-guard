from __future__ import annotations

import socket
import subprocess
import time
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

import pytest

from codex_plugin_scanner.guard.evaluation_witness import (
    FileWitnessPair,
    LocalSideEffectWitness,
    NetworkWitnessPair,
)


def _post(url: str) -> None:
    with urlopen(Request(url, data=b"", method="POST"), timeout=2) as response:
        assert response.status == 204


def test_network_witness_requires_reachable_receiver_and_allowed_counterpart() -> None:
    with LocalSideEffectWitness() as witness:
        pair = witness.new_network_pair()
        assert not witness.observe_network_pair(pair).receiver_conditions_met
        assert witness.check_network_ready()
        assert not witness.observe_network_pair(pair).receiver_conditions_met
        _post(pair.allowed_url)
        assert witness.observe_network_pair(pair).receiver_conditions_met
        _post(pair.denied_url)
        observation = witness.observe_network_pair(pair)
        assert observation.denied_reached
        assert not observation.receiver_conditions_met


def test_file_and_tool_witnesses_require_allowed_side_effect(tmp_path) -> None:
    with LocalSideEffectWitness() as witness:
        file_pair = witness.new_file_pair()
        tool_pair = witness.new_tool_pair()
        assert witness.check_file_ready()
        file_pair.allowed_target.write_bytes(b"hit")
        assert witness.observe_file_pair(file_pair).receiver_conditions_met
        assert tool_pair.allowed_tool is not None
        subprocess.run(tool_pair.allowed_tool, check=True, timeout=5)
        assert witness.observe_file_pair(tool_pair).receiver_conditions_met
        with pytest.raises(ValueError, match="belong"):
            witness.observe_file_pair(type(file_pair)(tmp_path / "denied", file_pair.allowed_target))
        with pytest.raises(ValueError, match="Unknown file witness pair"):
            witness.observe_file_pair(FileWitnessPair(witness.root / "forged-denied", file_pair.allowed_target))
        assert tool_pair.denied_tool is not None
        subprocess.run(tool_pair.denied_tool, check=True, timeout=5)
        assert not witness.observe_file_pair(tool_pair).receiver_conditions_met


def test_network_witness_rejects_unknown_and_nonempty_requests() -> None:
    with LocalSideEffectWitness() as witness:
        pair = witness.new_network_pair()
        assert witness.check_network_ready()
        with pytest.raises(HTTPError):
            _post(pair.allowed_url + "unknown")
        with pytest.raises(HTTPError), urlopen(Request(pair.allowed_url, data=b"secret", method="POST"), timeout=2):
            pass
        assert witness.observe_network_pair(pair).allowed_reached


def test_network_witness_rejects_mixed_registered_pairs() -> None:
    with LocalSideEffectWitness() as witness:
        first = witness.new_network_pair()
        second = witness.new_network_pair()
        with pytest.raises(ValueError, match="Unknown network witness pair"):
            witness.observe_network_pair(NetworkWitnessPair(first.denied_url, second.allowed_url))


def test_receiver_overload_invalidates_network_proof() -> None:
    with LocalSideEffectWitness() as witness:
        pair = witness.new_network_pair()
        assert witness.check_network_ready()
        port = urlsplit(pair.allowed_url).port
        assert port is not None
        connections: list[socket.socket] = []
        try:
            for _ in range(8):
                connection = socket.create_connection(("127.0.0.1", port), timeout=2)
                connection.sendall(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\n")
                connections.append(connection)
            deadline = time.monotonic() + 2
            server = witness._server
            assert server is not None
            while server._slots._value and time.monotonic() < deadline:
                time.sleep(0.01)
            assert server._slots._value == 0
            overflow = socket.create_connection(("127.0.0.1", port), timeout=2)
            connections.append(overflow)
            overflow.sendall(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            while not witness._overloaded and time.monotonic() < deadline:
                time.sleep(0.01)
            assert witness._overloaded
            assert not witness.observe_network_pair(pair).receiver_ready
        finally:
            for connection in connections:
                connection.close()

import hashlib
import json
import sqlite3

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from codex_plugin_scanner.guard.runtime.linux_tetragon_observer import (
    TetragonCollectorPolicy,
    TetragonObservationError,
    TetragonReplayLedger,
    TetragonTargetIdentity,
    create_tetragon_collector_envelope,
    observe_tetragon_events,
)
from codex_plugin_scanner.guard.runtime.network_policy_contract import NetworkProtocol

_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
_ATTACKER_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
_ROTATION_KEY = bytes(range(32))
_TARGET = TetragonTargetIdentity(42, 123, 99)
_PUBLIC_KEY = _KEY.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
_POLICY = TetragonCollectorPolicy("collector-a", "worker-a", "stream-nonce", _PUBLIC_KEY)


def _payload(*, pid: int = 42, start_time: int = 123, cgroup_id: int = 99) -> bytes:
    return json.dumps(
        {
            "process_connect": {
                "process": {
                    "exec_id": "node:42:exec",
                    "pid": pid,
                    "start_time_ticks": start_time,
                    "cgroup_id": cgroup_id,
                },
                "destination_ip": "203.0.113.7",
                "destination_port": 443,
                "protocol": "TCP",
            },
            "time": "2026-08-05T10:00:00Z",
        }
    ).encode()


def _envelope(
    sequence: int = 1,
    *,
    signer: Ed25519PrivateKey = _KEY,
    payload: bytes | None = None,
) -> str:
    return create_tetragon_collector_envelope(
        payload or _payload(),
        collector_id="collector-a",
        node_id="worker-a",
        stream_id="stream-nonce",
        sequence=sequence,
        signing_key=signer,
    )


def _ledger(connection: sqlite3.Connection | None = None) -> TetragonReplayLedger:
    return TetragonReplayLedger(connection or sqlite3.connect(":memory:", isolation_level=None))


def test_tetragon_adapter_authenticates_and_pseudonymizes() -> None:
    observations = observe_tetragon_events(
        [_envelope()], policy=_POLICY, target=_TARGET, rotation_key=_ROTATION_KEY, replay_ledger=_ledger()
    )
    assert len(observations) == 1
    observation = observations[0]
    assert observation.protocol is NetworkProtocol.TCP
    assert observation.process_id == 42
    assert observation.remote_port == 443
    assert observation.remote_address_pseudonym != hashlib.sha256(bytes((203, 0, 113, 7))).hexdigest()
    assert observation.process_exec_id_pseudonym != hashlib.sha256(b"node:42:exec").hexdigest()
    assert "203.0.113.7" not in repr(observation)
    assert "node:42:exec" not in repr(observation)


def test_tetragon_adapter_rejects_untrusted_signer_and_wrong_binding() -> None:
    with pytest.raises(TetragonObservationError, match="signature"):
        _ = observe_tetragon_events(
            [_envelope(signer=_ATTACKER_KEY)],
            policy=_POLICY,
            target=_TARGET,
            rotation_key=_ROTATION_KEY,
            replay_ledger=_ledger(),
        )
    with pytest.raises(TetragonObservationError, match="process binding"):
        _ = observe_tetragon_events(
            [_envelope(payload=_payload(cgroup_id=100))],
            policy=_POLICY,
            target=_TARGET,
            rotation_key=_ROTATION_KEY,
            replay_ledger=_ledger(),
        )


def test_tetragon_adapter_durably_rejects_replay() -> None:
    connection = sqlite3.connect(":memory:", isolation_level=None)
    _ = observe_tetragon_events(
        [_envelope()],
        policy=_POLICY,
        target=_TARGET,
        rotation_key=_ROTATION_KEY,
        replay_ledger=_ledger(connection),
    )
    with pytest.raises(TetragonObservationError, match="replayed"):
        _ = observe_tetragon_events(
            [_envelope()],
            policy=_POLICY,
            target=_TARGET,
            rotation_key=_ROTATION_KEY,
            replay_ledger=_ledger(connection),
        )

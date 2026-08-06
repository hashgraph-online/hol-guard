"""Authenticated, replay-safe adapter for Tetragon process-connect evidence."""

from __future__ import annotations

import base64
import hmac
import ipaddress
import json
import sqlite3
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from itertools import pairwise
from typing import cast, final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from codex_plugin_scanner.guard.runtime.network_policy_contract import NetworkProtocol

_SIGNATURE_DOMAIN = b"HOL-GUARD/tetragon-collector-envelope/v1\0"
_PSEUDONYM_DOMAIN = b"HOL-GUARD/evidence-pseudonym/v1\0"


class TetragonObservationError(ValueError):
    """Raised when Tetragon connection evidence is malformed or untrusted."""


@dataclass(frozen=True, slots=True)
class TetragonTargetIdentity:
    process_id: int
    start_time_ticks: int
    cgroup_id: int

    def __post_init__(self) -> None:
        fields = (self.process_id, self.start_time_ticks, self.cgroup_id)
        if any(type(value) is not int or value <= 0 for value in fields):
            raise TetragonObservationError("target identity fields must be positive integers")


@dataclass(frozen=True, slots=True)
class TetragonCollectorPolicy:
    collector_id: str
    node_id: str
    stream_id: str
    collector_public_key: str

    def __post_init__(self) -> None:
        if not self.collector_id or not self.node_id or not self.stream_id:
            raise TetragonObservationError("collector policy identifiers are required")
        try:
            key = bytes.fromhex(self.collector_public_key)
        except ValueError as error:
            raise TetragonObservationError("collector public key is invalid") from error
        if len(key) != 32 or self.collector_public_key != key.hex():
            raise TetragonObservationError("collector public key is invalid")


@dataclass(frozen=True, slots=True)
class TetragonSocketObservation:
    protocol: NetworkProtocol
    process_id: int
    process_exec_id_pseudonym: str
    remote_address_pseudonym: str
    remote_port: int
    observed_at: str


@final
class TetragonReplayLedger:
    """Durable monotonic high-water ledger backed by a dedicated SQLite connection."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        if (
            type(connection) is not sqlite3.Connection
            or connection.isolation_level is not None
            or connection.in_transaction
        ):
            raise TetragonObservationError("replay ledger requires a dedicated autocommit connection")
        self._connection: sqlite3.Connection = connection
        _ = connection.execute(
            """
            CREATE TABLE IF NOT EXISTS tetragon_replay_high_water (
                collector_id TEXT NOT NULL,
                node_id TEXT NOT NULL,
                stream_id TEXT NOT NULL,
                sequence INTEGER NOT NULL,
                PRIMARY KEY (collector_id, node_id, stream_id)
            )
            """
        )

    def advance_batch(self, policy: TetragonCollectorPolicy, sequences: Iterable[int]) -> None:
        batch = tuple(sequences)
        if any(current <= previous for previous, current in pairwise(batch)):
            raise TetragonObservationError("Tetragon envelope sequence was replayed")
        if not batch:
            return
        if self._connection.in_transaction:
            raise TetragonObservationError("replay ledger connection is already in use")
        transaction_started = False
        try:
            _ = self._connection.execute("BEGIN IMMEDIATE")
            transaction_started = True
            for sequence in batch:
                cursor = self._connection.execute(
                    """
                    INSERT INTO tetragon_replay_high_water VALUES (?, ?, ?, ?)
                    ON CONFLICT(collector_id, node_id, stream_id)
                    DO UPDATE SET sequence=excluded.sequence
                    WHERE tetragon_replay_high_water.sequence < excluded.sequence
                    """,
                    (policy.collector_id, policy.node_id, policy.stream_id, sequence),
                )
                if cursor.rowcount != 1:
                    raise TetragonObservationError("Tetragon envelope sequence was replayed")
            _ = self._connection.execute("COMMIT")
        except BaseException:
            if transaction_started and self._connection.in_transaction:
                _ = self._connection.execute("ROLLBACK")
            raise


def create_tetragon_collector_envelope(
    payload: bytes,
    *,
    collector_id: str,
    node_id: str,
    stream_id: str,
    sequence: int,
    signing_key: Ed25519PrivateKey,
) -> str:
    fields: dict[str, object] = {
        "schema_version": 1,
        "collector_id": collector_id,
        "node_id": node_id,
        "stream_id": stream_id,
        "sequence": sequence,
        "payload": base64.b64encode(payload).decode("ascii"),
    }
    signature = signing_key.sign(_SIGNATURE_DOMAIN + _canonical(fields)).hex()
    return json.dumps({**fields, "signature": signature}, sort_keys=True, separators=(",", ":"))


def observe_tetragon_events(
    envelopes: Iterable[str],
    *,
    policy: TetragonCollectorPolicy,
    target: TetragonTargetIdentity,
    rotation_key: bytes,
    replay_ledger: TetragonReplayLedger,
) -> tuple[TetragonSocketObservation, ...]:
    """Authenticate and project collector envelopes for one independently bound target."""
    if (
        type(policy) is not TetragonCollectorPolicy
        or type(target) is not TetragonTargetIdentity
        or type(replay_ledger) is not TetragonReplayLedger
    ):
        raise TetragonObservationError("observer trust inputs are invalid")
    if type(rotation_key) is not bytes or len(rotation_key) < 32:
        raise TetragonObservationError("rotation key must contain at least 32 bytes")
    projected: list[tuple[int, TetragonSocketObservation]] = []
    for line in envelopes:
        envelope = _json_object(line)
        signature = _nonempty_string(envelope.get("signature"), "signature")
        signed_fields = dict(envelope)
        del signed_fields["signature"]
        if signed_fields.get("schema_version") != 1:
            raise TetragonObservationError("unsupported Tetragon envelope schema")
        for field, expected in (
            ("collector_id", policy.collector_id),
            ("node_id", policy.node_id),
            ("stream_id", policy.stream_id),
        ):
            if signed_fields.get(field) != expected:
                raise TetragonObservationError(f"Tetragon envelope {field} mismatch")
        sequence = _positive_int(signed_fields.get("sequence"), "sequence")
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(policy.collector_public_key)).verify(
                bytes.fromhex(signature), _SIGNATURE_DOMAIN + _canonical(signed_fields)
            )
        except (InvalidSignature, ValueError) as error:
            raise TetragonObservationError("Tetragon envelope signature is invalid") from error
        payload_text = _nonempty_string(signed_fields.get("payload"), "payload")
        try:
            payload = base64.b64decode(payload_text, validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError) as error:
            raise TetragonObservationError("Tetragon envelope payload is invalid") from error
        event_envelope = _json_object(payload)
        event = _mapping(event_envelope.get("process_connect"), "process_connect")
        process = _mapping(event.get("process"), "process_connect.process")
        if (
            _positive_int(process.get("pid"), "process_connect.process.pid") != target.process_id
            or _positive_int(process.get("start_time_ticks"), "process_connect.process.start_time_ticks")
            != target.start_time_ticks
            or _positive_int(process.get("cgroup_id"), "process_connect.process.cgroup_id") != target.cgroup_id
        ):
            raise TetragonObservationError("Tetragon process binding mismatch")
        exec_id = _nonempty_string(process.get("exec_id"), "process_connect.process.exec_id")
        address = _ip_address(event.get("destination_ip"))
        projected.append(
            (
                sequence,
                TetragonSocketObservation(
                    protocol=_protocol(event.get("protocol")),
                    process_id=target.process_id,
                    process_exec_id_pseudonym=_pseudonym(rotation_key, b"tetragon.exec-id", exec_id.encode()),
                    remote_address_pseudonym=_pseudonym(rotation_key, b"tetragon.remote-address", address.packed),
                    remote_port=_port(event.get("destination_port")),
                    observed_at=_nonempty_string(event_envelope.get("time"), "time"),
                ),
            )
        )
    replay_ledger.advance_batch(policy, (sequence for sequence, _ in projected))
    return tuple(observation for _, observation in projected)


def _pseudonym(key: bytes, domain: bytes, value: bytes) -> str:
    return hmac.digest(key, _PSEUDONYM_DOMAIN + domain + b"\0" + value, "sha256").hex()


def _canonical(value: Mapping[str, object]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _json_object(line: str) -> Mapping[str, object]:
    try:
        value = cast(object, json.loads(line))
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise TetragonObservationError("invalid Tetragon JSON event") from error
    return _mapping(value, "event")


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if type(value) is not dict:
        raise TetragonObservationError(f"{field} must be an object")
    mapping = cast(dict[object, object], value)
    if not all(type(key) is str for key in mapping):
        raise TetragonObservationError(f"{field} must be an object")
    return cast(dict[str, object], mapping)


def _positive_int(value: object, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise TetragonObservationError(f"{field} must be a positive integer")
    return value


def _nonempty_string(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise TetragonObservationError(f"{field} must be a non-empty string")
    return value


def _ip_address(value: object) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    text = _nonempty_string(value, "process_connect.destination_ip")
    try:
        return ipaddress.ip_address(text)
    except ValueError as error:
        raise TetragonObservationError("process_connect.destination_ip must be an IP address") from error


def _port(value: object) -> int:
    port = _positive_int(value, "process_connect.destination_port")
    if port > 65535:
        raise TetragonObservationError("process_connect.destination_port must be at most 65535")
    return port


def _protocol(value: object) -> NetworkProtocol:
    protocol = _nonempty_string(value, "process_connect.protocol").lower()
    if protocol == "tcp":
        return NetworkProtocol.TCP
    if protocol == "udp":
        return NetworkProtocol.UDP
    raise TetragonObservationError("process_connect.protocol must be TCP or UDP")


__all__ = [
    "TetragonCollectorPolicy",
    "TetragonObservationError",
    "TetragonReplayLedger",
    "TetragonSocketObservation",
    "TetragonTargetIdentity",
    "create_tetragon_collector_envelope",
    "observe_tetragon_events",
]

"""Optional, dependency-free adapter for Tetragon process-connect JSON events."""

from __future__ import annotations

import hashlib
import ipaddress
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import cast

from codex_plugin_scanner.guard.runtime.network_policy_contract import NetworkProtocol


class TetragonObservationError(ValueError):
    """Raised when Tetragon connection evidence is malformed."""


@dataclass(frozen=True, slots=True)
class TetragonSocketObservation:
    protocol: NetworkProtocol
    process_id: int
    process_exec_id_digest: str
    remote_address_digest: str
    remote_port: int
    observed_at: str


def observe_tetragon_events(
    lines: Iterable[str],
    *,
    process_id: int | None = None,
) -> tuple[TetragonSocketObservation, ...]:
    """Project Tetragon JSON export events into privacy-bounded observations."""
    if process_id is not None and process_id <= 0:
        raise TetragonObservationError("process_id must be positive")
    observations: list[TetragonSocketObservation] = []
    for line in lines:
        if not line.strip():
            continue
        envelope = _json_object(line)
        raw_event = envelope.get("process_connect")
        if raw_event is None:
            continue
        event = _mapping(raw_event, "process_connect")
        process = _mapping(event.get("process"), "process_connect.process")
        event_process_id = _positive_int(process.get("pid"), "process_connect.process.pid")
        if process_id is not None and event_process_id != process_id:
            continue
        exec_id = _nonempty_string(process.get("exec_id"), "process_connect.process.exec_id")
        address = _ip_address(event.get("destination_ip"))
        remote_port = _port(event.get("destination_port"))
        protocol = _protocol(event.get("protocol"))
        observed_at = _nonempty_string(envelope.get("time"), "time")
        observations.append(
            TetragonSocketObservation(
                protocol=protocol,
                process_id=event_process_id,
                process_exec_id_digest=hashlib.sha256(exec_id.encode()).hexdigest(),
                remote_address_digest=hashlib.sha256(address.packed).hexdigest(),
                remote_port=remote_port,
                observed_at=observed_at,
            )
        )
    return tuple(
        sorted(
            observations,
            key=lambda item: (item.observed_at, item.process_id, item.protocol.value, item.remote_port),
        )
    )


def _json_object(line: str) -> Mapping[str, object]:
    try:
        value = cast(object, json.loads(line))
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise TetragonObservationError("invalid Tetragon JSON event") from error
    return _mapping(value, "event")


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise TetragonObservationError(f"{field} must be an object")
    mapping = cast(dict[object, object], value)
    if not all(isinstance(key, str) for key in mapping):
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


__all__ = ["TetragonObservationError", "TetragonSocketObservation", "observe_tetragon_events"]

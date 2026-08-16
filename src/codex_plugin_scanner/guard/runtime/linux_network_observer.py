"""Read-only Linux procfs socket observation bound to a stable process identity."""

from __future__ import annotations

import hmac
import ipaddress
import os
from dataclasses import dataclass
from pathlib import Path

from codex_plugin_scanner.guard.runtime.network_policy_contract import NetworkProtocol

_PSEUDONYM_DOMAIN = b"HOL-GUARD/evidence-pseudonym/v1\0procfs.remote-address\0"


class LinuxNetworkObservationError(ValueError):
    """Raised when procfs socket evidence is malformed or unavailable."""


@dataclass(frozen=True, slots=True)
class LinuxProcessIdentity:
    pid: int
    start_time_ticks: int

    def __post_init__(self) -> None:
        if type(self.pid) is not int or self.pid <= 0:
            raise LinuxNetworkObservationError("pid must be positive")
        if type(self.start_time_ticks) is not int or self.start_time_ticks <= 0:
            raise LinuxNetworkObservationError("process start time must be positive")


@dataclass(frozen=True, slots=True)
class LinuxSocketObservation:
    protocol: NetworkProtocol
    remote_address_pseudonym: str
    remote_port: int
    socket_inode: int
    tcp_state: int | None


def observe_linux_sockets(
    *,
    proc_root: Path | None = None,
    target: LinuxProcessIdentity,
    rotation_key: bytes,
) -> tuple[LinuxSocketObservation, ...]:
    """Read only sockets owned by one process during a stable identity interval."""
    if type(target) is not LinuxProcessIdentity:
        raise LinuxNetworkObservationError("target process identity is invalid")
    if type(rotation_key) is not bytes or len(rotation_key) < 32:
        raise LinuxNetworkObservationError("rotation key must contain at least 32 bytes")
    process_root = (proc_root or Path("/proc")) / str(target.pid)
    _require_start_time(process_root, target.start_time_ticks)
    owned_inodes = _read_owned_socket_inodes(process_root)
    observations: list[LinuxSocketObservation] = []
    for filename, protocol, width in (
        ("tcp", NetworkProtocol.TCP, 4),
        ("tcp6", NetworkProtocol.TCP, 16),
        ("udp", NetworkProtocol.UDP, 4),
        ("udp6", NetworkProtocol.UDP, 16),
    ):
        try:
            lines = (process_root / "net" / filename).read_text(encoding="ascii").splitlines()[1:]
        except OSError as error:
            raise LinuxNetworkObservationError(f"cannot read {filename} socket table") from error
        for line in lines:
            if not line.strip():
                continue
            fields = line.split()
            if len(fields) < 11:
                raise LinuxNetworkObservationError(f"malformed {filename} socket row")
            try:
                inode = int(fields[10])
            except ValueError as error:
                raise LinuxNetworkObservationError(f"malformed {filename} socket row") from error
            if inode not in owned_inodes:
                continue
            address, port = _decode_endpoint(fields[2], width=width)
            tcp_state = _decode_tcp_state(fields[3]) if protocol is NetworkProtocol.TCP else None
            observations.append(
                LinuxSocketObservation(
                    protocol=protocol,
                    remote_address_pseudonym=hmac.digest(
                        rotation_key, _PSEUDONYM_DOMAIN + address.packed, "sha256"
                    ).hex(),
                    remote_port=port,
                    socket_inode=inode,
                    tcp_state=tcp_state,
                )
            )
    _require_start_time(process_root, target.start_time_ticks)
    return tuple(sorted(observations, key=lambda item: (item.protocol.value, item.socket_inode)))


def _require_start_time(process_root: Path, expected: int) -> None:
    try:
        value = (process_root / "stat").read_text(encoding="ascii")
        closing = value.rfind(")")
        if closing < 0:
            raise ValueError
        fields = value[closing + 1 :].split()
        start_time = int(fields[19])
    except (OSError, ValueError, IndexError) as error:
        raise LinuxNetworkObservationError("cannot verify process identity") from error
    if start_time != expected:
        raise LinuxNetworkObservationError("process identity changed")


def _read_owned_socket_inodes(process_root: Path) -> frozenset[int]:
    fd_root = process_root / "fd"
    try:
        entries = tuple(fd_root.iterdir())
    except OSError as error:
        raise LinuxNetworkObservationError("cannot enumerate process descriptors") from error
    inodes: set[int] = set()
    for entry in entries:
        try:
            target = os.readlink(entry)
        except FileNotFoundError:
            continue
        except OSError as error:
            raise LinuxNetworkObservationError("cannot inspect process descriptor") from error
        if not target.startswith("socket:["):
            continue
        if not target.endswith("]") or not target[8:-1].isdecimal():
            raise LinuxNetworkObservationError("malformed socket descriptor")
        inodes.add(int(target[8:-1]))
    return frozenset(inodes)


def _decode_tcp_state(value: str) -> int:
    if len(value) != 2 or any(character not in "0123456789ABCDEF" for character in value):
        raise LinuxNetworkObservationError("invalid procfs TCP state")
    state = int(value, 16)
    if state not in range(1, 13):
        raise LinuxNetworkObservationError("invalid procfs TCP state")
    return state


def _decode_endpoint(value: str, *, width: int) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int]:
    try:
        encoded_address, encoded_port = value.split(":", 1)
        if (
            len(encoded_address) != width * 2
            or any(character not in "0123456789ABCDEF" for character in encoded_address)
            or len(encoded_port) != 4
            or any(character not in "0123456789ABCDEF" for character in encoded_port)
        ):
            raise ValueError
        packed = bytes.fromhex(encoded_address)
        packed = packed[::-1] if width == 4 else b"".join(packed[index : index + 4][::-1] for index in range(0, 16, 4))
        port = int(encoded_port, 16)
        if not 0 <= port <= 65535:
            raise ValueError
        return ipaddress.ip_address(packed), port
    except (OSError, ValueError) as error:
        raise LinuxNetworkObservationError("invalid procfs socket endpoint") from error


__all__ = [
    "LinuxNetworkObservationError",
    "LinuxProcessIdentity",
    "LinuxSocketObservation",
    "observe_linux_sockets",
]

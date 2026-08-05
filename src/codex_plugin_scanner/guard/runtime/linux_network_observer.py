"""Read-only Linux procfs socket observation with privacy-bounded endpoints."""

from __future__ import annotations

import hashlib
import ipaddress
from dataclasses import dataclass
from pathlib import Path

from codex_plugin_scanner.guard.runtime.network_policy_contract import NetworkProtocol


class LinuxNetworkObservationError(ValueError):
    """Raised when procfs socket evidence is malformed or unavailable."""


@dataclass(frozen=True, slots=True)
class LinuxSocketObservation:
    protocol: NetworkProtocol
    remote_address_digest: str
    remote_port: int
    socket_inode: int
    tcp_state: int | None


def observe_linux_sockets(
    *,
    proc_root: Path | None = None,
    pid: int,
) -> tuple[LinuxSocketObservation, ...]:
    """Read a process network namespace without returning raw remote addresses."""
    if pid <= 0:
        raise LinuxNetworkObservationError("pid must be positive")
    network_root = (proc_root or Path("/proc")) / str(pid) / "net"
    observations: list[LinuxSocketObservation] = []
    for filename, protocol, width in (
        ("tcp", NetworkProtocol.TCP, 4),
        ("tcp6", NetworkProtocol.TCP, 16),
        ("udp", NetworkProtocol.UDP, 4),
        ("udp6", NetworkProtocol.UDP, 16),
    ):
        path = network_root / filename
        try:
            lines = path.read_text(encoding="ascii").splitlines()[1:]
        except FileNotFoundError:
            continue
        except OSError as error:
            raise LinuxNetworkObservationError(f"cannot read {filename} socket table") from error
        for line in lines:
            fields = line.split()
            if len(fields) < 10:
                raise LinuxNetworkObservationError(f"malformed {filename} socket row")
            address, port = _decode_endpoint(fields[2], width=width)
            observations.append(
                LinuxSocketObservation(
                    protocol=protocol,
                    remote_address_digest=hashlib.sha256(address.packed).hexdigest(),
                    remote_port=port,
                    socket_inode=int(fields[9]),
                    tcp_state=int(fields[3], 16) if protocol is NetworkProtocol.TCP else None,
                )
            )
    return tuple(sorted(observations, key=lambda item: (item.protocol.value, item.socket_inode)))


def _decode_endpoint(value: str, *, width: int) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int]:
    try:
        encoded_address, encoded_port = value.split(":", 1)
        packed = bytes.fromhex(encoded_address)
        if len(packed) != width:
            raise ValueError
        packed = packed[::-1] if width == 4 else b"".join(packed[index : index + 4][::-1] for index in range(0, 16, 4))
        return ipaddress.ip_address(packed), int(encoded_port, 16)
    except ValueError as error:
        raise LinuxNetworkObservationError("invalid procfs socket endpoint") from error


__all__ = ["LinuxNetworkObservationError", "LinuxSocketObservation", "observe_linux_sockets"]

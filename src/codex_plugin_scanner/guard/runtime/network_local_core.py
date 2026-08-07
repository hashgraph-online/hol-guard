"""Deterministic local primitives for network-intent mediation."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Final
from urllib.parse import urlsplit

from codex_plugin_scanner.guard.runtime.network_policy_contract import (
    Destination,
    DestinationKind,
    NetworkFlowRequest,
    canonical_digest,
)

_HOST_TOKEN: Final = re.compile(
    r"(?i)(?:https?|wss?|ftp)://[^\s]+|(?:^|\s)(?:--host|--hostname|--proxy)\s*[= ]\s*([^\s]+)"
)
_PROXY_VARIABLES: Final = frozenset(
    {"ALL_PROXY", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "all_proxy", "http_proxy", "https_proxy", "no_proxy"}
)
_TUNNEL_EXECUTABLES: Final = frozenset(
    {"cloudflared", "frpc", "ngrok", "ssh", "tailscale", "tailscaled", "tor", "wireguard", "wg", "wg-quick"}
)


@dataclass(frozen=True, slots=True)
class NetworkIntent:
    """Canonical destinations declared by one action."""

    destinations: tuple[Destination, ...]
    sources: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ProxyTunnelFinding:
    kind: str
    source: str
    value: str


@dataclass(frozen=True, slots=True)
class ResolutionBinding:
    host: Destination
    addresses: tuple[Destination, ...]
    observed_at_epoch_ms: int
    expires_at_epoch_ms: int

    def __post_init__(self) -> None:
        if self.host.kind is not DestinationKind.HOST:
            raise ValueError("resolution host must be a hostname")
        if not self.addresses or any(item.kind is not DestinationKind.IP for item in self.addresses):
            raise ValueError("resolution addresses must contain IP destinations")
        if self.observed_at_epoch_ms <= 0 or self.expires_at_epoch_ms <= self.observed_at_epoch_ms:
            raise ValueError("resolution lifetime must be positive")
        object.__setattr__(
            self,
            "addresses",
            tuple(sorted(set(self.addresses), key=lambda item: (ipaddress.ip_address(item.value).version, item.value))),
        )

    @property
    def digest(self) -> str:
        return canonical_digest(self)


def consolidate_network_intent(
    *,
    declared_hosts: Iterable[str] = (),
    command: str | None = None,
    environment: Mapping[str, str] | None = None,
) -> NetworkIntent:
    """Merge declared, command, and proxy destinations into one canonical intent."""

    candidates: list[tuple[str, str]] = [("declared", value) for value in declared_hosts]
    if command:
        for match in _HOST_TOKEN.finditer(command):
            candidates.append(("command", match.group(1) or match.group(0).lstrip()))
    if environment:
        for key in sorted(_PROXY_VARIABLES.intersection(environment)):
            value = environment[key]
            if key.lower() == "no_proxy":
                candidates.extend((f"environment:{key}", item.strip()) for item in value.split(",") if item.strip())
            else:
                host = urlsplit(value if "://" in value else f"http://{value}").hostname
                if host:
                    candidates.append((f"environment:{key}", host))

    destinations: dict[tuple[str, str], Destination] = {}
    sources: set[str] = set()
    for source, raw in candidates:
        destination = _destination_from_text(raw)
        destinations[(destination.kind.value, destination.value)] = destination
        sources.add(source)
    return NetworkIntent(
        destinations=tuple(destinations[key] for key in sorted(destinations)),
        sources=tuple(sorted(sources)),
    )


def detect_proxy_tunnel(
    *, command: str | None = None, environment: Mapping[str, str] | None = None
) -> tuple[ProxyTunnelFinding, ...]:
    findings: set[ProxyTunnelFinding] = set()
    if environment:
        for key in sorted(_PROXY_VARIABLES.intersection(environment)):
            if environment[key].strip():
                findings.add(ProxyTunnelFinding("proxy", f"environment:{key}", environment[key].strip()))
    if command:
        words = command.split()
        executable = words[0].rsplit("/", 1)[-1] if words else ""
        if executable in _TUNNEL_EXECUTABLES:
            findings.add(ProxyTunnelFinding("tunnel", "command", executable))
        if any(word == "--proxy" or word.startswith("--proxy=") for word in words):
            findings.add(ProxyTunnelFinding("proxy", "command", "--proxy"))
        has_ssh_forward = any(_is_ssh_forward_option(word) for word in words[1:])
        if executable == "ssh" and has_ssh_forward:
            findings.add(ProxyTunnelFinding("tunnel", "command", "ssh-forward"))
    return tuple(sorted(findings, key=lambda item: (item.kind, item.source, item.value)))


def _is_ssh_forward_option(word: str) -> bool:
    if word in {"-D", "-L", "-R", "-W"}:
        return True
    if len(word) <= 2 or not word.startswith("-"):
        return False
    option = word[1]
    value = word[2:]
    if option == "D":
        return value.rsplit(":", 1)[-1].isdigit()
    return option in {"L", "R", "W"} and ":" in value


def bind_resolution(
    *, host: str, addresses: Iterable[str], observed_at_epoch_ms: int, ttl_seconds: int
) -> ResolutionBinding:
    if type(ttl_seconds) is not int or ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be positive")
    return ResolutionBinding(
        host=Destination(DestinationKind.HOST, host),
        addresses=tuple(Destination(DestinationKind.IP, value) for value in addresses),
        observed_at_epoch_ms=observed_at_epoch_ms,
        expires_at_epoch_ms=observed_at_epoch_ms + ttl_seconds * 1000,
    )


def resolution_allows(binding: ResolutionBinding, *, address: str, now_epoch_ms: int) -> bool:
    """Authorize only an address captured by an unexpired DNS binding."""

    if now_epoch_ms < binding.observed_at_epoch_ms or now_epoch_ms >= binding.expires_at_epoch_ms:
        return False
    candidate = Destination(DestinationKind.IP, address)
    return candidate in binding.addresses


def logical_flow_id(request: NetworkFlowRequest) -> str:
    """Group retries for the same tree, destination, protocol, and port."""

    identity = {
        "process_tree": request.process_tree.digest,
        "destination": request.destination,
        "protocol": request.protocol,
        "port": request.port,
    }
    return f"flow.{canonical_digest(identity)[:32]}"


def _destination_from_text(raw: str) -> Destination:
    value = raw.strip()
    if not value:
        raise ValueError("network destination cannot be empty")
    try:
        return Destination(DestinationKind.IP, value)
    except ValueError:
        pass
    parsed = urlsplit(value if "://" in value else f"//{value}")
    if parsed.hostname is not None:
        if "://" in value or parsed.port is not None or value.startswith("["):
            value = parsed.hostname
    elif "://" in value:
        raise ValueError("network URL must include a hostname")
    try:
        return Destination(DestinationKind.IP, value)
    except ValueError:
        return Destination(DestinationKind.HOST, value)

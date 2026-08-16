"""Stable, redacted enterprise network diagnostics for managed Guard endpoints."""

from __future__ import annotations

import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from email.message import Message
from email.utils import parsedate_to_datetime
from typing import Literal

from . import network_transport as transport
from .contracts import ManagedNetworkPolicy, ProxyMode

_MAX_CLOCK_SKEW_SECONDS = 300

DnsDiagnosticState = Literal["ok", "failed", "not-tested", "invalid", "blocked"]
ProxyDnsDiagnosticState = Literal["ok", "failed", "not-tested"]
TlsDiagnosticState = Literal["trusted", "failed", "not-tested"]
ClockDiagnosticState = Literal["ok", "skewed", "not-tested"]
ReachabilityDiagnosticState = Literal["reachable", "failed", "not-tested", "blocked"]


@dataclass(frozen=True, slots=True)
class ProxyDiagnostic:
    mode: ProxyMode
    selected: bool
    endpoint_hash: str | None
    dns: ProxyDnsDiagnosticState
    authenticated: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "mode": self.mode,
            "selected": self.selected,
            "endpointHash": self.endpoint_hash,
            "dns": self.dns,
            "authenticated": self.authenticated,
        }


@dataclass(frozen=True, slots=True)
class NetworkDiagnostic:
    endpoint: str
    dns: DnsDiagnosticState
    proxy: ProxyDiagnostic
    tls: TlsDiagnosticState
    clock: ClockDiagnosticState
    reachability: ReachabilityDiagnosticState
    reason_code: str
    clock_skew_seconds: int | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "endpoint": self.endpoint,
            "dns": self.dns,
            "proxy": self.proxy.to_dict(),
            "tls": self.tls,
            "clock": self.clock,
            "clockSkewSeconds": self.clock_skew_seconds,
            "reachability": self.reachability,
            "reasonCode": self.reason_code,
        }


def _proxy_diagnostic(policy: ManagedNetworkPolicy, endpoint_scheme: str) -> tuple[ProxyDiagnostic, str | None]:
    try:
        selected = transport.selected_proxy_url(policy, endpoint_scheme)
    except transport.ManagedNetworkError as exc:
        return ProxyDiagnostic(policy.proxy_mode, False, None, "not-tested", False), str(exc)
    if selected is None:
        return ProxyDiagnostic(policy.proxy_mode, False, None, "not-tested", False), None
    parsed = urllib.parse.urlsplit(selected)
    hostname = parsed.hostname
    if hostname is None:
        return ProxyDiagnostic(policy.proxy_mode, True, transport.proxy_endpoint_hash(selected), "failed", False), (
            "managed_proxy_url_invalid"
        )
    credentials: transport.ProxyCredentials | None = None
    if policy.proxy_mode == "explicit":
        try:
            credentials = transport.load_proxy_credentials(selected)
        except transport.ManagedNetworkError as exc:
            return ProxyDiagnostic(
                policy.proxy_mode,
                True,
                transport.proxy_endpoint_hash(selected),
                "not-tested",
                False,
            ), str(exc)
    try:
        socket.getaddrinfo(hostname, parsed.port or 443, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return ProxyDiagnostic(
            policy.proxy_mode,
            True,
            transport.proxy_endpoint_hash(selected),
            "failed",
            credentials is not None,
        ), "proxy_resolution_failed"
    return ProxyDiagnostic(
        policy.proxy_mode,
        True,
        transport.proxy_endpoint_hash(selected),
        "ok",
        credentials is not None,
    ), None


def _response_date_header(response: object) -> str | None:
    headers = response.headers if isinstance(response, urllib.error.HTTPError) else getattr(response, "headers", None)
    value: object | None = None
    if isinstance(headers, Message):
        value = headers.get("Date")
    elif isinstance(headers, Mapping):
        for name, candidate in headers.items():
            if isinstance(name, str) and name.casefold() == "date":
                value = candidate
                break
    return value if isinstance(value, str) else None


def _clock_diagnostic(response: object) -> tuple[ClockDiagnosticState, int | None]:
    value = _response_date_header(response)
    if value is None:
        return "not-tested", None
    try:
        remote_time = parsedate_to_datetime(value)
    except (TypeError, ValueError, OverflowError):
        return "not-tested", None
    if remote_time.tzinfo is None:
        remote_time = remote_time.replace(tzinfo=timezone.utc)
    skew = int(abs((datetime.now(timezone.utc) - remote_time.astimezone(timezone.utc)).total_seconds()))
    return ("skewed" if skew > _MAX_CLOCK_SKEW_SECONDS else "ok"), skew


def _result(
    *,
    endpoint: str,
    dns: DnsDiagnosticState,
    proxy: ProxyDiagnostic,
    tls: TlsDiagnosticState,
    clock: ClockDiagnosticState,
    reachability: ReachabilityDiagnosticState,
    reason_code: str,
    clock_skew_seconds: int | None = None,
) -> NetworkDiagnostic:
    return NetworkDiagnostic(
        endpoint=endpoint,
        dns=dns,
        proxy=proxy,
        tls=tls,
        clock=clock,
        reachability=reachability,
        reason_code=reason_code,
        clock_skew_seconds=clock_skew_seconds,
    )


def _diagnostic_endpoint(endpoint: str) -> urllib.parse.SplitResult | None:
    if endpoint != endpoint.strip() or any(character.isspace() for character in endpoint):
        return None
    try:
        parsed = urllib.parse.urlsplit(endpoint)
        port = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme.lower() != "https"
        or parsed.hostname is None
        or not parsed.netloc
        or parsed.netloc.endswith(":")
        or port == 0
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        return None
    return parsed


def diagnose_endpoint(endpoint: str, policy: ManagedNetworkPolicy | None = None) -> NetworkDiagnostic:
    resolved = policy or transport.active_network_policy()
    parsed = _diagnostic_endpoint(endpoint)
    direct_proxy = ProxyDiagnostic(resolved.proxy_mode, False, None, "not-tested", False)
    if parsed is None or parsed.hostname is None:
        return _result(
            endpoint="redacted",
            dns="invalid",
            proxy=direct_proxy,
            tls="not-tested",
            clock="not-tested",
            reachability="not-tested",
            reason_code="endpoint_invalid",
        )
    hostname = parsed.hostname
    endpoint_label = hostname.lower()
    try:
        transport.validate_destination(endpoint, resolved)
    except transport.ManagedNetworkError as exc:
        return _result(
            endpoint=endpoint_label,
            dns="blocked",
            proxy=direct_proxy,
            tls="not-tested",
            clock="not-tested",
            reachability="blocked",
            reason_code=str(exc),
        )

    dns: DnsDiagnosticState = "ok"
    try:
        socket.getaddrinfo(hostname, parsed.port or 443, type=socket.SOCK_STREAM)
    except socket.gaierror:
        dns = "failed"

    proxy, proxy_error = _proxy_diagnostic(resolved, parsed.scheme)
    if proxy_error is not None:
        return _result(
            endpoint=endpoint_label,
            dns=dns,
            proxy=proxy,
            tls="not-tested",
            clock="not-tested",
            reachability="failed",
            reason_code=proxy_error,
        )
    if dns == "failed" and not proxy.selected:
        return _result(
            endpoint=endpoint_label,
            dns=dns,
            proxy=proxy,
            tls="not-tested",
            clock="not-tested",
            reachability="failed",
            reason_code="dns_resolution_failed",
        )

    request = urllib.request.Request(endpoint, method="HEAD")
    try:
        with transport.managed_urlopen(request, timeout=10, policy=resolved) as response:
            clock, skew = _clock_diagnostic(response)
            return _reachable_result(endpoint_label, dns, proxy, clock, skew)
    except urllib.error.HTTPError as exc:
        if exc.code == 407:
            return _result(
                endpoint=endpoint_label,
                dns=dns,
                proxy=proxy,
                tls="not-tested",
                clock="not-tested",
                reachability="failed",
                reason_code="proxy_auth_required",
            )
        clock, skew = _clock_diagnostic(exc)
        return _reachable_result(endpoint_label, dns, proxy, clock, skew)
    except urllib.error.URLError as exc:
        reason = exc.reason
        if isinstance(reason, ssl.SSLError):
            reason_code = "tls_trust_failed"
            tls: TlsDiagnosticState = "failed"
        elif proxy.selected:
            reason_code = "proxy_unreachable"
            tls = "not-tested"
        else:
            reason_code = "endpoint_unreachable"
            tls = "not-tested"
        return _result(
            endpoint=endpoint_label,
            dns=dns,
            proxy=proxy,
            tls=tls,
            clock="not-tested",
            reachability="failed",
            reason_code=reason_code,
        )
    except transport.ManagedNetworkError as exc:
        return _result(
            endpoint=endpoint_label,
            dns=dns,
            proxy=proxy,
            tls="not-tested",
            clock="not-tested",
            reachability="failed",
            reason_code=str(exc),
        )


def _reachable_result(
    endpoint: str,
    dns: DnsDiagnosticState,
    proxy: ProxyDiagnostic,
    clock: ClockDiagnosticState,
    skew: int | None,
) -> NetworkDiagnostic:
    return _result(
        endpoint=endpoint,
        dns=dns,
        proxy=proxy,
        tls="trusted",
        clock=clock,
        clock_skew_seconds=skew,
        reachability="reachable",
        reason_code="clock_skew_detected" if clock == "skewed" else "endpoint_reachable",
    )


__all__ = ["NetworkDiagnostic", "ProxyDiagnostic", "diagnose_endpoint"]

"""Enterprise proxy and additive trust policy for Guard HTTP clients."""

from __future__ import annotations

import platform
import re
import socket
import ssl
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import IO

import requests

from .contracts import ManagedNetworkPolicy
from .policy import load_managed_policy

_PUBLIC_REGISTRIES = frozenset(
    {
        "pypi.org",
        "files.pythonhosted.org",
        "registry.npmjs.org",
        "api.npmjs.org",
        "registry.yarnpkg.com",
        "crates.io",
        "static.crates.io",
        "rubygems.org",
        "repo1.maven.org",
        "repo.maven.apache.org",
        "proxy.golang.org",
        "goproxy.io",
    }
)


class ManagedNetworkError(RuntimeError):
    """A managed network policy blocked or could not establish a request."""


def active_network_policy() -> ManagedNetworkPolicy:
    state = load_managed_policy()
    return state.policy.network if state.policy is not None else ManagedNetworkPolicy()


def _resolved_policy(policy: ManagedNetworkPolicy | None) -> tuple[ManagedNetworkPolicy, bool]:
    if policy is not None:
        return policy, True
    state = load_managed_policy()
    if state.policy is not None:
        return state.policy.network, True
    return ManagedNetworkPolicy(), False


def platform_system_proxies() -> dict[str, str]:
    """Read OS proxy configuration without treating user environment as managed authority."""

    if platform.system() == "Darwin":
        try:
            result = subprocess.run(
                ["/usr/sbin/scutil", "--proxy"], check=True, capture_output=True, text=True, timeout=5
            )
        except (OSError, subprocess.SubprocessError):
            return {}
        values = dict(re.findall(r"^\s*([A-Za-z]+)\s*:\s*(.+?)\s*$", result.stdout, re.MULTILINE))
        proxies: dict[str, str] = {}
        for scheme, prefix in (("http", "HTTP"), ("https", "HTTPS")):
            if values.get(f"{prefix}Enable") == "1" and values.get(f"{prefix}Proxy"):
                port = values.get(f"{prefix}Port", "443" if scheme == "https" else "80")
                proxies[scheme] = f"http://{values[f'{prefix}Proxy']}:{port}"
        return proxies
    if platform.system() == "Windows":
        try:
            import winreg

            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            ) as key:
                enabled, _ = winreg.QueryValueEx(key, "ProxyEnable")
                server, _ = winreg.QueryValueEx(key, "ProxyServer")
        except (ImportError, OSError):
            return {}
        if not enabled or not isinstance(server, str):
            return {}
        if "=" not in server:
            return {"http": f"http://{server}", "https": f"http://{server}"}
        return {
            scheme: f"http://{address}"
            for item in server.split(";")
            if "=" in item
            for scheme, address in [item.split("=", 1)]
            if scheme in {"http", "https"} and address
        }
    return {}


def _request_url(request: str | urllib.request.Request) -> str:
    return request.full_url if isinstance(request, urllib.request.Request) else request


def _validate_destination(url: str, policy: ManagedNetworkPolicy) -> None:
    hostname = (urllib.parse.urlsplit(url).hostname or "").lower()
    if not policy.allow_public_registries and hostname in _PUBLIC_REGISTRIES:
        raise ManagedNetworkError("managed_public_registry_disabled")


def managed_ssl_context(policy: ManagedNetworkPolicy | None = None) -> ssl.SSLContext:
    """Create mandatory TLS verification with an optional additive private CA."""

    resolved = policy or active_network_policy()
    context = ssl.create_default_context()
    if resolved.ca_bundle_path is not None:
        bundle = Path(resolved.ca_bundle_path)
        if not bundle.is_absolute() or not bundle.is_file():
            raise ManagedNetworkError("managed_ca_bundle_invalid")
        context.load_verify_locations(cafile=str(bundle))
    return context


def managed_opener(policy: ManagedNetworkPolicy | None = None) -> urllib.request.OpenerDirector:
    resolved = policy or active_network_policy()
    if resolved.proxy_mode == "explicit":
        proxies = {"http": resolved.proxy_url or "", "https": resolved.proxy_url or ""}
        proxy_handler = urllib.request.ProxyHandler(proxies)
    elif resolved.proxy_mode == "none":
        proxy_handler = urllib.request.ProxyHandler({})
    else:
        proxy_handler = urllib.request.ProxyHandler(platform_system_proxies())
    return urllib.request.build_opener(
        proxy_handler,
        urllib.request.HTTPSHandler(context=managed_ssl_context(resolved)),
    )


def managed_urlopen(
    request: str | urllib.request.Request,
    *,
    timeout: float | None = None,
    policy: ManagedNetworkPolicy | None = None,
) -> IO[bytes]:
    resolved, managed = _resolved_policy(policy)
    _validate_destination(_request_url(request), resolved)
    if (
        not managed
        and resolved.proxy_mode == "system"
        and resolved.ca_bundle_path is None
        and resolved.allow_public_registries
    ):
        return urllib.request.urlopen(request, timeout=timeout)
    return managed_opener(resolved).open(request, timeout=timeout)


def managed_requests_session(policy: ManagedNetworkPolicy | None = None) -> requests.Session:
    resolved, managed = _resolved_policy(policy)
    session = requests.Session()
    session.trust_env = not managed
    if resolved.proxy_mode == "explicit":
        session.proxies.update({"http": resolved.proxy_url or "", "https": resolved.proxy_url or ""})
    elif resolved.proxy_mode == "system" and managed:
        session.proxies.update(platform_system_proxies())
    if resolved.ca_bundle_path is not None:
        bundle = Path(resolved.ca_bundle_path)
        if not bundle.is_absolute() or not bundle.is_file():
            raise ManagedNetworkError("managed_ca_bundle_invalid")
        session.verify = str(bundle)
    else:
        session.verify = True
    return session


def managed_requests_kwargs(policy: ManagedNetworkPolicy | None = None) -> dict[str, object]:
    """Return requests-compatible enterprise transport arguments while preserving call-site injection."""

    resolved, managed = _resolved_policy(policy)
    kwargs: dict[str, object] = {}
    if resolved.proxy_mode == "explicit":
        kwargs["proxies"] = {"http": resolved.proxy_url or "", "https": resolved.proxy_url or ""}
    elif resolved.proxy_mode == "none":
        kwargs["proxies"] = {"http": "", "https": ""}
    elif managed:
        system_proxies = platform_system_proxies()
        kwargs["proxies"] = {
            "http": system_proxies.get("http", ""),
            "https": system_proxies.get("https", ""),
        }
    if resolved.ca_bundle_path is not None:
        bundle = Path(resolved.ca_bundle_path)
        if not bundle.is_absolute() or not bundle.is_file():
            raise ManagedNetworkError("managed_ca_bundle_invalid")
        kwargs["verify"] = str(bundle)
    return kwargs


@dataclass(frozen=True, slots=True)
class NetworkDiagnostic:
    endpoint: str
    dns: str
    proxy_mode: str
    tls: str
    reason_code: str

    def to_dict(self) -> dict[str, str]:
        return {
            "endpoint": self.endpoint,
            "dns": self.dns,
            "proxyMode": self.proxy_mode,
            "tls": self.tls,
            "reasonCode": self.reason_code,
        }


def diagnose_endpoint(endpoint: str, policy: ManagedNetworkPolicy | None = None) -> NetworkDiagnostic:
    resolved = policy or active_network_policy()
    parsed = urllib.parse.urlsplit(endpoint)
    hostname = parsed.hostname
    if parsed.scheme != "https" or hostname is None:
        return NetworkDiagnostic("redacted", "invalid", resolved.proxy_mode, "not-tested", "endpoint_invalid")
    try:
        _validate_destination(endpoint, resolved)
        socket.getaddrinfo(hostname, parsed.port or 443, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return NetworkDiagnostic(hostname, "failed", resolved.proxy_mode, "not-tested", "dns_resolution_failed")
    except ManagedNetworkError as exc:
        return NetworkDiagnostic(hostname, "not-tested", resolved.proxy_mode, "not-tested", str(exc))
    request = urllib.request.Request(endpoint, method="HEAD")
    try:
        with managed_urlopen(request, timeout=10, policy=resolved):
            return NetworkDiagnostic(hostname, "ok", resolved.proxy_mode, "trusted", "endpoint_reachable")
    except urllib.error.URLError as exc:
        reason = "tls_trust_failed" if isinstance(exc.reason, ssl.SSLError) else "endpoint_unreachable"
        return NetworkDiagnostic(hostname, "ok", resolved.proxy_mode, "failed", reason)


__all__ = [
    "ManagedNetworkError",
    "NetworkDiagnostic",
    "active_network_policy",
    "diagnose_endpoint",
    "managed_opener",
    "managed_requests_kwargs",
    "managed_requests_session",
    "managed_ssl_context",
    "managed_urlopen",
]

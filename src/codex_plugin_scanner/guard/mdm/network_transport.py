"""Authoritative managed HTTP transport for enterprise Guard networking."""

from __future__ import annotations

import base64
import hashlib
import json
import platform
import re
import ssl
import subprocess
import urllib.parse
import urllib.request
from dataclasses import dataclass

import requests
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import ProxyManager

from ...no_redirect import RejectRedirects
from .contracts import ManagedNetworkPolicy
from .network_credentials import read_proxy_credential_record
from .network_trust import ManagedTrustError, build_managed_ssl_context
from .network_urlopen import ManagedOpener, ManagedResponse, ManagedUrlOpener
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
_MAX_PROXY_CREDENTIAL_BYTES = 16 * 1024


class ManagedNetworkError(RuntimeError):
    """A managed network policy blocked or could not establish a request."""


@dataclass(frozen=True, slots=True)
class ProxyCredentials:
    username: str
    password: str


def active_network_policy() -> ManagedNetworkPolicy:
    state = load_managed_policy()
    return state.policy.network if state.policy is not None else ManagedNetworkPolicy()


def resolved_network_policy(policy: ManagedNetworkPolicy | None) -> tuple[ManagedNetworkPolicy, bool]:
    if policy is not None:
        return policy, True
    state = load_managed_policy()
    if state.policy is not None:
        return state.policy.network, True
    return ManagedNetworkPolicy(), False


def platform_system_proxies() -> dict[str, str]:
    """Read OS proxy configuration without treating user environment as managed authority."""

    system_name = platform.system()
    if system_name == "Darwin":
        try:
            result = subprocess.run(
                ["/usr/sbin/scutil", "--proxy"],
                check=True,
                capture_output=True,
                text=True,
                timeout=5,
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
    if system_name == "Windows":
        try:
            import winreg
        except ImportError:
            return {}
        server: object = None
        for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
            try:
                with winreg.OpenKey(
                    hive,
                    r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                ) as key:
                    enabled, _ = winreg.QueryValueEx(key, "ProxyEnable")
                    candidate, _ = winreg.QueryValueEx(key, "ProxyServer")
            except OSError:
                continue
            if enabled and isinstance(candidate, str):
                server = candidate
                break
        if not isinstance(server, str):
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


def request_url(request: str | urllib.request.Request) -> str:
    return request.full_url if isinstance(request, urllib.request.Request) else request


def validate_destination(url: str, policy: ManagedNetworkPolicy) -> None:
    hostname = _canonical_hostname(urllib.parse.urlsplit(url).hostname or "")
    if not policy.allow_public_registries and hostname in _PUBLIC_REGISTRIES:
        raise ManagedNetworkError("managed_public_registry_disabled")


def _canonical_hostname(hostname: str) -> str:
    """Return a comparison-safe DNS hostname, accepting one root-label dot."""

    rooted = hostname[:-1] if hostname.endswith(".") else hostname
    try:
        return rooted.encode("idna").decode("ascii").lower()
    except UnicodeError as error:
        raise ManagedNetworkError("managed_destination_invalid") from error


def validated_proxy_url(value: str, *, require_https: bool, reason_code: str) -> str:
    if value != value.strip() or any(character.isspace() for character in value):
        raise ManagedNetworkError(reason_code)
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ManagedNetworkError(reason_code) from exc
    scheme = parsed.scheme.lower()
    allowed_scheme = scheme == "https" if require_https else scheme in {"http", "https"}
    if not allowed_scheme:
        raise ManagedNetworkError(reason_code)
    if parsed.hostname is None or not parsed.netloc or parsed.netloc.endswith(":") or port == 0:
        raise ManagedNetworkError(reason_code)
    if parsed.username is not None or parsed.password is not None:
        raise ManagedNetworkError("managed_proxy_credentials_forbidden")
    if parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
        raise ManagedNetworkError(reason_code)
    resolved_port = port or (443 if scheme == "https" else 80)
    host = parsed.hostname.lower()
    authority_host = f"[{host}]" if ":" in host else host
    return f"{scheme}://{authority_host}:{resolved_port}"


def proxy_map(policy: ManagedNetworkPolicy) -> dict[str, str]:
    if policy.proxy_mode == "none":
        if policy.proxy_url is not None:
            raise ManagedNetworkError("managed_proxy_url_mode_mismatch")
        return {}
    if policy.proxy_mode == "explicit":
        if policy.proxy_url is None:
            raise ManagedNetworkError("managed_proxy_url_required")
        proxy = validated_proxy_url(
            policy.proxy_url,
            require_https=True,
            reason_code="managed_proxy_url_invalid",
        )
        return {"http": proxy, "https": proxy}
    if policy.proxy_url is not None:
        raise ManagedNetworkError("managed_proxy_url_mode_mismatch")
    proxies: dict[str, str] = {}
    for scheme, proxy in platform_system_proxies().items():
        if scheme not in {"http", "https"}:
            continue
        proxies[scheme] = validated_proxy_url(
            proxy,
            require_https=False,
            reason_code="managed_system_proxy_invalid",
        )
    return proxies


def proxy_credential_key(proxy_url: str) -> str:
    return hashlib.sha256(proxy_url.encode("utf-8")).hexdigest()


def load_proxy_credentials(proxy_url: str) -> ProxyCredentials | None:
    """Load optional proxy auth from the native OS credential store without policy secrets."""

    raw = read_proxy_credential_record(proxy_credential_key(proxy_url))
    if raw is None:
        return None
    if len(raw.encode("utf-8")) > _MAX_PROXY_CREDENTIAL_BYTES:
        raise ManagedNetworkError("managed_proxy_credentials_invalid")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ManagedNetworkError("managed_proxy_credentials_invalid") from exc
    if not isinstance(payload, dict) or set(payload) != {"username", "password"}:
        raise ManagedNetworkError("managed_proxy_credentials_invalid")
    username = payload.get("username")
    password = payload.get("password")
    if (
        not isinstance(username, str)
        or not username
        or ":" in username
        or "\r" in username
        or "\n" in username
        or not isinstance(password, str)
        or not password
        or "\r" in password
        or "\n" in password
    ):
        raise ManagedNetworkError("managed_proxy_credentials_invalid")
    return ProxyCredentials(username=username, password=password)


def basic_proxy_authorization(credentials: ProxyCredentials) -> str:
    token = base64.b64encode(f"{credentials.username}:{credentials.password}".encode()).decode("ascii")
    return f"Basic {token}"


def selected_proxy_url(policy: ManagedNetworkPolicy, endpoint_scheme: str) -> str | None:
    return proxy_map(policy).get(endpoint_scheme)


def proxy_endpoint_hash(proxy_url: str) -> str:
    return hashlib.sha256(proxy_url.encode("utf-8")).hexdigest()


def managed_ssl_context(policy: ManagedNetworkPolicy | None = None) -> ssl.SSLContext:
    """Create mandatory TLS verification with an optional additive private CA."""

    resolved = policy or active_network_policy()
    try:
        return build_managed_ssl_context(resolved.ca_bundle_path)
    except ManagedTrustError as exc:
        raise ManagedNetworkError(str(exc)) from exc


def managed_opener(
    policy: ManagedNetworkPolicy | None = None,
    *,
    redirect_handler: urllib.request.HTTPRedirectHandler | None = None,
) -> ManagedOpener:
    resolved = policy or active_network_policy()
    proxies = proxy_map(resolved)
    context = managed_ssl_context(resolved)
    direct_handlers: list[urllib.request.BaseHandler] = [
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context),
    ]
    if redirect_handler is not None:
        direct_handlers.append(redirect_handler)
    proxy_headers: dict[str, str] = {}
    if resolved.proxy_mode == "explicit":
        selected = proxies.get("https")
        if selected is not None:
            credentials = load_proxy_credentials(selected)
            if credentials is not None:
                proxy_headers["Proxy-Authorization"] = basic_proxy_authorization(credentials)
    return ManagedUrlOpener(
        direct_opener=urllib.request.build_opener(*direct_handlers),
        proxy_urls=proxies,
        ssl_context=context,
        proxy_headers=proxy_headers,
        allow_redirects=redirect_handler is None,
    )


def _request_has_authentication(request: str | urllib.request.Request) -> bool:
    if not isinstance(request, urllib.request.Request):
        return False
    return any(name.lower() in {"authorization", "dpop"} for name, _value in request.header_items())


def managed_urlopen(
    request: str | urllib.request.Request,
    *,
    timeout: float | None = None,
    policy: ManagedNetworkPolicy | None = None,
) -> ManagedResponse:
    resolved, managed = resolved_network_policy(policy)
    validate_destination(request_url(request), resolved)
    reject_redirects = _request_has_authentication(request)
    if (
        not managed
        and resolved.proxy_mode == "system"
        and resolved.ca_bundle_path is None
        and resolved.allow_public_registries
    ):
        if reject_redirects:
            return urllib.request.build_opener(RejectRedirects()).open(request, timeout=timeout)
        return urllib.request.urlopen(request, timeout=timeout)
    return managed_opener(
        resolved,
        redirect_handler=RejectRedirects() if reject_redirects else None,
    ).open(request, timeout=timeout)


class _ManagedHTTPAdapter(HTTPAdapter):
    def __init__(
        self,
        context: ssl.SSLContext | None,
        proxy_authorization: str | None,
        policy: ManagedNetworkPolicy,
    ) -> None:
        self._managed_context = context
        self._proxy_authorization = proxy_authorization
        self._managed_policy = policy
        super().__init__()

    def add_headers(self, request: requests.PreparedRequest, **kwargs: object) -> None:
        del kwargs
        if request.url is None:
            raise ManagedNetworkError("managed_destination_missing")
        validate_destination(request.url, self._managed_policy)

    def init_poolmanager(
        self,
        connections: int,
        maxsize: int,
        block: bool = False,
        **pool_kwargs: object,
    ) -> None:
        if self._managed_context is not None:
            pool_kwargs["ssl_context"] = self._managed_context
        super().init_poolmanager(connections, maxsize, block=block, **pool_kwargs)

    def proxy_manager_for(self, proxy: str, **proxy_kwargs: object) -> ProxyManager:
        if self._managed_context is not None:
            proxy_kwargs["ssl_context"] = self._managed_context
            proxy_kwargs["proxy_ssl_context"] = self._managed_context
        return super().proxy_manager_for(proxy, **proxy_kwargs)

    def proxy_headers(self, proxy: str) -> dict[str, str]:
        headers = super().proxy_headers(proxy)
        if self._proxy_authorization is not None:
            headers["Proxy-Authorization"] = self._proxy_authorization
        return headers


def managed_requests_session(policy: ManagedNetworkPolicy | None = None) -> requests.Session:
    resolved, managed = resolved_network_policy(policy)
    proxies = proxy_map(resolved) if managed or resolved.proxy_mode != "system" else {}
    session = requests.Session()
    session.trust_env = not managed
    if proxies:
        session.proxies.update(proxies)
    elif managed and resolved.proxy_mode in {"none", "system"}:
        session.proxies.update({"http": "", "https": ""})
    context: ssl.SSLContext | None = managed_ssl_context(resolved) if managed else None
    proxy_authorization: str | None = None
    if resolved.proxy_mode == "explicit":
        selected = proxies.get("https")
        if selected is not None:
            credentials = load_proxy_credentials(selected)
            if credentials is not None:
                proxy_authorization = basic_proxy_authorization(credentials)
    session.mount("http://", _ManagedHTTPAdapter(context, proxy_authorization, resolved))
    session.mount("https://", _ManagedHTTPAdapter(context, proxy_authorization, resolved))
    session.verify = True
    return session


__all__ = [
    "ManagedNetworkError",
    "ProxyCredentials",
    "active_network_policy",
    "basic_proxy_authorization",
    "load_proxy_credentials",
    "managed_opener",
    "managed_requests_session",
    "managed_ssl_context",
    "managed_urlopen",
    "platform_system_proxies",
    "proxy_endpoint_hash",
    "proxy_map",
    "resolved_network_policy",
    "selected_proxy_url",
    "validate_destination",
]

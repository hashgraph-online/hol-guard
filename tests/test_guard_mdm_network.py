from __future__ import annotations

import ssl
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.mdm.contracts import ManagedNetworkPolicy
from codex_plugin_scanner.guard.mdm.network import (
    ManagedNetworkError,
    managed_requests_kwargs,
    managed_requests_session,
    managed_ssl_context,
    managed_urlopen,
)


def test_tls_verification_cannot_be_disabled() -> None:
    context = managed_ssl_context(ManagedNetworkPolicy(proxy_mode="none"))
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True
    session = managed_requests_session(ManagedNetworkPolicy(proxy_mode="none"))
    assert session.verify is True
    assert session.trust_env is False


def test_explicit_proxy_is_applied_without_credentials() -> None:
    policy = ManagedNetworkPolicy(proxy_mode="explicit", proxy_url="https://proxy.example:8443")
    session = managed_requests_session(policy)
    assert session.proxies == {
        "http": "https://proxy.example:8443",
        "https": "https://proxy.example:8443",
    }
    assert managed_requests_kwargs(policy)["proxies"] == session.proxies


def test_private_ca_must_be_an_absolute_readable_file(tmp_path: Path) -> None:
    with pytest.raises(ManagedNetworkError, match="managed_ca_bundle_invalid"):
        managed_ssl_context(ManagedNetworkPolicy(ca_bundle_path="relative.pem"))
    with pytest.raises(ManagedNetworkError, match="managed_ca_bundle_invalid"):
        managed_requests_session(ManagedNetworkPolicy(ca_bundle_path=str(tmp_path / "missing.pem")))


def test_disabled_public_registry_fails_before_network() -> None:
    policy = ManagedNetworkPolicy(allow_public_registries=False)
    with pytest.raises(ManagedNetworkError, match="managed_public_registry_disabled"):
        managed_urlopen("https://pypi.org/pypi/hol-guard/json", timeout=1, policy=policy)


def test_managed_system_proxy_uses_platform_configuration_not_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.mdm.network.platform_system_proxies",
        lambda: {"https": "http://system-proxy.example:8080"},
    )
    kwargs = managed_requests_kwargs(ManagedNetworkPolicy(proxy_mode="system"))
    assert kwargs["proxies"] == {
        "http": "",
        "https": "http://system-proxy.example:8080",
    }

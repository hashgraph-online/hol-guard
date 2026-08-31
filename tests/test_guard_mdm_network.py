from __future__ import annotations

import json
import os
import ssl
import sys
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from email.message import Message
from email.utils import format_datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from requests import Request
from requests.certs import where as requests_ca_bundle

from codex_plugin_scanner.guard.daemon import manager as daemon_manager
from codex_plugin_scanner.guard.mdm import network_diagnostics as diagnostics_module
from codex_plugin_scanner.guard.mdm import network_transport as transport_module
from codex_plugin_scanner.guard.mdm import network_trust as trust_module
from codex_plugin_scanner.guard.mdm.contracts import ManagedNetworkPolicy
from codex_plugin_scanner.guard.mdm.managed_file_trust import machine_controlled_file_is_trusted
from codex_plugin_scanner.guard.mdm.network import (
    ManagedNetworkError,
    diagnose_endpoint,
    managed_requests_session,
    managed_ssl_context,
    managed_urlopen,
    platform_system_proxies,
)


class _FakeResponse:
    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *_args: object) -> None:
        return None


def test_tls_verification_cannot_be_disabled() -> None:
    context = managed_ssl_context(ManagedNetworkPolicy(proxy_mode="none"))
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True
    assert context.minimum_version == ssl.TLSVersion.TLSv1_2
    session = managed_requests_session(ManagedNetworkPolicy(proxy_mode="none"))
    assert session.verify is True
    assert session.trust_env is False
    assert session.proxies == {"http": "", "https": ""}


def test_explicit_proxy_is_applied_without_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(transport_module, "read_proxy_credential_record", lambda _key: None)
    policy = ManagedNetworkPolicy(proxy_mode="explicit", proxy_url="https://proxy.example:8443")
    session = managed_requests_session(policy)
    assert session.proxies == {
        "http": "https://proxy.example:8443",
        "https": "https://proxy.example:8443",
    }
    assert "Proxy-Authorization" not in session.headers
    assert session.verify is True
    assert session.trust_env is False
    assert session.adapters["http://"].__class__.__name__ == "_ManagedHTTPAdapter"
    assert session.adapters["https://"].__class__.__name__ == "_ManagedHTTPAdapter"


@pytest.mark.parametrize(
    "proxy_url",
    (
        "http://proxy.example:8080",
        "https://user:secret@proxy.example:8443",
        "https://proxy.example:8443/path",
        "https://proxy.example:8443?token=secret",
        "https://proxy.example:65536",
        " https://proxy.example:8443",
    ),
)
def test_explicit_proxy_rejects_non_https_credentials_and_ambiguous_urls(proxy_url: str) -> None:
    with pytest.raises(ManagedNetworkError):
        managed_requests_session(ManagedNetworkPolicy(proxy_mode="explicit", proxy_url=proxy_url))


def test_proxy_url_is_rejected_outside_explicit_mode() -> None:
    with pytest.raises(ManagedNetworkError, match="managed_proxy_url_mode_mismatch"):
        managed_requests_session(ManagedNetworkPolicy(proxy_mode="none", proxy_url="https://proxy.example"))


def test_authenticated_proxy_uses_os_keyring_without_secret_leakage(monkeypatch: pytest.MonkeyPatch) -> None:
    username = "synthetic-proxy-user"
    password = "synthetic-proxy-password"
    monkeypatch.setattr(
        transport_module,
        "read_proxy_credential_record",
        lambda _key: json.dumps({"username": username, "password": password}),
    )
    monkeypatch.setattr(diagnostics_module.socket, "getaddrinfo", lambda *_args, **_kwargs: [(object(),)])
    monkeypatch.setattr(transport_module, "managed_urlopen", lambda *_args, **_kwargs: _FakeResponse())
    policy = ManagedNetworkPolicy(proxy_mode="explicit", proxy_url="https://proxy.example:8443")

    session = managed_requests_session(policy)
    result = diagnose_endpoint("https://guard.example", policy)
    public = json.dumps(
        {
            "policy": policy.to_dict(),
            "proxies": session.proxies,
            "diagnostic": result.to_dict(),
        },
        sort_keys=True,
    )

    assert result.proxy.authenticated is True
    assert result.proxy.selected is True
    assert result.proxy.endpoint_hash is not None
    assert username not in public
    assert password not in public
    assert "proxy.example" not in json.dumps(result.to_dict(), sort_keys=True)
    assert "Proxy-Authorization" not in session.headers
    for prefix in ("http://", "https://"):
        proxy_headers = session.adapters[prefix].proxy_headers(session.proxies[prefix.removesuffix("://")])
        assert proxy_headers["Proxy-Authorization"].startswith("Basic ")


def test_invalid_keyring_proxy_credentials_fail_with_redacted_reason(monkeypatch: pytest.MonkeyPatch) -> None:
    secret = "synthetic-secret-material"
    monkeypatch.setattr(transport_module, "read_proxy_credential_record", lambda _key: f"not-json-{secret}")
    policy = ManagedNetworkPolicy(proxy_mode="explicit", proxy_url="https://proxy.example:8443")

    with pytest.raises(ManagedNetworkError) as error:
        managed_requests_session(policy)

    assert str(error.value) == "managed_proxy_credentials_invalid"
    assert secret not in str(error.value)


def test_private_ca_must_be_an_absolute_trusted_file(tmp_path: Path) -> None:
    with pytest.raises(ManagedNetworkError, match="managed_ca_bundle_invalid"):
        managed_ssl_context(ManagedNetworkPolicy(ca_bundle_path="relative.pem"))
    with pytest.raises(ManagedNetworkError, match="managed_ca_bundle_invalid"):
        managed_requests_session(ManagedNetworkPolicy(ca_bundle_path=str(tmp_path / "missing.pem")))

    malformed = tmp_path / "malformed.pem"
    malformed.write_text("not a certificate", encoding="utf-8")
    with pytest.raises(ManagedNetworkError, match="managed_ca_bundle_invalid"):
        managed_ssl_context(ManagedNetworkPolicy(ca_bundle_path=str(malformed)))

    if os.name != "nt":
        writable = tmp_path / "writable.pem"
        writable.write_text(Path(requests_ca_bundle()).read_text(encoding="utf-8"), encoding="utf-8")
        writable.chmod(0o666)
        with pytest.raises(ManagedNetworkError, match="managed_ca_bundle_invalid"):
            managed_ssl_context(ManagedNetworkPolicy(ca_bundle_path=str(writable)))


def test_private_ca_is_added_without_replacing_public_trust(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(trust_module, "machine_controlled_file_is_trusted", lambda _path: True)
    session = managed_requests_session(ManagedNetworkPolicy(ca_bundle_path=requests_ca_bundle()))

    assert session.verify is True
    assert session.adapters["https://"].__class__.__name__ == "_ManagedHTTPAdapter"
    context = managed_ssl_context(ManagedNetworkPolicy(ca_bundle_path=requests_ca_bundle()))
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True


def test_managed_ca_requires_machine_owned_full_path(tmp_path: Path) -> None:
    bundle = tmp_path / "ca.pem"
    bundle.write_text(Path(requests_ca_bundle()).read_text(encoding="utf-8"), encoding="utf-8")

    assert machine_controlled_file_is_trusted(bundle, system_name="Linux") is False
    with pytest.raises(ManagedNetworkError, match="managed_ca_bundle_invalid"):
        managed_ssl_context(ManagedNetworkPolicy(ca_bundle_path=str(bundle)))


def test_disabled_public_registry_fails_before_network() -> None:
    policy = ManagedNetworkPolicy(allow_public_registries=False)
    with pytest.raises(ManagedNetworkError, match="managed_public_registry_disabled"):
        managed_urlopen("https://pypi.org/pypi/hol-guard/json", timeout=1, policy=policy)

    session = managed_requests_session(policy)
    prepared = session.prepare_request(Request("POST", "https://pypi.org/legacy/"))
    with pytest.raises(ManagedNetworkError, match="managed_public_registry_disabled"):
        session.adapters["https://"].add_headers(prepared)

    rooted = session.prepare_request(Request("GET", "https://PYPI.ORG./simple/hol-guard/"))
    with pytest.raises(ManagedNetworkError, match="managed_public_registry_disabled"):
        session.adapters["https://"].add_headers(rooted)


def test_authenticated_urlopen_disables_redirects_without_changing_public_downloads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = ManagedNetworkPolicy()
    handlers: list[object] = []

    class FakeOpener:
        def open(self, _request, timeout=None):
            assert timeout == 5
            return _FakeResponse()

    monkeypatch.setattr(transport_module, "resolved_network_policy", lambda _policy: (policy, False))
    monkeypatch.setattr(
        urllib.request,
        "build_opener",
        lambda *items: handlers.extend(items) or FakeOpener(),
    )
    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: pytest.fail("authenticated request used redirect-following urlopen"),
    )
    request = urllib.request.Request(
        "https://hol.org/api/guard/receipts/sync",
        headers={"Authorization": "Bearer synthetic", "DPoP": "proof"},
    )

    managed_urlopen(request, timeout=5, policy=policy)

    assert any(type(handler).__name__ == "RejectRedirects" for handler in handlers)


def test_blocked_public_registry_diagnostic_is_stable_and_offline() -> None:
    result = diagnose_endpoint(
        "https://pypi.org",
        ManagedNetworkPolicy(proxy_mode="none", allow_public_registries=False),
    )

    assert result.reason_code == "managed_public_registry_disabled"
    assert result.dns == "blocked"
    assert result.reachability == "blocked"
    assert result.tls == "not-tested"


def test_managed_system_proxy_uses_platform_configuration_not_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        transport_module,
        "platform_system_proxies",
        lambda: {"https": "http://system-proxy.example:8080"},
    )
    monkeypatch.setenv("HTTPS_PROXY", "http://unmanaged.example:9999")
    session = managed_requests_session(ManagedNetworkPolicy(proxy_mode="system"))
    assert session.proxies == {"https": "http://system-proxy.example:8080"}
    assert session.trust_env is False


def test_system_proxy_rejects_embedded_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        transport_module,
        "platform_system_proxies",
        lambda: {"https": "http://user:secret@system-proxy.example:8080"},
    )
    with pytest.raises(ManagedNetworkError, match="managed_proxy_credentials_forbidden"):
        managed_requests_session(ManagedNetworkPolicy(proxy_mode="system"))


def test_detached_daemon_does_not_inherit_shell_network_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ambient = {
        "HTTP_PROXY": "http://unmanaged.example:8080",
        "HTTPS_PROXY": "http://unmanaged.example:8443",
        "ALL_PROXY": "http://unmanaged.example:8888",
        "NO_PROXY": "*",
        "SSL_CERT_FILE": str(tmp_path / "ambient-ca.pem"),
        "SSL_CERT_DIR": str(tmp_path / "ambient-ca-dir"),
        "REQUESTS_CA_BUNDLE": str(tmp_path / "requests-ca.pem"),
        "CURL_CA_BUNDLE": str(tmp_path / "curl-ca.pem"),
    }
    for key, value in ambient.items():
        monkeypatch.setenv(key, value)

    env = daemon_manager._daemon_launcher_env(home_dir=tmp_path)

    for key in ambient:
        assert key not in env


def test_diagnostic_rejects_secret_bearing_or_non_origin_endpoints() -> None:
    secret = "synthetic-endpoint-secret"
    for endpoint in (
        f"https://user:{secret}@guard.example",
        f"https://guard.example/path/{secret}",
        f"https://guard.example?token={secret}",
        f"https://guard.example#{secret}",
        "http://guard.example",
    ):
        result = diagnose_endpoint(endpoint, ManagedNetworkPolicy(proxy_mode="none"))
        payload = json.dumps(result.to_dict(), sort_keys=True)
        assert result.reason_code == "endpoint_invalid"
        assert result.endpoint == "redacted"
        assert secret not in payload


def test_diagnostic_reports_dns_failure_without_exception_detail(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_dns(*_args: object, **_kwargs: object) -> object:
        raise diagnostics_module.socket.gaierror("synthetic-sensitive-dns-detail")

    monkeypatch.setattr(diagnostics_module.socket, "getaddrinfo", fail_dns)
    result = diagnose_endpoint("https://guard.example", ManagedNetworkPolicy(proxy_mode="none"))
    payload = json.dumps(result.to_dict(), sort_keys=True)

    assert result.reason_code == "dns_resolution_failed"
    assert result.dns == "failed"
    assert "synthetic-sensitive-dns-detail" not in payload


def test_proxy_routing_can_succeed_when_destination_dns_is_unavailable_locally(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def resolve(host: str, *_args: object, **_kwargs: object) -> list[tuple[object, ...]]:
        if host == "guard.example":
            raise diagnostics_module.socket.gaierror("destination unavailable locally")
        if host == "proxy.example":
            return [(object(),)]
        raise AssertionError(host)

    monkeypatch.setattr(transport_module, "read_proxy_credential_record", lambda _key: None)
    monkeypatch.setattr(diagnostics_module.socket, "getaddrinfo", resolve)
    monkeypatch.setattr(transport_module, "managed_urlopen", lambda *_args, **_kwargs: _FakeResponse())
    result = diagnose_endpoint(
        "https://guard.example",
        ManagedNetworkPolicy(proxy_mode="explicit", proxy_url="https://proxy.example:8443"),
    )

    assert result.reason_code == "endpoint_reachable"
    assert result.dns == "failed"
    assert result.proxy.selected is True
    assert result.proxy.dns == "ok"
    assert result.tls == "trusted"
    assert result.reachability == "reachable"


def test_diagnostic_reports_proxy_resolution_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def resolve(host: str, *_args: object, **_kwargs: object) -> list[tuple[object, ...]]:
        if host == "guard.example":
            return [(object(),)]
        if host == "proxy.example":
            raise diagnostics_module.socket.gaierror("proxy detail")
        raise AssertionError(host)

    monkeypatch.setattr(transport_module, "read_proxy_credential_record", lambda _key: None)
    monkeypatch.setattr(diagnostics_module.socket, "getaddrinfo", resolve)
    result = diagnose_endpoint(
        "https://guard.example",
        ManagedNetworkPolicy(proxy_mode="explicit", proxy_url="https://proxy.example:8443"),
    )

    assert result.reason_code == "proxy_resolution_failed"
    assert result.proxy.selected is True
    assert result.proxy.dns == "failed"
    assert result.reachability == "failed"


def test_diagnostic_reports_tls_failure_without_certificate_detail(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(diagnostics_module.socket, "getaddrinfo", lambda *_args, **_kwargs: [(object(),)])

    def fail_tls(*_args: object, **_kwargs: object) -> _FakeResponse:
        raise urllib.error.URLError(ssl.SSLCertVerificationError(1, "synthetic certificate secret"))

    monkeypatch.setattr(transport_module, "managed_urlopen", fail_tls)
    result = diagnose_endpoint("https://guard.example", ManagedNetworkPolicy(proxy_mode="none"))
    payload = json.dumps(result.to_dict(), sort_keys=True)

    assert result.reason_code == "tls_trust_failed"
    assert result.tls == "failed"
    assert result.reachability == "failed"
    assert "synthetic certificate secret" not in payload


def test_clock_skew_uses_http_date_with_stable_reason(monkeypatch: pytest.MonkeyPatch) -> None:
    headers = Message()
    headers["Date"] = format_datetime(datetime.now(timezone.utc) - timedelta(minutes=20), usegmt=True)
    response = urllib.error.HTTPError("https://guard.example", 503, "unavailable", headers, None)
    monkeypatch.setattr(diagnostics_module.socket, "getaddrinfo", lambda *_args, **_kwargs: [(object(),)])

    def fail_with_http_status(*_args: object, **_kwargs: object) -> _FakeResponse:
        raise response

    monkeypatch.setattr(transport_module, "managed_urlopen", fail_with_http_status)
    result = diagnose_endpoint("https://guard.example", ManagedNetworkPolicy(proxy_mode="none"))

    assert result.reason_code == "clock_skew_detected"
    assert result.clock == "skewed"
    assert result.clock_skew_seconds is not None
    assert result.clock_skew_seconds > 300
    assert result.tls == "trusted"
    assert result.reachability == "reachable"


def test_http_error_still_proves_endpoint_and_tls_reachability(monkeypatch: pytest.MonkeyPatch) -> None:
    headers = Message()
    headers["Date"] = format_datetime(datetime.now(timezone.utc), usegmt=True)
    response = urllib.error.HTTPError("https://guard.example", 401, "unauthorized", headers, None)
    monkeypatch.setattr(diagnostics_module.socket, "getaddrinfo", lambda *_args, **_kwargs: [(object(),)])

    def fail_with_http_status(*_args: object, **_kwargs: object) -> _FakeResponse:
        raise response

    monkeypatch.setattr(transport_module, "managed_urlopen", fail_with_http_status)
    result = diagnose_endpoint("https://guard.example", ManagedNetworkPolicy(proxy_mode="none"))

    assert result.reason_code == "endpoint_reachable"
    assert result.dns == "ok"
    assert result.tls == "trusted"
    assert result.clock == "ok"
    assert result.reachability == "reachable"


def test_windows_system_proxy_falls_back_to_machine_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeKey:
        def __enter__(self) -> FakeKey:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

    def open_key(hive: object, _path: str) -> FakeKey:
        if hive == "current-user":
            raise OSError
        return FakeKey()

    values = iter(((1, 0), ("proxy.example:8080", 0)))
    fake_winreg = SimpleNamespace(
        HKEY_CURRENT_USER="current-user",
        HKEY_LOCAL_MACHINE="local-machine",
        OpenKey=open_key,
        QueryValueEx=lambda _key, _name: next(values),
    )
    monkeypatch.setitem(sys.modules, "winreg", fake_winreg)
    monkeypatch.setattr(transport_module.platform, "system", lambda: "Windows")

    assert platform_system_proxies() == {
        "http": "http://proxy.example:8080",
        "https": "http://proxy.example:8080",
    }

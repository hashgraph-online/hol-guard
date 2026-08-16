from __future__ import annotations

import base64
import ipaddress
import json
import select
import socket
import socketserver
import ssl
import threading
import urllib.error
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Iterator

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from codex_plugin_scanner.guard.mdm import network_transport as transport_module
from codex_plugin_scanner.guard.mdm.contracts import ManagedNetworkPolicy
from codex_plugin_scanner.guard.mdm.network import diagnose_endpoint, managed_requests_session, managed_urlopen


class _OriginHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_HEAD(self) -> None:  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        payload = b"guard-network-ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, _format: str, *_args: object) -> None:
        return None


@dataclass(slots=True)
class _ProxyState:
    target_port: int
    expected_authorization: str | None = None
    attempts: int = 0
    successful_connects: int = 0
    last_authorization: str | None = None


class _TlsProxyServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, state: _ProxyState) -> None:
        self.state = state
        super().__init__(("127.0.0.1", 0), _ProxyHandler)

    @property
    def bound_port(self) -> int:
        address = self.server_address
        if not isinstance(address, tuple) or len(address) < 2 or not isinstance(address[1], int):
            raise RuntimeError("proxy_test_port_unavailable")
        return address[1]


class _ProxyHandler(socketserver.StreamRequestHandler):
    server: _TlsProxyServer

    def handle(self) -> None:
        request_line = self.rfile.readline(8192).decode("ascii", errors="strict").strip()
        headers: dict[str, str] = {}
        while True:
            raw_line = self.rfile.readline(8192)
            if raw_line in {b"\r\n", b"\n", b""}:
                break
            name, separator, value = raw_line.decode("ascii", errors="strict").partition(":")
            if not separator:
                self._write_response(400, "Bad Request")
                return
            headers[name.strip().lower()] = value.strip()

        state = self.server.state
        state.attempts += 1
        state.last_authorization = headers.get("proxy-authorization")
        if state.expected_authorization is not None and state.last_authorization != state.expected_authorization:
            self.wfile.write(
                b'HTTP/1.1 407 Proxy Authentication Required\r\n'
                b'Proxy-Authenticate: Basic realm="guard-test"\r\n'
                b"Content-Length: 0\r\n\r\n"
            )
            self.wfile.flush()
            return

        method, separator, target = request_line.partition(" ")
        if method != "CONNECT" or not separator:
            self._write_response(405, "Method Not Allowed")
            return
        authority, separator, _http_version = target.partition(" ")
        if not separator:
            self._write_response(400, "Bad Request")
            return
        host, separator, port_text = authority.rpartition(":")
        if not separator or host not in {"127.0.0.1", "localhost"}:
            self._write_response(403, "Forbidden")
            return
        try:
            port = int(port_text)
        except ValueError:
            self._write_response(400, "Bad Request")
            return
        if port != state.target_port:
            self._write_response(403, "Forbidden")
            return

        with socket.create_connection(("127.0.0.1", port), timeout=5) as upstream:
            self.wfile.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            self.wfile.flush()
            state.successful_connects += 1
            self.connection.settimeout(5)
            upstream.settimeout(5)
            sockets = (self.connection, upstream)
            while True:
                readable, _, _ = select.select(sockets, (), (), 5)
                if not readable:
                    return
                for source in readable:
                    try:
                        data = source.recv(65536)
                    except (TimeoutError, ssl.SSLWantReadError):
                        continue
                    if not data:
                        return
                    destination = upstream if source is self.connection else self.connection
                    destination.sendall(data)

    def _write_response(self, status: int, reason: str) -> None:
        self.wfile.write(f"HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\n\r\n".encode("ascii"))
        self.wfile.flush()


@dataclass(frozen=True, slots=True)
class _NetworkLab:
    target_url: str
    proxy_url: str
    ca_bundle: Path
    proxy_state: _ProxyState


def _write_certificates(tmp_path: Path) -> tuple[Path, Path, Path]:
    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "HOL Guard integration CA")])
    ca_certificate = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    server_certificate = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    ca_path = tmp_path / "ca.pem"
    cert_path = tmp_path / "server.pem"
    key_path = tmp_path / "server-key.pem"
    ca_path.write_bytes(ca_certificate.public_bytes(serialization.Encoding.PEM))
    cert_path.write_bytes(server_certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        server_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    for path in (ca_path, cert_path, key_path):
        path.chmod(0o600)
    return ca_path, cert_path, key_path


@pytest.fixture
def network_lab(tmp_path: Path) -> Iterator[_NetworkLab]:
    ca_path, cert_path, key_path = _write_certificates(tmp_path)
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.minimum_version = ssl.TLSVersion.TLSv1_2
    server_context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))

    origin = ThreadingHTTPServer(("127.0.0.1", 0), _OriginHandler)
    origin.socket = server_context.wrap_socket(origin.socket, server_side=True)
    origin_port = origin.server_port

    proxy_state = _ProxyState(target_port=origin_port)
    proxy = _TlsProxyServer(proxy_state)
    proxy.socket = server_context.wrap_socket(proxy.socket, server_side=True)

    origin_thread = threading.Thread(target=origin.serve_forever, name="guard-test-origin", daemon=True)
    proxy_thread = threading.Thread(target=proxy.serve_forever, name="guard-test-proxy", daemon=True)
    origin_thread.start()
    proxy_thread.start()
    try:
        yield _NetworkLab(
            target_url=f"https://127.0.0.1:{origin_port}",
            proxy_url=f"https://127.0.0.1:{proxy.bound_port}",
            ca_bundle=ca_path,
            proxy_state=proxy_state,
        )
    finally:
        proxy.shutdown()
        origin.shutdown()
        proxy.server_close()
        origin.server_close()
        proxy_thread.join(timeout=5)
        origin_thread.join(timeout=5)


def test_direct_networking_and_private_ca_are_real_tls(network_lab: _NetworkLab) -> None:
    policy = ManagedNetworkPolicy(proxy_mode="none", ca_bundle_path=str(network_lab.ca_bundle))

    with managed_urlopen(network_lab.target_url, timeout=5, policy=policy) as response:
        assert response.read() == b"guard-network-ok"

    diagnostic = diagnose_endpoint(network_lab.target_url, policy)
    assert diagnostic.reason_code == "endpoint_reachable"
    assert diagnostic.tls == "trusted"
    assert diagnostic.clock == "ok"
    assert diagnostic.reachability == "reachable"


def test_unapproved_private_ca_is_rejected_by_real_tls(network_lab: _NetworkLab) -> None:
    policy = ManagedNetworkPolicy(proxy_mode="none")

    with pytest.raises(urllib.error.URLError):
        managed_urlopen(network_lab.target_url, timeout=5, policy=policy)

    diagnostic = diagnose_endpoint(network_lab.target_url, policy)
    assert diagnostic.reason_code == "tls_trust_failed"
    assert diagnostic.tls == "failed"
    assert diagnostic.reachability == "failed"


def test_explicit_https_proxy_cannot_be_bypassed_by_no_proxy(
    network_lab: _NetworkLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NO_PROXY", "*")
    monkeypatch.setenv("no_proxy", "*")
    monkeypatch.setattr(transport_module, "read_proxy_credential_record", lambda _key: None)
    policy = ManagedNetworkPolicy(
        proxy_mode="explicit",
        proxy_url=network_lab.proxy_url,
        ca_bundle_path=str(network_lab.ca_bundle),
    )

    with managed_urlopen(network_lab.target_url, timeout=5, policy=policy) as response:
        assert response.read() == b"guard-network-ok"

    assert network_lab.proxy_state.successful_connects >= 1


def test_system_https_proxy_uses_real_proxy_tunnel(
    network_lab: _NetworkLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    monkeypatch.setattr(transport_module, "platform_system_proxies", lambda: {"https": network_lab.proxy_url})
    policy = ManagedNetworkPolicy(proxy_mode="system", ca_bundle_path=str(network_lab.ca_bundle))

    with managed_urlopen(network_lab.target_url, timeout=5, policy=policy) as response:
        assert response.read() == b"guard-network-ok"

    assert network_lab.proxy_state.successful_connects >= 1


def test_authenticated_proxy_uses_keyring_without_secret_in_public_state(
    network_lab: _NetworkLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    username = "synthetic-user"
    password = "synthetic-password"
    authorization = "Basic " + base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    network_lab.proxy_state.expected_authorization = authorization
    monkeypatch.setenv("NO_PROXY", "*")
    monkeypatch.setenv("no_proxy", "*")
    monkeypatch.setattr(
        transport_module,
        "read_proxy_credential_record",
        lambda _key: json.dumps({"username": username, "password": password}),
    )
    policy = ManagedNetworkPolicy(
        proxy_mode="explicit",
        proxy_url=network_lab.proxy_url,
        ca_bundle_path=str(network_lab.ca_bundle),
    )

    response = managed_requests_session(policy).get(network_lab.target_url, timeout=5)
    assert response.status_code == 200
    assert response.text == "guard-network-ok"
    assert network_lab.proxy_state.last_authorization == authorization
    assert network_lab.proxy_state.successful_connects >= 1

    public_state = json.dumps(policy.to_dict(), sort_keys=True)
    assert username not in public_state
    assert password not in public_state
    assert authorization not in public_state


def test_real_proxy_outage_reports_redacted_failure(
    network_lab: _NetworkLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
        reservation.bind(("127.0.0.1", 0))
        unused_port = reservation.getsockname()[1]
    monkeypatch.setattr(transport_module, "read_proxy_credential_record", lambda _key: None)
    policy = ManagedNetworkPolicy(
        proxy_mode="explicit",
        proxy_url=f"https://127.0.0.1:{unused_port}",
        ca_bundle_path=str(network_lab.ca_bundle),
    )

    diagnostic = diagnose_endpoint(network_lab.target_url, policy)
    payload = json.dumps(diagnostic.to_dict(), sort_keys=True)

    assert diagnostic.reason_code == "proxy_unreachable"
    assert diagnostic.proxy.selected is True
    assert diagnostic.proxy.dns == "ok"
    assert diagnostic.reachability == "failed"
    assert network_lab.proxy_url not in payload

"""Sigstore's trust-root refresh gets a CA bundle when OpenSSL has no default one."""

from __future__ import annotations

import os
import threading
from types import SimpleNamespace

import pytest
import requests.certs

from codex_plugin_scanner.guard.catalog_delivery import authority


def _verify_paths(cafile: str | None, capath: str | None) -> SimpleNamespace:
    # ssl reports a default path as None when it does not exist.
    return SimpleNamespace(cafile=cafile, capath=capath)


@pytest.fixture
def no_trust_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SSL_CERT_FILE", raising=False)
    monkeypatch.delenv("SSL_CERT_DIR", raising=False)


@pytest.mark.usefixtures("no_trust_override")
def test_lends_bundled_roots_only_for_the_refresh(monkeypatch: pytest.MonkeyPatch) -> None:
    # The packaged runtime's OpenSSL names the build machine's directory.
    monkeypatch.setattr(authority.ssl, "get_default_verify_paths", lambda: _verify_paths(None, None))

    with authority._trust_refresh_ca():
        assert os.environ["SSL_CERT_FILE"] == requests.certs.where()
    assert "SSL_CERT_FILE" not in os.environ


@pytest.mark.usefixtures("no_trust_override")
def test_keeps_the_platform_default_when_openssl_has_one(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(authority.ssl, "get_default_verify_paths", lambda: _verify_paths("/etc/ssl/cert.pem", None))

    with authority._trust_refresh_ca():
        assert "SSL_CERT_FILE" not in os.environ


@pytest.mark.parametrize("name", ["SSL_CERT_FILE", "SSL_CERT_DIR"])
def test_keeps_an_explicit_trust_source(monkeypatch: pytest.MonkeyPatch, name: str) -> None:
    monkeypatch.delenv("SSL_CERT_FILE", raising=False)
    monkeypatch.delenv("SSL_CERT_DIR", raising=False)
    monkeypatch.setenv(name, "/corporate/roots")
    monkeypatch.setattr(authority.ssl, "get_default_verify_paths", lambda: _verify_paths(None, None))

    with authority._trust_refresh_ca():
        assert os.environ[name] == "/corporate/roots"
        assert name == "SSL_CERT_FILE" or "SSL_CERT_FILE" not in os.environ
    assert os.environ[name] == "/corporate/roots"


@pytest.mark.usefixtures("no_trust_override")
def test_an_overlapping_refresh_waits_instead_of_borrowing_the_temporary_roots(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Without a platform default, a second refresh that started while the first
    # had lent the roots used to read them as a standing source, skip the lock
    # and lose them when the first call finished.
    monkeypatch.setattr(authority.ssl, "get_default_verify_paths", lambda: _verify_paths(None, None))
    entered = threading.Event()
    seen: list[str | None] = []

    def second() -> None:
        with authority._trust_refresh_ca():
            entered.set()
            seen.append(os.environ.get("SSL_CERT_FILE"))

    with authority._trust_refresh_ca():
        worker = threading.Thread(target=second)
        worker.start()
        assert not entered.wait(0.2)
    worker.join(5)

    assert seen == [requests.certs.where()]
    assert "SSL_CERT_FILE" not in os.environ

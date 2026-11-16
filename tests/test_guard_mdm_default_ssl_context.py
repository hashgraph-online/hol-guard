from __future__ import annotations

import ssl
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.mdm import network_trust as trust_module


@pytest.fixture
def counted_contexts(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> tuple[list[ssl.SSLContext], Path]:
    monkeypatch.delenv("SSL_CERT_FILE", raising=False)
    monkeypatch.delenv("SSL_CERT_DIR", raising=False)
    bundle = tmp_path / "bundle.pem"
    bundle.write_text("")
    monkeypatch.setattr(trust_module, "_requests_ca_bundle", lambda: bundle)
    built: list[ssl.SSLContext] = []

    def create_default_context() -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        built.append(context)
        return context

    monkeypatch.setattr(ssl, "create_default_context", create_default_context)
    return built, bundle


def test_default_context_is_reused_while_trust_sources_are_unchanged(counted_contexts) -> None:
    built, _bundle = counted_contexts

    first = trust_module.build_default_ssl_context()
    second = trust_module.build_default_ssl_context()

    assert first is second
    assert len(built) == 1


def test_default_context_is_rebuilt_when_the_public_bundle_changes(counted_contexts) -> None:
    built, bundle = counted_contexts
    first = trust_module.build_default_ssl_context()

    bundle.write_text("\n")

    assert trust_module.build_default_ssl_context() is not first
    assert len(built) == 2


def test_default_context_is_rebuilt_when_ca_overrides_change(
    counted_contexts, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    built, _bundle = counted_contexts
    first = trust_module.build_default_ssl_context()

    monkeypatch.setenv("SSL_CERT_DIR", str(tmp_path))

    assert trust_module.build_default_ssl_context() is not first
    assert len(built) == 2


def test_default_context_is_rebuilt_once_it_is_old(counted_contexts, monkeypatch: pytest.MonkeyPatch) -> None:
    built, _bundle = counted_contexts
    clock = [1_000.0]
    monkeypatch.setattr(trust_module.time, "monotonic", lambda: clock[0])
    first = trust_module.build_default_ssl_context()

    clock[0] += trust_module._DEFAULT_CONTEXT_MAX_AGE_SECONDS

    assert trust_module.build_default_ssl_context() is not first
    assert len(built) == 2

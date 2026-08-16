from __future__ import annotations

import socket

import pytest

from codex_plugin_scanner.guard.runtime.network_public_suffix import registrable_domain


def test_registrable_domain_uses_bundled_psl_without_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def reject_network(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("PSL lookup attempted network access")

    monkeypatch.setattr(socket, "create_connection", reject_network)

    assert registrable_domain("www.service.example.co.uk") == "example.co.uk"
    assert registrable_domain("co.uk") is None
    assert registrable_domain("www.bücher.example") == "xn--bcher-kva.example"

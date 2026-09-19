"""Opt-in network prohibition for package and evidence source-route qualification.

Load with ``python -m pytest -p tests.package_offline``. External socket attempts
fail the test even if the caller catches the exception. Existing test servers at
literal loopback addresses remain available. This plugin supplies no synthetic
successful HTTP response and opens no listener.
"""

from __future__ import annotations

import socket

import pytest


@pytest.fixture(autouse=True)
def forbid_package_qualification_network(monkeypatch: pytest.MonkeyPatch):
    attempts = []
    original_create_connection = socket.create_connection
    original_connect = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex

    def rejected(*_args, **_kwargs):
        attempts.append(True)
        raise AssertionError("External network is prohibited in offline package qualification")

    def is_loopback(address):
        return isinstance(address, tuple) and len(address) >= 2 and address[0] in {"127.0.0.1", "::1"}

    def create_connection(address, *args, **kwargs):
        if not is_loopback(address):
            return rejected()
        return original_create_connection(address, *args, **kwargs)

    def connect(stream, address):
        if not is_loopback(address):
            return rejected()
        return original_connect(stream, address)

    def connect_ex(stream, address):
        if not is_loopback(address):
            return rejected()
        return original_connect_ex(stream, address)

    monkeypatch.setattr(socket, "create_connection", create_connection)
    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(socket.socket, "connect_ex", connect_ex)
    yield
    assert not attempts, "Offline package test attempted an external network connection"

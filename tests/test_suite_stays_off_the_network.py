"""The suite itself must never reach a public host.

Fixtures carry production Guard Cloud URLs, so a code path a test forgets to
fake would otherwise send a test token to the real Cloud.
"""

from __future__ import annotations

import socket
import threading
import urllib.request

import pytest


def test_a_public_name_is_not_resolved() -> None:
    with pytest.raises(ConnectionRefusedError, match=r"resolve hol\.org"):
        socket.getaddrinfo("hol.org", 443)


def test_a_public_address_is_not_connected() -> None:
    with (
        socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock,
        pytest.raises(ConnectionRefusedError, match=r"connect 192\.0\.2\.1:443"),
    ):
        sock.connect(("192.0.2.1", 443))


def test_a_real_request_to_cloud_never_leaves_the_host() -> None:
    with pytest.raises(OSError, match="outbound network refused in test"):
        urllib.request.urlopen("https://hol.org/api/guard/session", timeout=2)


def test_a_background_thread_is_refused_too() -> None:
    errors: list[BaseException] = []

    def resolve() -> None:
        try:
            socket.getaddrinfo("hol.org", 443)
        except BaseException as error:
            errors.append(error)

    thread = threading.Thread(target=resolve)
    thread.start()
    thread.join(timeout=5)
    assert len(errors) == 1
    assert isinstance(errors[0], ConnectionRefusedError)


def test_loopback_stays_open() -> None:
    assert socket.getaddrinfo("127.0.0.1", 80)
    assert socket.getaddrinfo("localhost", 80)

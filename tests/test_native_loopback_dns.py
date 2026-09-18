"""Real loopback protocol and exact owned-file boundaries of the CI DNS fixture."""

from __future__ import annotations

import os
import socket
import struct
from pathlib import Path

import pytest

from scripts.ci import native_loopback_dns as dns

OWNER = "a" * 32


def _name(value: str) -> bytes:
    return b"".join(bytes([len(label)]) + label.encode() for label in value.split(".")) + b"\0"


def _query(*, name: str = dns.REVERSE_NAME, kind: int = 12, flags: int = 0x0100, additional: int = 0) -> bytes:
    return struct.pack("!6H", 0x1234, flags, 1, 0, 0, additional) + _name(name) + struct.pack("!HH", kind, 1)


@pytest.mark.parametrize("name", [dns.REVERSE_NAME, dns.REVERSE_NAME.upper()])
def test_fixed_ptr_answer_preserves_question_and_transaction(name: str) -> None:
    query = _query(name=name)
    response = dns.ptr_response(query)
    assert response is not None and len(response) <= dns.MAX_QUERY_BYTES
    assert struct.unpack("!6H", response[:12]) == (0x1234, 0x8500, 1, 1, 0, 0)
    assert response[12 : len(query)] == query[12:]
    target = _name(dns.LOOPBACK_NAME)
    assert response[len(query) :] == b"\xc0\x0c" + struct.pack("!HHIH", 12, 1, 0, len(target)) + target


def test_bounded_edns0_question_uses_same_fixed_answer() -> None:
    query = _query(additional=1) + b"\0" + struct.pack("!HHIH", 41, 1232, 0x8000, 0)
    assert dns.ptr_response(query) == dns.ptr_response(_query())


@pytest.mark.parametrize(
    "query",
    [
        b"",
        b"x" * 513,
        _query(name="2.0.0.127.in-addr.arpa"),
        _query(name="private.example"),
        _query(kind=1),
        _query(kind=28),
        _query(flags=0x8000),
        _query(flags=0x0800),
        _query(flags=0x0200),
        _query()[:-1],
        _query() + b"trailing",
        _query()[:12] + b"\xc0\x0c" + struct.pack("!HH", 12, 1),
        struct.pack("!6H", 1, 0, 2, 0, 0, 0) + _query()[12:] * 2,
        struct.pack("!6H", 1, 0, 1, 1, 0, 0) + _query()[12:],
        _query()[:-2] + struct.pack("!H", 3),
        _query(additional=1),
        _query(additional=1) + b"\0" + struct.pack("!HHIH", 41, 1232, 1 << 16, 0),
        _query(additional=1) + b"\0" + struct.pack("!HHIH", 1, 1232, 0, 0),
        _query(additional=1) + b"\0" + struct.pack("!HHIH", 41, 1232, 0, 8),
        _query(additional=1) + b"\0" + struct.pack("!HHIH", 41, 1232, 0, 1) + b"x",
        _query(additional=1) + b"\0" + struct.pack("!HHIH", 41, 1232, 0, 4) + struct.pack("!HH", 10, 12),
    ],
)
def test_other_questions_and_malformed_or_oversized_frames_are_not_answered(query: bytes) -> None:
    assert dns.ptr_response(query) is None


def test_real_udp_responder_is_loopback_only_and_shuts_down() -> None:
    with dns.LoopbackPTRResponder() as responder:
        assert responder._socket.getsockname() == ("127.0.0.1", responder.port)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(2)
            client.sendto(_query(name="private.example"), ("127.0.0.1", responder.port))
            client.sendto(b"x" * 513, ("127.0.0.1", responder.port))
            client.sendto(_query(), ("127.0.0.1", responder.port))
            response, peer = client.recvfrom(513)
            assert peer == ("127.0.0.1", responder.port)
            assert response == dns.ptr_response(_query())
    assert not responder._thread.is_alive() and responder._socket.fileno() == -1
    assert responder.snapshot() == {"received": 3, "answered": 1, "rejected": 2, "errors": 0}


@pytest.mark.parametrize(("port", "owner"), [(0, OWNER), (65536, OWNER), (True, OWNER), (12, "x" * 32), (12, "a\n")])
def test_configuration_rejects_unbounded_or_injected_values(port, owner) -> None:
    with pytest.raises(ValueError, match="resolver_configuration_invalid"):
        dns.resolver_configuration(port, owner)


@pytest.mark.skipif(os.name != "posix", reason="privileged resolver file operations are macOS/POSIX only")
def test_configuration_creates_only_fixed_file_and_removes_exact_owned_bytes(tmp_path: Path) -> None:
    directory = tmp_path / "resolver"
    assert dns.install_configuration(directory, 54321, OWNER)
    path = directory / dns.REVERSE_NAME
    assert list(directory.iterdir()) == [path]
    assert path.read_bytes() == dns.resolver_configuration(54321, OWNER)
    assert b"nameserver 127.0.0.1\n" in path.read_bytes()
    assert not dns.install_configuration(directory, 12345, "b" * 32)
    assert not dns.remove_configuration(directory, 54321, "b" * 32)
    assert dns.remove_configuration(directory, 54321, OWNER)
    assert not path.exists()
    assert dns.remove_configuration(directory, 54321, OWNER)


@pytest.mark.skipif(os.name != "posix", reason="privileged resolver file operations are macOS/POSIX only")
def test_changed_configuration_and_symlinks_are_never_removed(tmp_path: Path) -> None:
    directory = tmp_path / "resolver"
    assert dns.install_configuration(directory, 54321, OWNER)
    path = directory / dns.REVERSE_NAME
    changed = dns.resolver_configuration(54321, OWNER) + b"# another owner modified this\n"
    path.write_bytes(changed)
    assert not dns.remove_configuration(directory, 54321, OWNER)
    assert path.read_bytes() == changed
    path.unlink()
    target = tmp_path / "existing"
    target.write_bytes(dns.resolver_configuration(54321, OWNER))
    path.symlink_to(target)
    assert not dns.install_configuration(directory, 54321, OWNER)
    with pytest.raises(OSError):
        dns.remove_configuration(directory, 54321, OWNER)
    assert target.read_bytes() == dns.resolver_configuration(54321, OWNER)
    assert path.is_symlink()


@pytest.mark.skipif(os.name != "posix", reason="privileged resolver file operations are macOS/POSIX only")
def test_configuration_refuses_symlink_or_shared_writable_parent(tmp_path: Path) -> None:
    directory = tmp_path / "resolver"
    directory.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(directory, target_is_directory=True)
    with pytest.raises(OSError):
        dns.install_configuration(alias, 54321, OWNER)
    directory.chmod(0o777)
    with pytest.raises(ValueError, match="resolver_directory_not_private_to_owner"):
        dns.install_configuration(directory, 54321, OWNER)
    assert not list(directory.iterdir())

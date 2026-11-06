from __future__ import annotations

import os
import socket
import stat
import time
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

import pytest

from codex_plugin_scanner.guard import evaluation_witness as witness_module
from codex_plugin_scanner.guard.evaluation_witness import (
    LocalSideEffectWitness,
    NetworkWitnessPair,
    _rmtree_at,
)


@pytest.mark.skipif(os.name == "nt", reason="directory descriptors require POSIX")
def test_pinned_cleanup_fallback_keeps_symlink_target(tmp_path) -> None:
    owned = tmp_path / "owned"
    owned.mkdir()
    (owned / "nested").mkdir()
    (owned / "nested" / "file").write_bytes(b"owned")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep").write_bytes(b"keep")
    (owned / "outside-link").symlink_to(outside, target_is_directory=True)
    parent_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        _rmtree_at(parent_fd, owned.name)
    finally:
        os.close(parent_fd)
    assert not owned.exists()
    assert (outside / "keep").read_bytes() == b"keep"


@pytest.mark.skipif(os.name == "nt", reason="directory descriptors require POSIX")
def test_pinned_cleanup_restores_owner_write_to_nested_directories(tmp_path) -> None:
    owned = tmp_path / "owned"
    nested = owned / "nested"
    nested.mkdir(parents=True)
    (nested / "file").write_bytes(b"owned")
    nested.chmod(0o555)
    owned.chmod(0o555)
    parent_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        _rmtree_at(parent_fd, owned.name)
    finally:
        os.close(parent_fd)
        if owned.exists():
            owned.chmod(0o700)
        if nested.exists():
            nested.chmod(0o700)
    assert not owned.exists()


@pytest.mark.skipif(os.name == "nt", reason="directory descriptors require POSIX")
def test_pinned_cleanup_does_not_change_an_unopenable_directory(tmp_path, monkeypatch) -> None:
    owned = tmp_path / "owned"
    owned.mkdir(mode=0o700)
    owned.chmod(0o555)
    parent_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    real_open = os.open

    def reject_directory_open(path, flags, mode=0o777, *, dir_fd=None):
        if path == owned.name and dir_fd == parent_fd:
            raise PermissionError("cannot pin directory")
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(witness_module.os, "open", reject_directory_open)
    try:
        with pytest.raises(PermissionError, match="cannot pin directory"):
            _rmtree_at(parent_fd, owned.name)
        assert stat.S_IMODE(owned.stat().st_mode) == 0o555
    finally:
        os.close(parent_fd)
        owned.chmod(0o700)


@pytest.mark.skipif(os.name == "nt", reason="directory descriptors require POSIX")
def test_pinned_cleanup_fallback_rejects_directory_swap(tmp_path, monkeypatch) -> None:
    owned = tmp_path / "owned"
    owned.mkdir()
    (owned / "original").write_bytes(b"original")
    replacement = tmp_path / "replacement"
    replacement.mkdir()
    (replacement / "keep").write_bytes(b"keep")
    held = tmp_path / "held"
    parent_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    real_open = os.open

    def swap_before_open(path, flags, mode=0o777, *, dir_fd=None):
        if path == owned.name and dir_fd == parent_fd:
            owned.rename(held)
            replacement.rename(owned)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(witness_module.os, "open", swap_before_open)
    try:
        with pytest.raises(ValueError, match="changed before cleanup"):
            _rmtree_at(parent_fd, owned.name)
    finally:
        os.close(parent_fd)
    assert (owned / "keep").read_bytes() == b"keep"
    assert (held / "original").read_bytes() == b"original"


def _post(url: str) -> None:
    with urlopen(Request(url, data=b"", method="POST"), timeout=2) as response:
        assert response.status == 204


def test_network_witness_requires_reachable_receiver_and_allowed_counterpart() -> None:
    with LocalSideEffectWitness() as witness:
        pair = witness.new_network_pair()
        assert not witness.observe_network_pair(pair).receiver_conditions_met
        assert witness.check_network_ready()
        assert not witness.observe_network_pair(pair).receiver_conditions_met
        _post(pair.allowed_url)
        assert witness.observe_network_pair(pair).receiver_conditions_met
        _post(pair.denied_url)
        observation = witness.observe_network_pair(pair)
        assert observation.denied_reached
        assert not observation.receiver_conditions_met


def test_file_only_witness_does_not_start_network_receiver() -> None:
    with LocalSideEffectWitness(network_enabled=False) as witness:
        assert witness._server is None
        assert witness.check_file_ready()


def test_network_witness_rejects_unknown_and_nonempty_requests() -> None:
    with LocalSideEffectWitness() as witness:
        pair = witness.new_network_pair()
        assert witness.check_network_ready()
        with pytest.raises(HTTPError):
            _post(pair.allowed_url + "unknown")
        with pytest.raises(HTTPError), urlopen(Request(pair.allowed_url, data=b"secret", method="POST"), timeout=2):
            pass
        assert witness.observe_network_pair(pair).allowed_reached


def test_network_witness_rejects_mixed_registered_pairs() -> None:
    with LocalSideEffectWitness() as witness:
        first = witness.new_network_pair()
        second = witness.new_network_pair()
        with pytest.raises(ValueError, match="Unknown network witness pair"):
            witness.observe_network_pair(NetworkWitnessPair(first.denied_url, second.allowed_url))


def test_receiver_overload_invalidates_network_proof() -> None:
    with LocalSideEffectWitness() as witness:
        pair = witness.new_network_pair()
        assert witness.check_network_ready()
        port = urlsplit(pair.allowed_url).port
        assert port is not None
        connections: list[socket.socket] = []
        try:
            for _ in range(8):
                connection = socket.create_connection(("127.0.0.1", port), timeout=2)
                connection.sendall(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\n")
                connections.append(connection)
            deadline = time.monotonic() + 2
            server = witness._server
            assert server is not None
            while server._slots._value and time.monotonic() < deadline:
                time.sleep(0.01)
            assert server._slots._value == 0
            overflow = socket.create_connection(("127.0.0.1", port), timeout=2)
            connections.append(overflow)
            overflow.sendall(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            while not witness._overloaded and time.monotonic() < deadline:
                time.sleep(0.01)
            assert witness._overloaded
            assert not witness.observe_network_pair(pair).receiver_ready
        finally:
            for connection in connections:
                connection.close()

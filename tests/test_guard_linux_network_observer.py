import hashlib
import hmac
import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.linux_network_observer import (
    LinuxNetworkObservationError,
    LinuxProcessIdentity,
    observe_linux_sockets,
)
from codex_plugin_scanner.guard.runtime.network_policy_contract import NetworkProtocol

_HEADER = "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode"
_KEY = bytes(range(32))


def _prepare_process(root: Path, pid: int, start_time: int = 123) -> Path:
    process_root = root / str(pid)
    network_root = process_root / "net"
    fd_root = process_root / "fd"
    _ = network_root.mkdir(parents=True)
    _ = fd_root.mkdir()
    fields = ["S", *("0" for _ in range(18)), str(start_time), *("0" for _ in range(5))]
    _ = (process_root / "stat").write_text(f"{pid} (worker ) name) {' '.join(fields)}", encoding="ascii")
    for name in ("tcp", "tcp6", "udp", "udp6"):
        _ = (network_root / name).write_text(f"{_HEADER}\n", encoding="ascii")
    return process_root


def _write_rows(root: Path, pid: int, name: str, rows: list[str]) -> None:
    body = "\n".join(rows)
    _ = (root / str(pid) / "net" / name).write_text(f"{_HEADER}\n{body}\n", encoding="ascii")


def test_linux_observer_scopes_procfs_to_owned_sockets_and_pseudonymizes(tmp_path: Path) -> None:
    process_root = _prepare_process(tmp_path, 42)
    _ = os.symlink("socket:[77]", process_root / "fd" / "3")
    _write_rows(
        tmp_path,
        42,
        "tcp",
        [
            "0: 0100007F:1234 08080808:01BB 01 0:0 0:0 00:0 0 1000 0 77",
            "1: 0100007F:1234 01010101:0035 01 0:0 0:0 00:0 0 1000 0 88",
        ],
    )

    observations = observe_linux_sockets(
        proc_root=tmp_path,
        target=LinuxProcessIdentity(42, 123),
        rotation_key=_KEY,
    )

    assert len(observations) == 1
    observation = observations[0]
    assert observation.protocol is NetworkProtocol.TCP
    assert observation.remote_port == 443
    assert observation.socket_inode == 77
    assert observation.tcp_state == 1
    expected = hmac.digest(
        _KEY,
        b"HOL-GUARD/evidence-pseudonym/v1\0procfs.remote-address\0" + bytes((8, 8, 8, 8)),
        "sha256",
    ).hex()
    assert observation.remote_address_pseudonym == expected
    assert observation.remote_address_pseudonym != hashlib.sha256(bytes((8, 8, 8, 8))).hexdigest()
    rotated = observe_linux_sockets(
        proc_root=tmp_path,
        target=LinuxProcessIdentity(42, 123),
        rotation_key=bytes(range(1, 33)),
    )[0]
    assert rotated.remote_address_pseudonym != expected
    assert "8.8.8.8" not in repr(observation)


def test_linux_observer_accepts_kernel_new_syn_recv_state(tmp_path: Path) -> None:
    process_root = _prepare_process(tmp_path, 42)
    _ = os.symlink("socket:[77]", process_root / "fd" / "3")
    _write_rows(
        tmp_path,
        42,
        "tcp",
        ["0: 0100007F:1234 08080808:01BB 0C 0:0 0:0 00:0 0 1000 0 77"],
    )

    observation = observe_linux_sockets(
        proc_root=tmp_path,
        target=LinuxProcessIdentity(42, 123),
        rotation_key=_KEY,
    )[0]

    assert observation.tcp_state == 12


def test_linux_observer_fails_closed_on_malformed_row(tmp_path: Path) -> None:
    _ = _prepare_process(tmp_path, 42)
    _write_rows(tmp_path, 42, "udp", ["malformed"])

    with pytest.raises(LinuxNetworkObservationError, match="malformed udp"):
        _ = observe_linux_sockets(
            proc_root=tmp_path,
            target=LinuxProcessIdentity(42, 123),
            rotation_key=_KEY,
        )


def test_linux_observer_rejects_pid_reuse(tmp_path: Path) -> None:
    _ = _prepare_process(tmp_path, 42, start_time=124)
    with pytest.raises(LinuxNetworkObservationError, match="process identity changed"):
        _ = observe_linux_sockets(
            proc_root=tmp_path,
            target=LinuxProcessIdentity(42, 123),
            rotation_key=_KEY,
        )

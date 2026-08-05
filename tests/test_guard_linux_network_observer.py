import hashlib
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.linux_network_observer import (
    LinuxNetworkObservationError,
    observe_linux_sockets,
)
from codex_plugin_scanner.guard.runtime.network_policy_contract import NetworkProtocol

_HEADER = "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode"


def _write_table(root: Path, pid: int, name: str, row: str) -> None:
    network_root = root / str(pid) / "net"
    network_root.mkdir(parents=True, exist_ok=True)
    (network_root / name).write_text(f"{_HEADER}\n{row}\n", encoding="ascii")


def test_linux_observer_projects_procfs_without_raw_address(tmp_path: Path) -> None:
    _write_table(
        tmp_path,
        42,
        "tcp",
        "0: 0100007F:1234 08080808:01BB 01 0:0 0:0 00:0 0 1000 0 77",
    )

    observations = observe_linux_sockets(proc_root=tmp_path, pid=42)

    assert len(observations) == 1
    observation = observations[0]
    assert observation.protocol is NetworkProtocol.TCP
    assert observation.remote_port == 443
    assert observation.socket_inode == 77
    assert observation.tcp_state == 1
    assert observation.remote_address_digest == hashlib.sha256(bytes((8, 8, 8, 8))).hexdigest()
    assert "8.8.8.8" not in repr(observation)


def test_linux_observer_fails_closed_on_malformed_row(tmp_path: Path) -> None:
    _write_table(tmp_path, 42, "udp", "malformed")

    with pytest.raises(LinuxNetworkObservationError, match="malformed udp"):
        observe_linux_sockets(proc_root=tmp_path, pid=42)

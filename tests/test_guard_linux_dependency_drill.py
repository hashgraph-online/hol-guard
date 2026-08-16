import os
import sqlite3
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from codex_plugin_scanner.guard.runtime.linux_artifact_supply_chain import (
    LinuxArtifactSupplyChainError,
    LinuxArtifactSupplyChainManifest,
    LinuxArtifactSupplyChainReceipt,
    create_linux_artifact_supply_chain_manifest,
    verify_linux_artifact_supply_chain,
)
from codex_plugin_scanner.guard.runtime.linux_network_observer import (
    LinuxProcessIdentity,
    observe_linux_sockets,
)
from codex_plugin_scanner.guard.runtime.linux_tetragon_observer import (
    TetragonCollectorPolicy,
    TetragonObservationError,
    TetragonReplayLedger,
    TetragonTargetIdentity,
    create_tetragon_collector_envelope,
    observe_tetragon_events,
)

_ARTIFACT = b"privileged-linux-artifact"
_PROC_HEADER = "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode"
_SBOM = b'{"bomFormat":"CycloneDX","components":[]}'
_SOURCE_DIGEST = "a" * 64
_TRUSTED_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
_COMPROMISED_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
_ROTATION_KEY = bytes(range(32))


def _tetragon_policy() -> TetragonCollectorPolicy:
    return TetragonCollectorPolicy("collector-a", "worker-a", "stream-a", _public_key(_TRUSTED_KEY))


def _public_key(key: Ed25519PrivateKey) -> str:
    return (
        key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        .hex()
    )


def _manifest(
    key: Ed25519PrivateKey,
    key_id: str,
) -> LinuxArtifactSupplyChainManifest:
    return create_linux_artifact_supply_chain_manifest(
        component_id="guard-linux-ebpf",
        version="3.0.0",
        release_sequence=1,
        artifact=_ARTIFACT,
        sbom=_SBOM,
        source_digest=_SOURCE_DIGEST,
        builder_id="github-actions-release",
        key_id=key_id,
        signing_key=key,
    )


def _verify(
    key: Ed25519PrivateKey,
    key_id: str,
    *,
    revoked: frozenset[str] | None = None,
) -> LinuxArtifactSupplyChainReceipt:
    return verify_linux_artifact_supply_chain(
        _manifest(key, key_id),
        artifact=_ARTIFACT,
        expected_release_sequence=1,
        sbom=_SBOM,
        expected_component_id="guard-linux-ebpf",
        expected_version="3.0.0",
        expected_source_digest=_SOURCE_DIGEST,
        trusted_builder_ids=frozenset({"github-actions-release"}),
        trusted_public_keys={"release-2026": _public_key(_TRUSTED_KEY)},
        revoked_key_ids=revoked,
    )


def test_optional_tetragon_unavailability_preserves_procfs_observer(tmp_path: Path) -> None:
    process_root = tmp_path / "42"
    network_root = process_root / "net"
    fd_root = process_root / "fd"
    network_root.mkdir(parents=True)
    fd_root.mkdir()
    os.symlink("socket:[77]", fd_root / "3")
    fields = ["S", *("0" for _ in range(18)), "123", *("0" for _ in range(5))]
    _ = (process_root / "stat").write_text(f"42 (guard) {' '.join(fields)}", encoding="ascii")
    for name in ("tcp", "tcp6", "udp", "udp6"):
        rows = "0: 0100007F:1234 08080808:01BB 01 0:0 0:0 00:0 0 1000 0 77" if name == "tcp" else ""
        _ = (network_root / name).write_text(f"{_PROC_HEADER}\n{rows}\n", encoding="ascii")

    assert (
        observe_tetragon_events(
            [],
            policy=_tetragon_policy(),
            target=TetragonTargetIdentity(42, 123, 99),
            rotation_key=_ROTATION_KEY,
            replay_ledger=TetragonReplayLedger(sqlite3.connect(":memory:", isolation_level=None)),
        )
        == ()
    )
    observations = observe_linux_sockets(
        proc_root=tmp_path,
        target=LinuxProcessIdentity(42, 123),
        rotation_key=_ROTATION_KEY,
    )
    assert len(observations) == 1
    assert observations[0].socket_inode == 77


def test_compromised_tetragon_evidence_fails_closed() -> None:
    payload = b'{"process_connect":{},"time":"2026-08-05T10:00:00Z"}'
    event = create_tetragon_collector_envelope(
        payload,
        collector_id="collector-a",
        node_id="worker-a",
        stream_id="stream-a",
        sequence=1,
        signing_key=_COMPROMISED_KEY,
    )
    with pytest.raises(TetragonObservationError, match="signature is invalid"):
        _ = observe_tetragon_events(
            [event],
            policy=_tetragon_policy(),
            target=TetragonTargetIdentity(42, 123, 99),
            rotation_key=_ROTATION_KEY,
            replay_ledger=TetragonReplayLedger(sqlite3.connect(":memory:", isolation_level=None)),
        )


def test_untrusted_dependency_signing_key_cannot_substitute_artifact() -> None:
    with pytest.raises(LinuxArtifactSupplyChainError, match="signer is not trusted"):
        _ = _verify(_COMPROMISED_KEY, "compromised-key")


def test_compromised_previously_trusted_key_is_revoked() -> None:
    with pytest.raises(LinuxArtifactSupplyChainError, match="signer is revoked"):
        _ = _verify(_TRUSTED_KEY, "release-2026", revoked=frozenset({"release-2026"}))

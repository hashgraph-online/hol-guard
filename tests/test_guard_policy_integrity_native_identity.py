"""Do not destroy the native signing identity when Linux keyring sessions differ."""

from __future__ import annotations

import base64
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_command_control_authority import (
    AUTHORITY_FILE_NAME,
    AUTHORITY_MAX_BYTES,
    AUTHORITY_SCHEMA,
    encode_authority,
)
from codex_plugin_scanner.guard.native_command_control_authority_io import write_private_state
from codex_plugin_scanner.guard.native_policy_snapshot_codec import derive_native_policy_verifier_key
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NATIVE_POLICY_VERIFIER_KEY_NAME
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_policy_integrity_backend import MirroredPolicyIntegritySecretStore
from tests.test_guard_extension_control_authority import MemorySecretStore

PRIMARY = base64.urlsafe_b64encode(b"p" * 32).decode("ascii")
FALLBACK = base64.urlsafe_b64encode(b"f" * 32).decode("ascii")


def _setup(home: Path, *, signer: bytes = b"f" * 32) -> tuple[GuardStore, MirroredPolicyIntegritySecretStore]:
    store = GuardStore(home, prime_policy_integrity=False)
    backend = MirroredPolicyIntegritySecretStore(MemorySecretStore(), MemorySecretStore(), guard_home=home)
    store._policy_integrity_secret_store = backend
    backend.primary.set_secret(store._policy_integrity_key_ref, PRIMARY)
    backend.fallback.set_secret(store._policy_integrity_key_ref, FALLBACK)
    marker = {
        "schema": AUTHORITY_SCHEMA,
        "epoch": 2,
        "mutation_revision": 11,
        "authority_key_id": "0" * 64,
        "phase": "closed",
        "effective_digest": None,
        "recovery": None,
    }
    write_private_state(
        home,
        AUTHORITY_FILE_NAME,
        encode_authority(marker, derive_native_policy_verifier_key(signer)),
        AUTHORITY_MAX_BYTES,
    )
    return store, backend


def _assert_copies_preserved(store: GuardStore, backend: MirroredPolicyIntegritySecretStore) -> None:
    assert backend.primary.get_secret(store._policy_integrity_key_ref) == PRIMARY
    assert backend.fallback.get_secret(store._policy_integrity_key_ref) == FALLBACK


def test_authenticated_native_key_wins_without_replacing_either_backend(tmp_path: Path) -> None:
    store, backend = _setup(tmp_path)
    write_private_state(tmp_path, NATIVE_POLICY_VERIFIER_KEY_NAME, derive_native_policy_verifier_key(b"f" * 32), 32)
    assert backend.get_secret(store._policy_integrity_key_ref) == FALLBACK
    _assert_copies_preserved(store, backend)


def test_authenticated_primary_repairs_the_stale_local_copy(tmp_path: Path) -> None:
    store, backend = _setup(tmp_path, signer=b"p" * 32)
    assert backend.get_secret(store._policy_integrity_key_ref) == PRIMARY
    assert backend.fallback.get_secret(store._policy_integrity_key_ref) == PRIMARY


def test_unverifiable_marker_preserves_both_copies_for_explicit_recovery(tmp_path: Path) -> None:
    store, backend = _setup(tmp_path, signer=b"x" * 32)
    assert backend.get_secret(store._policy_integrity_key_ref) == PRIMARY
    _assert_copies_preserved(store, backend)


@pytest.mark.parametrize("conflict", ["verifier", "floor", "malformed-marker"])
def test_partial_native_evidence_cannot_select_or_overwrite_a_key(tmp_path: Path, conflict: str) -> None:
    store, backend = _setup(tmp_path)
    if conflict == "verifier":
        write_private_state(tmp_path, NATIVE_POLICY_VERIFIER_KEY_NAME, derive_native_policy_verifier_key(b"p" * 32), 32)
    elif conflict == "floor":
        write_private_state(tmp_path, "policy-snapshot-v3.json", b"{}", 280 * 1024)
    else:
        write_private_state(tmp_path, AUTHORITY_FILE_NAME, b"{}", AUTHORITY_MAX_BYTES)
    assert backend.get_secret(store._policy_integrity_key_ref) == PRIMARY
    _assert_copies_preserved(store, backend)


@pytest.mark.parametrize("value", ["!", "not-a-key", "\u2603", base64.urlsafe_b64encode(b"short").decode("ascii")])
def test_malformed_primary_does_not_replace_the_authenticated_local_key(tmp_path: Path, value: str) -> None:
    store, backend = _setup(tmp_path)
    backend.primary.set_secret(store._policy_integrity_key_ref, value)
    assert backend.get_secret(store._policy_integrity_key_ref) == FALLBACK
    assert backend.fallback.get_secret(store._policy_integrity_key_ref) == FALLBACK
    assert backend.primary.get_secret(store._policy_integrity_key_ref) == value


def test_missing_marker_does_not_let_a_returning_keyring_destroy_the_local_copy(tmp_path: Path) -> None:
    store, backend = _setup(tmp_path)
    (tmp_path / "native-runtime" / AUTHORITY_FILE_NAME).unlink()
    write_private_state(tmp_path, NATIVE_POLICY_VERIFIER_KEY_NAME, derive_native_policy_verifier_key(b"f" * 32), 32)
    assert backend.get_secret(store._policy_integrity_key_ref) == PRIMARY
    _assert_copies_preserved(store, backend)


def test_primary_unavailable_keeps_local_key_readable(tmp_path: Path) -> None:
    store, backend = _setup(tmp_path)
    assert isinstance(backend.primary, MemorySecretStore)
    backend.primary.available = False
    assert backend.get_secret(store._policy_integrity_key_ref) == FALLBACK
    assert backend.fallback.get_secret(store._policy_integrity_key_ref) == FALLBACK


def test_first_publication_still_mirrors_primary(tmp_path: Path) -> None:
    store, backend = _setup(tmp_path)
    (tmp_path / "native-runtime" / AUTHORITY_FILE_NAME).unlink()
    assert backend.get_secret(store._policy_integrity_key_ref) == PRIMARY
    assert backend.fallback.get_secret(store._policy_integrity_key_ref) == PRIMARY


def _legacy_floor(home: Path, key: bytes) -> bytes:
    from codex_plugin_scanner.guard.native_policy_snapshot_codec import (
        _canonical_json_bytes_v3,
        _generation_floor_mac_v3,
    )

    verifier = derive_native_policy_verifier_key(key)
    encoded = _canonical_json_bytes_v3(
        {
            "schema": "guard-policy-snapshot-generation-floor.v1",
            "generation": 19,
            "policy_digest": "d" * 64,
            "mac": _generation_floor_mac_v3(19, "d" * 64, verifier),
        }
    )
    write_private_state(home, "policy-snapshot-generation-floor.json", encoded, 8 * 1024)
    return encoded


def test_stale_primary_marker_cannot_replace_the_legacy_floor_key(tmp_path: Path) -> None:
    store, backend = _setup(tmp_path, signer=b"p" * 32)
    encoded = _legacy_floor(tmp_path, b"f" * 32)
    assert backend.get_secret(store._policy_integrity_key_ref) == PRIMARY
    _assert_copies_preserved(store, backend)
    assert (tmp_path / "native-runtime" / "policy-snapshot-generation-floor.json").read_bytes() == encoded


def test_a_legacy_floor_alone_prevents_destructive_key_mirroring(tmp_path: Path) -> None:
    store, backend = _setup(tmp_path)
    (tmp_path / "native-runtime" / AUTHORITY_FILE_NAME).unlink()
    _legacy_floor(tmp_path, b"f" * 32)
    assert backend.get_secret(store._policy_integrity_key_ref) == PRIMARY
    _assert_copies_preserved(store, backend)


def test_primary_must_also_authenticate_the_legacy_floor_before_mirroring(tmp_path: Path) -> None:
    store, backend = _setup(tmp_path, signer=b"p" * 32)
    _legacy_floor(tmp_path, b"p" * 32)
    assert backend.get_secret(store._policy_integrity_key_ref) == PRIMARY
    assert backend.fallback.get_secret(store._policy_integrity_key_ref) == PRIMARY


@pytest.mark.parametrize(
    "corruption",
    [
        "schema",
        "fields",
        "generation-zero",
        "generation-bool",
        "generation-overflow",
        "digest",
        "mac",
        "noncanonical",
        "duplicate",
        "not-object",
    ],
)
def test_invalid_legacy_floor_never_authorizes_key_replacement(tmp_path: Path, corruption: str) -> None:
    import json

    from codex_plugin_scanner.guard.native_policy_snapshot_codec import _canonical_json_bytes_v3

    store, backend = _setup(tmp_path, signer=b"p" * 32)
    original = _legacy_floor(tmp_path, b"p" * 32)
    record = json.loads(original)
    if corruption == "schema":
        record["schema"] = "unknown"
    elif corruption == "fields":
        record["extra"] = True
    elif corruption == "generation-zero":
        record["generation"] = 0
    elif corruption == "generation-bool":
        record["generation"] = True
    elif corruption == "generation-overflow":
        record["generation"] = 1 << 64
    elif corruption == "digest":
        record["policy_digest"] = "D" * 64
    elif corruption == "mac":
        record["mac"] = "0" * 64
    encoded = _canonical_json_bytes_v3(record)
    if corruption == "noncanonical":
        encoded += b"\n"
    elif corruption == "duplicate":
        encoded = original[:-1] + b',"generation":19}'
    elif corruption == "not-object":
        encoded = b"[]"
    write_private_state(tmp_path, "policy-snapshot-generation-floor.json", encoded, 8 * 1024)
    assert backend.get_secret(store._policy_integrity_key_ref) == PRIMARY
    _assert_copies_preserved(store, backend)


@pytest.mark.parametrize("read_key_first", [False, True])
def test_returning_keyring_cannot_separate_control_metadata_from_local_key(
    tmp_path: Path, read_key_first: bool
) -> None:
    store, backend = _setup(tmp_path)
    primary_control = '{"version":1,"generation":1,"pending_generation":null,"cutover_complete":true}'
    fallback_control = '{"version":1,"generation":7,"pending_generation":null,"cutover_complete":true}'
    backend.primary.set_secret(store._policy_integrity_control_ref, primary_control)
    backend.fallback.set_secret(store._policy_integrity_control_ref, fallback_control)
    if read_key_first:
        assert backend.get_secret(store._policy_integrity_key_ref) == FALLBACK
    assert backend.get_secret(store._policy_integrity_control_ref) == fallback_control
    assert backend.get_secret(store._policy_integrity_key_ref) == FALLBACK
    assert backend.primary.get_secret(store._policy_integrity_control_ref) == primary_control
    assert backend.fallback.get_secret(store._policy_integrity_control_ref) == fallback_control
    _assert_copies_preserved(store, backend)


@pytest.mark.parametrize("verifier", [b"", b"short"])
def test_truncated_resident_verifier_preserves_both_key_copies(tmp_path: Path, verifier: bytes) -> None:
    store, backend = _setup(tmp_path)
    path = tmp_path / "native-runtime" / NATIVE_POLICY_VERIFIER_KEY_NAME
    path.write_bytes(verifier)
    path.chmod(0o600)
    assert backend.get_secret(store._policy_integrity_key_ref) == PRIMARY
    _assert_copies_preserved(store, backend)


def test_dangling_authority_symlink_is_not_treated_as_a_fresh_home(tmp_path: Path) -> None:
    store, backend = _setup(tmp_path)
    marker = tmp_path / "native-runtime" / AUTHORITY_FILE_NAME
    marker.unlink()
    try:
        marker.symlink_to(tmp_path / "missing-marker")
    except OSError:
        pytest.skip("symlink creation unavailable")
    assert backend.get_secret(store._policy_integrity_key_ref) == PRIMARY
    _assert_copies_preserved(store, backend)
    assert marker.is_symlink()


def test_control_update_stays_with_the_authenticated_local_key(tmp_path: Path) -> None:
    store, backend = _setup(tmp_path)
    backend.primary.set_secret(store._policy_integrity_control_ref, "old-primary-control")
    backend.fallback.set_secret(store._policy_integrity_control_ref, "old-local-control")
    backend.set_secret(store._policy_integrity_control_ref, "updated-local-control")
    assert backend.get_secret(store._policy_integrity_control_ref) == "updated-local-control"
    assert backend.primary.get_secret(store._policy_integrity_control_ref) == "old-primary-control"
    _assert_copies_preserved(store, backend)


def test_unverified_control_update_preserves_both_identities(tmp_path: Path) -> None:
    store, backend = _setup(tmp_path, signer=b"x" * 32)
    backend.primary.set_secret(store._policy_integrity_control_ref, "primary-control")
    backend.fallback.set_secret(store._policy_integrity_control_ref, "local-control")
    with pytest.raises(RuntimeError, match="could not be verified"):
        backend.set_secret(store._policy_integrity_control_ref, "replacement-control")
    assert backend.primary.get_secret(store._policy_integrity_control_ref) == "primary-control"
    assert backend.fallback.get_secret(store._policy_integrity_control_ref) == "local-control"
    _assert_copies_preserved(store, backend)


def test_primary_key_and_matching_control_are_mirrored_together(tmp_path: Path) -> None:
    store, backend = _setup(tmp_path, signer=b"p" * 32)
    backend.primary.set_secret(store._policy_integrity_control_ref, "primary-control")
    backend.fallback.set_secret(store._policy_integrity_control_ref, "old-control")
    assert backend.get_secret(store._policy_integrity_key_ref) == PRIMARY
    assert backend.fallback.get_secret(store._policy_integrity_key_ref) == PRIMARY
    assert backend.fallback.get_secret(store._policy_integrity_control_ref) == "primary-control"

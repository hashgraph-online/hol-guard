"""Bounded signed marker, durable private writes, and cross-process locking."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import subprocess
import sys
from copy import deepcopy
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_command_control_authority import (
    AUTHORITY_DOMAIN,
    AUTHORITY_FILE_NAME,
    AUTHORITY_KEY_DOMAIN,
    AUTHORITY_MAX_BYTES,
    AUTHORITY_SCHEMA,
    FLOOR_LINK_DOMAIN,
    RECOVERY_SCHEMA,
    ZERO_DIGEST,
    authority_binding,
    authority_key_id,
    decode_authority,
    encode_authority,
    floor_link_digest,
    validate_authority_binding,
    validate_control_floor,
)
from codex_plugin_scanner.guard.native_command_control_authority_io import (
    NativeCommandControlMutationRequiredError,
    hold_command_control_authority_lock,
    read_private_state,
    require_command_control_mutation_lease,
    write_private_state,
)
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError

KEY = b"k" * 32


def test_shared_python_rust_authority_vectors() -> None:
    path = Path(__file__).parents[1] / "contracts/extensions/native-command-control-authority.v1.fixtures.json"
    fixture = json.loads(path.read_text())
    verifier_key = bytes.fromhex(fixture["verifier_key_hex"])
    for vector in fixture["vectors"]:
        expected = vector["canonical_signed_json"].encode()
        assert encode_authority(vector["record"], verifier_key) == expected
        assert decode_authority(expected, verifier_key)["schema"] == AUTHORITY_SCHEMA
    assert floor_link_digest(fixture["current_floor"]) == fixture["current_floor_link_digest"]
    assert floor_link_digest(None) == fixture["null_floor_link_digest"]


def _record() -> dict:
    return {
        "schema": AUTHORITY_SCHEMA,
        "epoch": 2,
        "mutation_revision": 9,
        "authority_key_id": "1" * 64,
        "phase": "committed",
        "effective_digest": "2" * 64,
        "recovery": {
            "schema": RECOVERY_SCHEMA,
            "previous_epoch": 1,
            "previous_mutation_revision": 6,
            "previous_authority_key_id": "3" * 64,
            "previous_floor_digest": "4" * 64,
            "nonce": "5" * 64,
        },
    }


def test_authority_domains_and_exact_body_authentication() -> None:
    body = _record()
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    encoded = encode_authority(body, KEY)
    decoded = decode_authority(encoded, KEY)
    assert decoded["mac"] == hmac.new(KEY, AUTHORITY_DOMAIN + canonical, hashlib.sha256).hexdigest()
    assert authority_binding(decoded) == {
        key: body[key] for key in ("epoch", "mutation_revision", "authority_key_id", "recovery")
    }
    assert authority_key_id(KEY) == hashlib.sha256(AUTHORITY_KEY_DOMAIN + KEY).hexdigest()
    assert authority_key_id(None) == ZERO_DIGEST
    assert floor_link_digest(None) == hashlib.sha256(FLOOR_LINK_DOMAIN + b"null").hexdigest()
    with pytest.raises(NativePolicySnapshotError, match="integrity"):
        decode_authority(encoded, b"x" * 32)
    with pytest.raises(NativePolicySnapshotError, match="integrity"):
        decode_authority(encoded.replace(b'"mutation_revision":9', b'"mutation_revision":8'), KEY)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema", "unknown"),
        ("epoch", True),
        ("epoch", 0),
        ("mutation_revision", 0),
        ("mutation_revision", 1 << 64),
        ("authority_key_id", "A" * 64),
        ("phase", "open"),
        ("phase", []),
        ("effective_digest", None),
        ("recovery", {}),
        ("unknown", 1),
    ],
)
def test_invalid_marker_shapes_are_not_signed(field: str, value: object) -> None:
    candidate = _record()
    candidate[field] = value
    with pytest.raises(NativePolicySnapshotError):
        encode_authority(candidate, KEY)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema", "unknown"),
        ("previous_epoch", 2),
        ("previous_epoch", -1),
        ("previous_mutation_revision", 9),
        ("previous_mutation_revision", False),
        ("previous_authority_key_id", None),
        ("previous_floor_digest", "g" * 64),
        ("nonce", "x"),
        ("unknown", 1),
    ],
)
def test_recovery_requires_valid_prior_context(field: str, value: object) -> None:
    candidate = _record()
    candidate["recovery"][field] = value
    with pytest.raises(NativePolicySnapshotError):
        encode_authority(candidate, KEY)


def test_closed_marker_has_no_effective_digest_and_decoding_is_bounded() -> None:
    candidate = {**_record(), "phase": "closed", "effective_digest": None}
    encoded = encode_authority(candidate, KEY)
    assert decode_authority(encoded, KEY)["phase"] == "closed"
    with pytest.raises(NativePolicySnapshotError):
        encode_authority({**candidate, "effective_digest": "a" * 64}, KEY)
    for invalid in (b"", b"x" * (AUTHORITY_MAX_BYTES + 1), b'{"epoch":1,"epoch":2}'):
        with pytest.raises(NativePolicySnapshotError):
            decode_authority(invalid, KEY)


def test_extended_floor_authenticates_the_retained_recovery_link() -> None:
    authority = authority_binding(_record())
    floor = {
        "revision": 0,
        "managed_revision": 2,
        "effective_digest": "a" * 64,
        "authority": authority,
        "previous_floor_digest": "4" * 64,
    }
    assert validate_control_floor(floor) == floor
    changed = deepcopy(floor)
    changed["previous_floor_digest"] = "b" * 64
    with pytest.raises(NativePolicySnapshotError):
        validate_control_floor(changed)
    with pytest.raises(NativePolicySnapshotError):
        validate_authority_binding({**authority, "unknown": 1})


def test_private_marker_handles_short_writes_and_rejects_links(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import codex_plugin_scanner.guard.native_command_control_authority_io as io_module

    encoded = encode_authority(_record(), KEY)
    original_write = os.write
    monkeypatch.setattr(io_module.os, "write", lambda fd, data: original_write(fd, data[:7]))
    write_private_state(tmp_path, AUTHORITY_FILE_NAME, encoded, AUTHORITY_MAX_BYTES)
    assert read_private_state(tmp_path, AUTHORITY_FILE_NAME, AUTHORITY_MAX_BYTES) == encoded
    path = tmp_path / "native-runtime" / AUTHORITY_FILE_NAME
    if os.name != "nt":
        linked = tmp_path / "linked.json"
        os.link(path, linked)
        with pytest.raises(NativePolicySnapshotError):
            read_private_state(tmp_path, AUTHORITY_FILE_NAME, AUTHORITY_MAX_BYTES)
        linked.unlink()
        path.unlink()
        path.symlink_to(tmp_path / "absent.json")
        with pytest.raises(OSError):
            read_private_state(tmp_path, AUTHORITY_FILE_NAME, AUTHORITY_MAX_BYTES)


def test_mutation_requirement_accepts_exclusive_lease_and_rejects_shared_lease(tmp_path: Path) -> None:
    with hold_command_control_authority_lock(tmp_path):
        require_command_control_mutation_lease(tmp_path)
    with hold_command_control_authority_lock(tmp_path, shared=True):
        with pytest.raises(NativeCommandControlMutationRequiredError):
            require_command_control_mutation_lease(tmp_path)


@pytest.mark.skipif(os.name == "nt", reason="POSIX retained-inode identity replacement fault")
def test_mutation_lock_rejects_inode_replacement_and_allows_same_thread_reads(tmp_path: Path) -> None:
    with (
        pytest.raises(NativePolicySnapshotError, match="path_invalid"),
        hold_command_control_authority_lock(tmp_path),
    ):
        with hold_command_control_authority_lock(tmp_path, timeout_seconds=0):
            pass
        with hold_command_control_authority_lock(tmp_path / ".." / tmp_path.name, timeout_seconds=0):
            pass
        lock = tmp_path / "extension-control-authority.lock"
        lock.rename(tmp_path / "old.lock")
        lock.write_bytes(b"0")
    with hold_command_control_authority_lock(tmp_path):
        assert (tmp_path / "extension-control-authority.lock").stat().st_mode & 0o777 == 0o600


@pytest.mark.skipif(not hasattr(os, "fork"), reason="fork inheritance is a POSIX process boundary")
def test_fork_does_not_inherit_reentrant_mutation_ownership(tmp_path: Path) -> None:
    with hold_command_control_authority_lock(tmp_path):
        child = os.fork()
        if child == 0:
            try:
                with hold_command_control_authority_lock(tmp_path, timeout_seconds=0):
                    os._exit(2)
            except TimeoutError:
                os._exit(0)
            except BaseException:
                os._exit(3)
        _, status = os.waitpid(child, 0)
        assert os.waitstatus_to_exitcode(status) == 0


@pytest.mark.skipif(not hasattr(os, "fork"), reason="fork inheritance is a POSIX process boundary")
@pytest.mark.parametrize("shared", [False, True])
def test_child_unwinding_inherited_context_does_not_unlock_parent(tmp_path: Path, shared: bool) -> None:
    parent = os.getpid()
    try:
        with hold_command_control_authority_lock(tmp_path, shared=shared):
            child = os.fork()
            if child == 0:
                return  # Unwind the inherited context before exiting this process.
            _, status = os.waitpid(child, 0)
            assert os.waitstatus_to_exitcode(status) == 0
            script = """
import fcntl, pathlib, sys
with (pathlib.Path(sys.argv[1]) / 'extension-control-authority.lock').open('r+b') as handle:
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        sys.exit(0)
    sys.exit(2)
"""
            result = subprocess.run([sys.executable, "-c", script, str(tmp_path)], timeout=5, check=False)
            assert result.returncode == 0
    finally:
        if os.getpid() != parent:
            os._exit(0)


@pytest.mark.skipif(os.name == "nt", reason="Windows fs2/msvcrt overlap is qualified by the native integration suite")
def test_foreign_shared_evaluation_lease_excludes_python_mutation(tmp_path: Path) -> None:
    with hold_command_control_authority_lock(tmp_path):
        pass
    script = """
import fcntl, pathlib, sys
with (pathlib.Path(sys.argv[1]) / 'extension-control-authority.lock').open('r+b') as handle:
    fcntl.flock(handle.fileno(), fcntl.LOCK_SH)
    print('leased', flush=True)
    sys.stdin.readline()
"""
    process = subprocess.Popen(
        [sys.executable, "-c", script, str(tmp_path)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True
    )
    try:
        assert process.stdout is not None and process.stdout.readline() == "leased\n"
        with pytest.raises(TimeoutError), hold_command_control_authority_lock(tmp_path, timeout_seconds=0):
            pytest.fail("mutation acquired a shared evaluation lease")
        process.communicate("release\n", timeout=5)
        assert process.returncode == 0
        with hold_command_control_authority_lock(tmp_path, timeout_seconds=0):
            pass
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)

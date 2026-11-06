"""Compatibility façade for generation-bound native policy snapshots.

The public import path remains stable while protocol, storage, platform, and
publisher implementations live in bounded modules.
"""

from __future__ import annotations

import os
import stat
import threading
from pathlib import Path
from typing import TYPE_CHECKING

from . import native_policy_snapshot_codec as _codec
from . import native_policy_snapshot_constants as _constants
from . import native_policy_snapshot_contract as _contract
from . import native_policy_snapshot_generation as _generation
from . import native_policy_snapshot_policy as _policy
from . import native_policy_snapshot_storage as _storage
from . import native_policy_snapshot_windows_acl as _windows_acl
from . import native_policy_snapshot_windows_atomic as _windows_atomic
from . import native_policy_snapshot_windows_io as _windows_io
from . import native_policy_snapshot_windows_key as _windows_key
from . import native_policy_snapshot_windows_state as _windows_state
from . import native_policy_snapshot_windows_support as _windows_support
from .fork_safety import forget_in_child
from .native_policy_snapshot_publisher import NativePolicySnapshotPublisher

globals().update({name: getattr(_constants, name) for name in _constants.__all__})
NATIVE_POLICY_SNAPSHOT_CACHE_NAME = _constants.NATIVE_POLICY_SNAPSHOT_CACHE_NAME
NativePolicySnapshotError = _constants.NativePolicySnapshotError
POLICY_SNAPSHOT_ACK_REQUIRES_NEW_GENERATION = _constants.POLICY_SNAPSHOT_ACK_REQUIRES_NEW_GENERATION
POLICY_SNAPSHOT_INTEGRITY_DOMAIN = _constants.POLICY_SNAPSHOT_INTEGRITY_DOMAIN
POLICY_SNAPSHOT_PUSH_SCHEMA = _constants.POLICY_SNAPSHOT_PUSH_SCHEMA
POLICY_SNAPSHOT_SCHEMA = _constants.POLICY_SNAPSHOT_SCHEMA
POLICY_SNAPSHOT_V3_SCHEMA = _constants.POLICY_SNAPSHOT_V3_SCHEMA
_WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT = _constants._WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT
derive_native_policy_verifier_key = _codec.derive_native_policy_verifier_key
native_policy_verifier_key_id = _codec.native_policy_verifier_key_id
build_policy_snapshot_v3 = _contract.build_policy_snapshot_v3
snapshot_bytes_v3 = _contract.snapshot_bytes_v3
snapshot_mac_matches_v3 = _contract.snapshot_mac_matches_v3
native_policy_snapshot_v3 = _generation.native_policy_snapshot_v3
effective_native_policy_v3 = _contract.effective_native_policy_v3
provision_native_policy_verifier_key = _windows_key.provision_native_policy_verifier_key

_snapshot_integrity_mac_v3 = _contract._snapshot_integrity_mac_v3
_strict_json_loads_v3 = _codec._strict_json_loads_v3
_read_v3_snapshot_file = _storage._read_v3_snapshot_file
_windows_read_snapshot_bytes = _windows_atomic._windows_read_snapshot_bytes
_windows_read_private_file = _windows_atomic._windows_read_private_file
_windows_dll = _windows_support._windows_dll
_windows_file_information_type = _windows_support._windows_file_information_type
_windows_owner_sid = _windows_support._windows_owner_sid
_windows_security_attributes_type = _windows_support._windows_security_attributes_type
_windows_private_descriptor = _windows_support._windows_private_descriptor
_windows_path_has_reparse_component = _windows_support._windows_path_has_reparse_component
_windows_close_handle = _windows_io._windows_close_handle
_windows_open_handle = _windows_io._windows_open_handle
_windows_apply_private_dacl = _windows_io._windows_apply_private_dacl
_windows_open_private_fd = _windows_io._windows_open_private_fd
_windows_delete_private_child = _windows_atomic._windows_delete_private_child
_windows_write_private_file_atomic = _windows_atomic._windows_write_private_file_atomic
_windows_verify_private_owner = _windows_acl._windows_verify_private_owner
_windows_verify_private_dacl = _windows_acl._windows_verify_private_dacl
_windows_ensure_private_directory = _windows_atomic._windows_ensure_private_directory
_windows_private_directory_binding = _windows_state._windows_private_directory_binding
_normalize_scope_text_v3 = _policy._normalize_scope_text_v3
_utf8_size_v3 = _codec._utf8_size_v3
_valid_bounded_string_v3 = _codec._valid_bounded_string_v3
_valid_selector_key_v3 = _codec._valid_selector_key_v3
_normalized_harness_selector_v3 = _codec._normalized_harness_selector_v3
_validate_json_limits_v3 = _codec._validate_json_limits_v3
_canonical_json_bytes_v3 = _codec._canonical_json_bytes_v3
_digest_v3 = _codec._digest_v3
_runtime_state_directory = _windows_support._runtime_state_directory
_scope_digest_v3 = _policy._scope_digest_v3
_config_value = _policy._config_value
_valid_u64_v3 = _contract._valid_u64_v3
_valid_digest_v3 = _contract._valid_digest_v3
_policy_snapshot_push_bytes_v3 = _contract._policy_snapshot_push_bytes_v3

if TYPE_CHECKING:
    from .store import GuardStore


def _private_guard_home(guard_home: Path) -> None:
    """Refuse to keep generation state anywhere another account could reach it.

    A symlinked home is followed rather than refused: the link itself is not
    trusted to sign policy -- ``guard_home_symlink`` degrades local policy
    authority for exactly that reason -- but Guard still has to run from one,
    and what the generation lock needs is that the directory the link names is
    the owner's and closed to everyone else. A link that names nothing, or
    something other than a directory, is still invalid.
    """

    if os.name == "nt":
        _windows_ensure_private_directory(guard_home)
        return
    try:
        metadata = guard_home.lstat()
    except FileNotFoundError:
        guard_home.mkdir(mode=0o700, parents=True, exist_ok=True)
        metadata = guard_home.lstat()
    if stat.S_ISLNK(metadata.st_mode):
        try:
            metadata = guard_home.stat()
        except OSError as error:
            raise NativePolicySnapshotError("native_policy_generation_home_invalid") from error
    if not stat.S_ISDIR(metadata.st_mode):
        raise NativePolicySnapshotError("native_policy_generation_home_invalid")
    if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o022:
        raise NativePolicySnapshotError("native_policy_generation_home_invalid")


_PUBLISHER_LOCK = threading.RLock()
_PUBLISHERS: dict[str, set[NativePolicySnapshotPublisher]] = {}
forget_in_child(_PUBLISHERS)


def _publisher_key(guard_home: Path) -> str:
    try:
        return str(guard_home.expanduser().resolve(strict=False))
    except (OSError, RuntimeError, ValueError):
        return str(guard_home)


def notify_native_policy_mutation(guard_home: Path) -> None:
    """Invalidate publishers for a control-plane policy/config mutation."""

    with _PUBLISHER_LOCK:
        publishers = tuple(_PUBLISHERS.get(_publisher_key(guard_home), ()))
    for publisher in publishers:
        publisher.request_publish()


def local_cli_publication_status(guard_home: Path, revision: int) -> dict[str, object]:
    """Inspect existing publishers without starting a runtime or claiming readiness."""
    with _PUBLISHER_LOCK:
        publishers = tuple(_PUBLISHERS.get(_publisher_key(guard_home), ()))
    for publisher in publishers:
        receipt = publisher.local_cli_publication_receipt(revision)
        if receipt is not None:
            return {"state": "acknowledged", **receipt}
    errors = [publisher.last_error for publisher in publishers if not publisher.closed and publisher.last_error]
    return {
        "state": "failed" if errors else "pending" if publishers else "unavailable",
        "revision": revision,
        **({"reason": errors[0]} if errors else {}),
    }


def get_native_policy_snapshot_publisher(store: GuardStore) -> NativePolicySnapshotPublisher:
    """Return the per-Guard-home publisher shared by daemon hook workers."""

    key = _publisher_key(Path(store.guard_home))
    with _PUBLISHER_LOCK:
        for publisher in _PUBLISHERS.get(key, ()):
            if not publisher.closed:
                return publisher
        publisher = NativePolicySnapshotPublisher(store=store)
        _PUBLISHERS.setdefault(key, set()).add(publisher)
        return publisher


__all__ = [
    "NATIVE_POLICY_SNAPSHOT_CACHE_NAME",
    "POLICY_SNAPSHOT_ACK_REQUIRES_NEW_GENERATION",
    "POLICY_SNAPSHOT_INTEGRITY_DOMAIN",
    "POLICY_SNAPSHOT_PUSH_SCHEMA",
    "POLICY_SNAPSHOT_SCHEMA",
    "POLICY_SNAPSHOT_V3_SCHEMA",
    "NativePolicySnapshotError",
    "NativePolicySnapshotPublisher",
    "build_policy_snapshot_v3",
    "derive_native_policy_verifier_key",
    "effective_native_policy_v3",
    "get_native_policy_snapshot_publisher",
    "native_policy_snapshot_v3",
    "native_policy_verifier_key_id",
    "notify_native_policy_mutation",
    "provision_native_policy_verifier_key",
    "snapshot_bytes_v3",
    "snapshot_mac_matches_v3",
]

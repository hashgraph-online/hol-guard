"""Publisher half of the direct resident hook lane.

A hook that reaches the resident without passing through this daemon still
needs the publisher's ACK. Each push carries the state its snapshot was
compiled against (settled workspaces and watched non-database input stats),
and the publisher mirrors its ``_acked`` barrier into a short-lease ACK file
that the resident checks before answering directly. Withdrawing the barrier
unlinks the file; a crashed daemon stops renewing the lease. Anything the
resident cannot prove makes the hook take the daemon path instead.
"""

from __future__ import annotations

import base64
import contextlib
import json
import os
import stat
import threading
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from pathlib import Path

from .native_command_control_authority import AUTHORITY_FILE_NAME
from .native_policy_snapshot_constants import NATIVE_RUNTIME_STATE_DIRECTORY
from .native_policy_snapshot_direct_lane_windows import unlink_windows_ack, write_windows_ack

DIRECT_LANE_PUSH_FEATURE = "policy-snapshot-direct-lane-v1"
# The resident queues the evidence of each direct answer for the daemon to drain.
DIRECT_HOOK_EVIDENCE_FEATURE = "hook-direct-evidence-v1"
# The resident routes a Claude Code sandbox requirement with the bound sink command.
DIRECT_HOOK_CONTAINED_ROUTE_FEATURE = "hook-direct-contained-route-v1"
# The resident answers a Claude PermissionRequest from the session's notice,
# verified and marked seen with the bound policy-integrity key.
DIRECT_HOOK_PERMISSION_NOTICE_FEATURE = "hook-direct-permission-notice-v1"
# The resident answers a reviewed PreToolUse from an exact-action decision
# the user saved, verified with the bound policy-integrity key.
DIRECT_HOOK_SAVED_DECISION_FEATURE = "hook-direct-saved-decision-v1"
DIRECT_LANE_ACK_DIRECTORY = "direct-lane"
DIRECT_LANE_ACK_FILE_NAME = "ack.json"
DIRECT_LANE_ACK_SCHEMA = "guard-direct-lane-ack.v1"
DIRECT_LANE_ACK_LEASE_MS = 15_000
# Renew once a third of the lease has elapsed so one slow poll cannot lapse it.
DIRECT_LANE_ACK_RENEW_REMAINING_MS = 10_000

# Mirrors the resident limits in guard-policy-snapshot's direct_lane module.
_MAX_WORKSPACES = 512
_MAX_INPUTS = 256
_MAX_PATH_BYTES = 4096
_MAX_HARNESS_POSTURES = 32
_MAX_HARNESS_KEY_BYTES = 64
_HARNESS_POSTURES = frozenset({"protected", "extra_careful", "watch"})
_MAX_SINK_ARGS = 8
_MAX_SINK_ARG_BYTES = 16_384
_MAX_INTEGRITY_KEY_B64_BYTES = 2048
_MAX_INTEGRITY_KEY_ID_BYTES = 256
_I64_MIN = -(1 << 63)
_I64_MAX = (1 << 63) - 1
_U64_MAX = (1 << 64) - 1

# Database writes and the publisher's own command-control marker commit are
# hints the publisher recompiles and compares; they never revoke the ACK up
# front, so the resident does not watch them either. The marker is replaced
# atomically during publication, so binding its stat would close the lane on
# every publish that commits it.
_DATABASE_FILE_NAMES = frozenset({"guard.db", "guard.db-wal", "guard.db-shm", "guard.db-journal"})

# Serializes each barrier value change with its file operation, so a renewal
# can never resurrect an ACK that a concurrent withdrawal just unlinked.
_ACK_LOCK = threading.Lock()


def _path_valid(value: str) -> bool:
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return 0 < len(encoded) <= _MAX_PATH_BYTES and "\0" not in value and os.path.isabs(value)


def _stat_valid(stat_identity: tuple[int, int, int, int]) -> bool:
    mtime_ns, size, ino, ctime_ns = stat_identity
    return (
        _I64_MIN <= mtime_ns <= _I64_MAX
        and 0 <= size <= _U64_MAX
        and 0 <= ino <= _U64_MAX
        and _I64_MIN <= ctime_ns <= _I64_MAX
    )


def _hint_only(path: Path) -> bool:
    if path.name in _DATABASE_FILE_NAMES:
        return True
    return path.name == AUTHORITY_FILE_NAME and path.parent.name == NATIVE_RUNTIME_STATE_DIRECTORY


def direct_lane_binding(
    *,
    inputs: Iterable[tuple[str, tuple[int, int, int, int] | None]],
    workspaces: Iterable[Path],
) -> dict[str, object] | None:
    """Build the push binding, or None when the lane cannot be proven."""

    bound_inputs: list[dict[str, object]] = []
    for path, stat_identity in inputs:
        if _hint_only(Path(path)):
            continue
        # An input the resident cannot re-stat exactly would leave a change
        # unobserved, so the whole lane stays closed.
        if not _path_valid(path) or (stat_identity is not None and not _stat_valid(stat_identity)):
            return None
        bound_inputs.append(
            {
                "path": path,
                "stat": (
                    None
                    if stat_identity is None
                    else dict(zip(("mtime_ns", "size", "ino", "ctime_ns"), stat_identity, strict=True))
                ),
            }
        )
    # A workspace the resident cannot name simply defers as unknown.
    bound_workspaces = sorted({str(path) for path in workspaces if _path_valid(str(path))})
    if len(bound_inputs) > _MAX_INPUTS or len(bound_workspaces) > _MAX_WORKSPACES:
        return None
    if len({entry["path"] for entry in bound_inputs}) != len(bound_inputs):
        return None
    return {"workspaces": bound_workspaces, "inputs": bound_inputs}


def daemon_home_dir() -> str:
    """The home directory a daemon started without an explicit one resolves."""

    try:
        return str(Path.home().expanduser().resolve(strict=False))
    except (OSError, RuntimeError):
        return ""


def local_cli_block_rules_present(store: object) -> bool:
    """Whether the daemon would check custom command-line block rules.

    Mirrors the daemon probe: no probe means no rules, and a failed probe
    counts as rules present.
    """

    probe = getattr(store, "has_local_cli_block_rules", None)
    if not callable(probe):
        return False
    try:
        return bool(probe())
    except Exception:
        return True


def contained_sink_command(features: Iterable[str]) -> tuple[str, ...] | None:
    """The sink command prefix for a resident that routes sandbox requirements."""

    if DIRECT_HOOK_CONTAINED_ROUTE_FEATURE not in set(features):
        return None
    from .adapters.zcode_contained_tests import contained_sink_command_prefix

    try:
        return contained_sink_command_prefix()
    except (OSError, RuntimeError, ValueError):
        return None


def direct_lane_integrity_key(store: object, features: Iterable[str]) -> tuple[bytes, str] | None:
    """The policy-integrity key for a resident that answers permission notices
    or saved exact-action decisions.

    The key is read, never created: without one there is no notice or saved
    decision to verify.
    """

    if not {DIRECT_HOOK_PERMISSION_NOTICE_FEATURE, DIRECT_HOOK_SAVED_DECISION_FEATURE} & set(features):
        return None
    material = getattr(store, "_policy_integrity_secret_material", None)
    if not callable(material):
        return None
    try:
        loaded = material(create=False)
    except (OSError, RuntimeError, ValueError):
        return None
    if not isinstance(loaded, tuple) or len(loaded) != 2:
        return None
    key, key_id = loaded
    if not isinstance(key, bytes) or not key or not isinstance(key_id, str) or not key_id:
        return None
    return key, key_id


def _integrity_key_fields(integrity_key: tuple[bytes, str]) -> dict[str, str] | None:
    key, key_id = integrity_key
    if not isinstance(key, bytes) or not key or not isinstance(key_id, str):
        return None
    encoded = base64.urlsafe_b64encode(key).rstrip(b"=").decode("ascii")
    try:
        key_id_bytes = key_id.encode("utf-8")
    except UnicodeEncodeError:
        return None
    if (
        len(encoded) > _MAX_INTEGRITY_KEY_B64_BYTES
        or not 0 < len(key_id_bytes) <= _MAX_INTEGRITY_KEY_ID_BYTES
        or any(ord(char) < 0x20 or 0x7F <= ord(char) <= 0x9F for char in key_id)
    ):
        return None
    return {"integrity_key_b64": encoded, "integrity_key_id": key_id}


def _sink_command_valid(command: Sequence[str]) -> bool:
    def arg_valid(value: str) -> bool:
        try:
            encoded = value.encode("utf-8")
        except UnicodeEncodeError:
            return False
        return 0 < len(encoded) <= _MAX_SINK_ARG_BYTES and "\0" not in value

    return (
        0 < len(command) <= _MAX_SINK_ARGS
        and _path_valid(command[0])
        and all(isinstance(value, str) and arg_valid(value) for value in command)
    )


def with_direct_hook_state(
    binding: Mapping[str, object] | None,
    *,
    home_dir: str,
    harness_postures: Mapping[str, str],
    local_cli_block_rules: bool,
    evidence_drain: bool,
    contained_sink_command: Sequence[str] | None = None,
    integrity_key: tuple[bytes, str] | None = None,
) -> dict[str, object] | None:
    """Add the daemon state a direct hook needs beyond the snapshot.

    A field the resident cannot accept is left out, so the lane still proves
    freshness and direct hooks defer as incomplete. ``evidence_drain`` is
    true only while this daemon drains the evidence of direct answers.
    Without ``contained_sink_command`` a Claude Code sandbox requirement
    defers to this daemon, which routes it. Without ``integrity_key`` a
    Claude PermissionRequest with a pending notice defers to this daemon.
    """

    if binding is None:
        return None
    bound: dict[str, object] = {
        **binding,
        "local_cli_block_rules": local_cli_block_rules,
        "evidence_drain": evidence_drain,
    }
    if _path_valid(home_dir):
        bound["home_dir"] = home_dir
    if len(harness_postures) <= _MAX_HARNESS_POSTURES and all(
        0 < len(harness.encode("utf-8", "surrogatepass")) <= _MAX_HARNESS_KEY_BYTES and posture in _HARNESS_POSTURES
        for harness, posture in harness_postures.items()
    ):
        bound["harness_postures"] = dict(sorted(harness_postures.items()))
    if contained_sink_command is not None and _sink_command_valid(contained_sink_command):
        bound["contained_sink_command"] = list(contained_sink_command)
    if integrity_key is not None and (fields := _integrity_key_fields(integrity_key)) is not None:
        bound.update(fields)
    return bound


class NativePolicySnapshotDirectLaneAck:
    """Mirror the publisher's ACK barrier into the resident's direct-lane ACK file."""

    guard_home: Path  # pyright: ignore[reportUninitializedInstanceVariable]
    _acked_value: bool = False
    _direct_lane_ack_target: tuple[int, str] | None = None
    _direct_lane_lease_expires_at_ms: int = 0
    # The custom command-line rule revision the open lane was bound against.
    _direct_lane_local_cli_revision: int | None = None
    # Set while the daemon drains direct-answer evidence from the resident.
    _direct_evidence_drain_enabled: bool = False
    # The open ACK was published for a resident that queues evidence.
    _direct_lane_evidence_bound: bool = False
    # The home the serving daemon gives a hook that names none.
    _direct_lane_daemon_home: str | None = None
    # The approval center origin and working directory the open lane bound.
    _direct_lane_review_facts: tuple[object, object] | None = None
    # The managed-policy view the open lane bound for Oh My Pi output mediation.
    _direct_lane_structured_output: dict[str, object] | None = None

    def bind_direct_lane_daemon_home(self, home_dir: Path) -> None:
        """Record the home the serving daemon gives a hook that names none."""

        try:
            home = str(home_dir.expanduser().resolve(strict=False))
        except (OSError, RuntimeError):
            home = ""
        if home == self._direct_lane_daemon_home:
            return
        self._direct_lane_daemon_home = home
        request_publish = getattr(self, "request_publish", None)
        if callable(request_publish):
            request_publish()

    def _direct_lane_home_dir(self) -> str:
        """The home the lane answers for, or empty to keep it closed.

        The daemon expands `~` with its own home but gives a hook without a
        home the one it was started with. The resident substitutes the bound
        home for both, so one that differs from the other binds none.
        """

        home = daemon_home_dir()
        started = self._direct_lane_daemon_home
        return home if started is None or started == home else ""

    @property
    def _acked(self) -> bool:
        return self._acked_value

    @_acked.setter
    def _acked(self, value: bool) -> None:
        with _ACK_LOCK:
            self._acked_value = value
            if not value:
                self._direct_lane_ack_target = None
                self._direct_lane_lease_expires_at_ms = 0
                self._unlink_direct_lane_ack()

    def _publish_direct_lane_ack(self, snapshot: Mapping[str, object], *, evidence_drain: bool = False) -> None:
        """Open the lane for the snapshot whose ACK was just committed."""

        generation = snapshot.get("generation")
        policy_digest = snapshot.get("policy_digest")
        if isinstance(generation, bool) or not isinstance(generation, int) or not isinstance(policy_digest, str):
            return
        with _ACK_LOCK:
            if not self._acked_value:
                return
            # The binding was compiled while the drain was up. Writing the ACK
            # after the drain stopped would let the resident allow hooks whose
            # evidence nobody records.
            if evidence_drain and not self._direct_evidence_drain_enabled:
                return
            self._direct_lane_ack_target = (generation, policy_digest)
            self._direct_lane_evidence_bound = evidence_drain
            self._write_direct_lane_ack_locked()

    def _renew_direct_lane_ack(self) -> None:
        """Extend the lease while the barrier stays acknowledged."""

        if self._direct_lane_ack_target is None:
            return
        if self._direct_lane_lease_expires_at_ms - _now_ms() > DIRECT_LANE_ACK_RENEW_REMAINING_MS:
            return
        with _ACK_LOCK:
            if self._direct_lane_evidence_bound and not self._direct_evidence_drain_enabled:
                self._direct_lane_ack_target = None
                self._direct_lane_lease_expires_at_ms = 0
                self._direct_lane_evidence_bound = False
                self._unlink_direct_lane_ack()
                return
            if self._acked_value and self._direct_lane_ack_target is not None:
                self._write_direct_lane_ack_locked()

    def _recheck_direct_lane_local_cli(self, revision: int | None) -> None:
        """Close the lane once custom command-line rules move past the binding.

        The binding records whether any block rule existed, which only the
        daemon applies. Any later rule change sends hooks back to the daemon
        until the next publish binds the new state.
        """

        if self._direct_lane_ack_target is None or revision == self._direct_lane_local_cli_revision:
            return
        self._close_direct_lane_ack()

    def _close_direct_lane_ack(self) -> None:
        """Stop direct hooks without withdrawing the daemon's own ACK."""

        with _ACK_LOCK:
            self._direct_lane_ack_target = None
            self._direct_lane_lease_expires_at_ms = 0
            self._direct_lane_evidence_bound = False
            self._unlink_direct_lane_ack()

    def enable_direct_evidence_drain(self, enabled: bool) -> None:
        """Advertise the evidence drain in the next binding, or stop direct hooks."""

        with _ACK_LOCK:
            self._direct_evidence_drain_enabled = enabled
        if not enabled:
            self._close_direct_lane_ack()

    def direct_evidence_bound(self, features: Iterable[str]) -> bool:
        """Whether a push to a resident with ``features`` may bind the drain."""

        return self._direct_evidence_drain_enabled and DIRECT_HOOK_EVIDENCE_FEATURE in set(features)

    def direct_evidence_transport(self) -> tuple[Path, Callable[..., bytes | None]] | None:
        """The resident executable and client the evidence drain uses."""

        status = getattr(self, "_last_runtime_status", None)
        identity = getattr(status, "identity", None)
        capabilities = getattr(status, "capabilities", None)
        path = getattr(identity, "path", None)
        if path is None or DIRECT_HOOK_EVIDENCE_FEATURE not in set(getattr(capabilities, "features", ())):
            return None
        client = getattr(self, "_client_request", None)
        if client is None:
            from .native_resident_client import native_resident_client_ready, native_resident_client_request

            # The drain polls every 250 ms with a short deadline. A cold start
            # that misses it is aborted and still spends a restart, so a
            # Windows resident that starts slower than the poll deadline trips
            # the restart circuit before the daemon is up. Leave starting the
            # resident to callers that budget for a spawn.
            if not native_resident_client_ready(Path(path), self.guard_home):
                return None
            client = native_resident_client_request
        return Path(path), client

    def _direct_lane_ack_path(self) -> Path:
        return self.guard_home / NATIVE_RUNTIME_STATE_DIRECTORY / DIRECT_LANE_ACK_DIRECTORY / DIRECT_LANE_ACK_FILE_NAME

    def _unlink_direct_lane_ack(self) -> None:
        try:
            if os.name == "nt":
                unlink_windows_ack(self._direct_lane_ack_path())
            else:
                self._direct_lane_ack_path().unlink()
        except FileNotFoundError:
            pass
        except (OSError, RuntimeError):
            # A failed Windows binding or delete raises NativePolicySnapshotError.
            # The lease still bounds how long the resident can trust it.
            self._direct_lane_lease_expires_at_ms = 0

    def _write_direct_lane_ack_locked(self) -> None:
        target = self._direct_lane_ack_target
        if target is None:
            return
        generation, policy_digest = target
        lease_expires_at_ms = _now_ms() + DIRECT_LANE_ACK_LEASE_MS
        body = json.dumps(
            {
                "schema": DIRECT_LANE_ACK_SCHEMA,
                "generation": generation,
                "policy_digest": policy_digest,
                "lease_expires_at_ms": lease_expires_at_ms,
            },
            separators=(",", ":"),
        ).encode("ascii")
        path = self._direct_lane_ack_path()
        try:
            if os.name == "nt":
                write_windows_ack(self.guard_home, path, body)
                self._direct_lane_lease_expires_at_ms = lease_expires_at_ms
                return
            _ensure_private_directory(path.parent)
            temporary = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                0o600,
            )
            try:
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(body)
                os.replace(temporary, path)
            except BaseException:
                with contextlib.suppress(OSError):
                    temporary.unlink()
                raise
        except (OSError, RuntimeError):
            # Without a fresh ACK file the resident defers every direct hook.
            self._direct_lane_lease_expires_at_ms = 0
            return
        self._direct_lane_lease_expires_at_ms = lease_expires_at_ms


def _ensure_private_directory(directory: Path) -> None:
    with contextlib.suppress(FileExistsError):
        os.mkdir(directory, 0o700)
    metadata = os.lstat(directory)
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid():
        raise OSError("direct lane ACK directory is not private")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        # Owner-only. A directory needs the execute bit, and 0o644 would leave it readable.
        # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
        os.chmod(directory, 0o700)


def _now_ms() -> int:
    return time.time_ns() // 1_000_000

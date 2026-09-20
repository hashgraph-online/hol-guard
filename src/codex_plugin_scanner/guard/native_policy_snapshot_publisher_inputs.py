"""Publisher input observation and off-path policy compilation."""

from __future__ import annotations

import hashlib
import os
import platform
import sqlite3
import stat
from collections import OrderedDict
from contextlib import closing
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from threading import Condition
from typing import TYPE_CHECKING, cast

from .config_source_io import (
    GUARD_CONFIG_FILENAMES,
    GuardConfigCapture,
    GuardConfigSourceError,
    capture_guard_config,
)
from .native_command_control_authority import AUTHORITY_FILE_NAME
from .native_command_control_binding import read_native_command_control_binding
from .native_policy_snapshot_codec import _digest_v3
from .native_policy_snapshot_constants import (
    NATIVE_POLICY_VERIFIER_KEY_NAME,
    NATIVE_RUNTIME_STATE_DIRECTORY,
    NativePolicySnapshotError,
)
from .native_policy_snapshot_policy import _merge_effective_native_policies, effective_native_policy_v3
from .native_policy_snapshot_resident_inputs import NativePolicySnapshotResidentInputsMixin

if TYPE_CHECKING:
    from .native_policy_snapshot_publisher import NativePolicySnapshotPublisher
    from .runtime.extension_control_runtime import ExtensionControlRuntime
    from .store import GuardStore


@dataclass(frozen=True)
class _CapturedPolicyInput:
    identity: object
    # None bypasses caching for a generic non-config input above the capture
    # limit. Guard TOML always uses the bounded source reader and raises instead.
    content: bytes | None


def _captured_config_reader(path: Path, *, inputs: dict[Path, _CapturedPolicyInput]) -> dict[str, object]:
    from .config import tomllib

    content = inputs[path].content
    if content is None:
        raise ValueError("uncaptured policy input")
    return cast(dict[str, object], tomllib.loads(content.decode("utf-8")))


class NativePolicySnapshotPublisherInputs(NativePolicySnapshotResidentInputsMixin):
    """Mixin containing filesystem observation outside synchronous hooks."""

    guard_home: Path  # pyright: ignore[reportUninitializedInstanceVariable]
    config_capture: GuardConfigCapture | None  # pyright: ignore[reportUninitializedInstanceVariable]
    store: GuardStore  # pyright: ignore[reportUninitializedInstanceVariable]
    _command_control_runtime: ExtensionControlRuntime | None  # pyright: ignore[reportUninitializedInstanceVariable]
    _condition: Condition  # pyright: ignore[reportUninitializedInstanceVariable]
    _acked: bool  # pyright: ignore[reportUninitializedInstanceVariable]
    _workspace_paths: set[Path]  # pyright: ignore[reportUninitializedInstanceVariable]
    _published_policy_fingerprint: tuple[str, str, str] | None  # pyright: ignore[reportUninitializedInstanceVariable]
    _observed_policy_fingerprint: tuple[str, str, str] | None  # pyright: ignore[reportUninitializedInstanceVariable]
    _compiled_workspace_policies: OrderedDict[Path | None, tuple[object, dict[str, object]]]  # pyright: ignore[reportUninitializedInstanceVariable]
    _database_policy_fingerprint: str | None  # pyright: ignore[reportUninitializedInstanceVariable]
    _cached_managed_identity: tuple[str, str | None, str | None, object]  # pyright: ignore[reportUninitializedInstanceVariable]

    def _current_input_fingerprint(
        self,
    ) -> tuple[tuple[tuple[str, tuple[int, int, int, int] | None], ...], tuple[tuple[str, int, int], ...]]:
        values: list[tuple[str, tuple[int, int, int, int] | None]] = []
        # The database and both journal modes are watched for cross-process
        # changes. WAL-only writes are included because they can contain an
        # effective policy mutation before checkpointing.
        paths = (
            self.guard_home / "config.toml",
            self.guard_home / "guard.db",
            self.guard_home / "guard.db-wal",
            self.guard_home / "guard.db-shm",
            self.guard_home / "guard.db-journal",
            self.guard_home / NATIVE_RUNTIME_STATE_DIRECTORY / NATIVE_POLICY_VERIFIER_KEY_NAME,
            self.guard_home / NATIVE_RUNTIME_STATE_DIRECTORY / AUTHORITY_FILE_NAME,
            *self._external_policy_paths(),
            *self._workspace_policy_paths(),
        )
        seen_paths: set[str] = set()
        for path in paths:
            path_key = str(path)
            if path_key in seen_paths:
                continue
            seen_paths.add(path_key)
            try:
                metadata = path.stat()
            except OSError:
                values.append((path_key, None))
            else:
                values.append(
                    (
                        path_key,
                        (metadata.st_mtime_ns, metadata.st_size, metadata.st_ino, metadata.st_ctime_ns),
                    )
                )
        return tuple(values), self._current_resident_fingerprint()

    def _workspace_policy_paths(self) -> tuple[Path, ...]:
        with self._condition:
            workspaces = tuple(self._workspace_paths)
        paths: list[Path] = []
        for workspace in workspaces:
            paths.extend(workspace / filename for filename in (".ai-plugin-scanner-guard.toml", ".hol-guard.toml"))
        return tuple(paths)

    def _compiled_effective_policy(self) -> dict[str, object]:
        """Build the native snapshot input off the synchronous hook path."""

        from .config import load_guard_config
        from .mdm.policy import _cache_path, load_managed_policy

        with self._condition:
            workspaces = tuple(sorted(self._workspace_paths, key=str))
        # Verify machine authority once per compilation pass, including HKLM on
        # Windows. Sharing this value does not cache a trust decision across
        # reconciliation passes or cause one cache write per workspace.
        managed = load_managed_policy(write_cache=False)
        managed_cache_path = _cache_path(platform.system())
        managed_identity = (
            managed.status,
            managed.policy.content_hash if managed.policy is not None else None,
            managed.reason_code,
            self._capture_policy_input(managed_cache_path).identity,
        )
        if managed.policy is not None and managed_identity != getattr(self, "_cached_managed_identity", None):
            # Retain the loader's durable last-known policy behavior, without
            # rewriting identical cache files on every reconciliation pass.
            managed = load_managed_policy()
            self._cached_managed_identity = (
                managed.status,
                managed.policy.content_hash if managed.policy is not None else None,
                managed.reason_code,
                self._capture_policy_input(managed_cache_path).identity,
            )
        home_path = self.guard_home / "config.toml"
        home_input = self._capture_config_policy_input(home_path)
        captured_inputs = {home_path: home_input.identity}
        common = (
            home_input.identity,
            managed.status,
            managed.policy.content_hash if managed.policy is not None else None,
            managed.reason_code,
        )
        if not hasattr(self, "_compiled_workspace_policies"):
            self._compiled_workspace_policies = OrderedDict()
        cache = self._compiled_workspace_policies
        policies: list[dict[str, object]] = []
        for workspace in (None, *workspaces):
            captured = {home_path: home_input}
            if workspace is not None:
                captured.update(
                    (workspace / name, self._capture_config_policy_input(workspace / name))
                    for name in (".ai-plugin-scanner-guard.toml", ".hol-guard.toml")
                )
            captured_inputs.update((path, value.identity) for path, value in captured.items())
            identity = (common, tuple((path, value.identity) for path, value in captured.items()))
            cacheable = all(value.content is not None for value in captured.values())
            cached = cache.get(workspace)
            if not cacheable or cached is None or cached[0] != identity:
                if cached is not None:
                    # Periodic reconciliation may discover a change with no
                    # file notification (for example HKLM). Withdraw authority
                    # before rebuilding that scope, just as the watcher does.
                    with self._condition:
                        self._acked = False
                        self._condition.notify_all()
                config = load_guard_config(
                    self.guard_home,
                    workspace=workspace,
                    managed_policy_state=managed,
                    config_reader=(
                        partial(_captured_config_reader, inputs=captured) if cacheable else self._uncached_config_reader
                    ),
                )
                policy = effective_native_policy_v3(config) | {"mode": config.mode}
                if cacheable:
                    cache[workspace] = (identity, policy)
                else:
                    cache.pop(workspace, None)
            else:
                policy = cached[1]
            if cacheable:
                cache.move_to_end(workspace)
            policies.append(policy)
        # Compiled entries are expendable; evicting one only requires rebuilding
        # it next pass. Registered active overlays are never evicted.
        while len(cache) > 1_025:
            cache.popitem(last=False)
        effective = _merge_effective_native_policies(tuple(policies))
        cast("NativePolicySnapshotPublisher", self)._compiled_config_inputs = captured_inputs
        return effective

    def _configuration_input_changed(self) -> bool:
        """Check bounded config captures without rebuilding policy or controls."""
        previous = cast("NativePolicySnapshotPublisher", self)._compiled_config_inputs
        if not previous:
            return False
        paths = (self.guard_home / "config.toml", *self._workspace_policy_paths())
        try:
            # A capture includes admitted source identity and a hash of the
            # exact bytes. Metadata equality cannot hide a changed overlay.
            return set(paths) != set(previous) or any(
                self._capture_config_policy_input(path).identity != previous[path] for path in paths
            )
        except (OSError, NativePolicySnapshotError, TypeError, ValueError, RuntimeError):
            with self._condition:
                self._acked = False
                self._condition.notify_all()
            return True

    def _capture_config_policy_input(self, path: Path) -> _CapturedPolicyInput:
        try:
            if self.config_capture is not None:
                captured = self.config_capture(path)
                return _CapturedPolicyInput(
                    (captured.identity, hashlib.sha256(captured.content).hexdigest()), captured.content
                )
            return self._capture_policy_input(path)
        except GuardConfigSourceError:
            # A rejected input may occur before cache-change invalidation.
            # Withdraw any previous ACK immediately, including during renewal;
            # generic publication errors can otherwise retain an unexpired ACK.
            with self._condition:
                self._acked = False
                self._condition.notify_all()
            raise

    def _uncached_config_reader(self, path: Path) -> dict[str, object]:
        return _captured_config_reader(path, inputs={path: self._capture_config_policy_input(path)})

    @staticmethod
    def _capture_policy_input(path: Path) -> _CapturedPolicyInput:
        if path.name in GUARD_CONFIG_FILENAMES:
            captured = capture_guard_config(path)
            return _CapturedPolicyInput(
                (captured.identity, hashlib.sha256(captured.content).hexdigest()), captured.content
            )
        try:
            entry = path.lstat()
            target = path.stat()
            if not stat.S_ISREG(target.st_mode):
                return _CapturedPolicyInput(("not-file", target.st_mode), b"")
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0))
            with os.fdopen(descriptor, "rb") as handle:
                target = os.fstat(handle.fileno())
                if not stat.S_ISREG(target.st_mode):
                    return _CapturedPolicyInput(("not-file", target.st_mode), b"")
                content = handle.read(1024 * 1024 + 1)
        except OSError:
            # Preserve _read_toml's missing/inaccessible-file semantics. A later
            # successful read has a different content identity and is rebuilt.
            return _CapturedPolicyInput("unavailable", b"")
        metadata_identity = tuple(
            value
            for metadata in (entry, target)
            for value in (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_mode,
                metadata.st_uid,
                metadata.st_gid,
                metadata.st_size,
                metadata.st_mtime_ns,
                metadata.st_ctime_ns,
            )
        )
        if len(content) > 1024 * 1024:
            return _CapturedPolicyInput((metadata_identity, "uncached-large-input"), None)
        # Hash and parse these same captured bytes. Metadata-only caching is
        # insufficient on Windows, where ctime may represent creation time.
        return _CapturedPolicyInput((metadata_identity, hashlib.sha256(content).hexdigest()), content)

    def _database_policy_marker(self) -> str:
        """Read the publication authority domain through SQLite's WAL view.

        These bounded hashes are invalidation hints only. The publisher reads
        and authenticates full control authority before signing a binding.
        Receipts and activity rows cannot change this policy-domain marker.
        """

        path = (self.guard_home / "guard.db").absolute()
        try:
            with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=0.05)) as connection:
                rows = connection.execute(
                    "select state_key, substr(cast(payload_json as blob), 1, 1048577) "
                    "from sync_state where state_key in ('policy_integrity', 'managed_controls_active', "
                    "'managed_controls_revision', 'managed_controls_manifest_context') order by state_key"
                ).fetchall()
                values: list[object] = [
                    (
                        key,
                        hashlib.sha256(payload).hexdigest()
                        if isinstance(payload, bytes) and len(payload) <= 1048576
                        else "invalid",
                    )
                    for key, payload in rows
                ]
                tables = {
                    row[0]
                    for row in connection.execute(
                        "select name from sqlite_master where type = 'table' and name in "
                        "('extension_control_authority_snapshot', 'extension_control_authority_transition')"
                    )
                }
                if "extension_control_authority_snapshot" in tables:
                    row = connection.execute(
                        "select substr(cast(revision as text), 1, 32), substr(catalog_digest, 1, 65), "
                        "substr(snapshot_digest, 1, 65), substr(snapshot_mac, 1, 65), "
                        "substr(cast(layers_json as blob), 1, 262145), "
                        "substr(cast(snapshot_json as blob), 1, 1048577) "
                        "from extension_control_authority_snapshot where singleton = 1"
                    ).fetchone()
                    values.append(
                        (
                            "local",
                            tuple(
                                hashlib.sha256(value).hexdigest() if isinstance(value, bytes) else value
                                for value in row
                            )
                            if row is not None
                            else None,
                        )
                    )
                if "extension_control_authority_transition" in tables:
                    row = connection.execute(
                        "select substr(cast(revision as text), 1, 32), substr(phase, 1, 32), "
                        "substr(snapshot_digest, 1, 65) from extension_control_authority_transition "
                        "order by revision desc limit 1"
                    ).fetchone()
                    values.append(
                        (
                            "transition",
                            tuple(
                                hashlib.sha256(value).hexdigest() if isinstance(value, bytes) else value
                                for value in row
                            )
                            if row is not None
                            else None,
                        )
                    )
            return _digest_v3(values)
        except (OSError, sqlite3.Error, ValueError, NativePolicySnapshotError):
            return "unavailable"

    def _compiled_command_extensions(self) -> dict[str, object]:
        try:
            binding, runtime = read_native_command_control_binding(
                self.store, getattr(self, "_command_control_runtime", None)
            )
            self._command_control_runtime = runtime
            return binding
        except (OSError, NativePolicySnapshotError, TypeError, ValueError, RuntimeError):
            with self._condition:
                self._acked = False
                self._condition.notify_all()
            raise

    @staticmethod
    def _external_policy_paths() -> tuple[Path, ...]:
        try:
            from .mdm.contracts import default_machine_paths

            machine_paths = default_machine_paths()
        except (OSError, RuntimeError, ValueError):
            return ()
        paths = [machine_paths.policy_path]
        paths.append(machine_paths.state_root / "managed-policy-cache.json")
        return tuple(path for path in paths if path is not None)

    def _policy_input_changed(self, changed_paths: set[str] | None = None) -> bool:
        """Compare effective policy in the publisher thread, never in hooks."""

        force_republish = False
        if not changed_paths:
            marker = self._database_policy_marker()
            previous_marker = self._database_policy_fingerprint
            self._database_policy_fingerprint = marker
            force_republish = previous_marker is not None and previous_marker != marker
            if force_republish:
                with self._condition:
                    self._acked = False
                    self._condition.notify_all()
        if changed_paths:
            database_paths = {
                str(self.guard_home / name) for name in ("guard.db", "guard.db-wal", "guard.db-shm", "guard.db-journal")
            }
            control_marker_path = str(self.guard_home / NATIVE_RUNTIME_STATE_DIRECTORY / AUTHORITY_FILE_NAME)
            # The publisher creates/commits this signed marker itself. Its
            # authoritative content is compared in the verified binding below;
            # treating its mtime as unconditional change would revoke every
            # first ACK. Changed/closed/invalid markers still change the binding
            # or fail verification, while an identical record needs no push.
            other_changed_paths = changed_paths - {control_marker_path}
            database_only_change = bool(other_changed_paths) and other_changed_paths <= database_paths
            if database_only_change:
                marker = self._database_policy_marker()
                previous_marker = getattr(self, "_database_policy_fingerprint", None)
                self._database_policy_fingerprint = marker
                if previous_marker == marker and control_marker_path not in changed_paths:
                    return False
                force_republish = previous_marker is not None and previous_marker != marker
            if other_changed_paths and not database_only_change:
                # Guard config, workspace overrides, MDM policy files, and
                # verifier state are effective-input boundaries. Republish before the
                # resident is used even when this Python projection cannot
                # yet express a workspace-specific native policy.
                force_republish = True
            if force_republish:
                # Revoke the old snapshot before potentially slow compilation.
                with self._condition:
                    self._acked = False
                    self._condition.notify_all()
        try:
            effective_policy = self._compiled_effective_policy()
            # ``_compiled_effective_policy`` carries the raw mode beside the
            # bounded policy so snapshot generation can derive enforce versus
            # observe. ``config_digest`` deliberately covers only the
            # bounded policy fields, however; comparing the whole mapping
            # would make every database heartbeat look like a policy change
            # and continuously revoke the ACKed snapshot.
            policy_for_digest = dict(effective_policy)
            policy_for_digest.pop("mode", None)
            current_fingerprint = (
                cast(str, _digest_v3(policy_for_digest)),
                cast(str, effective_policy["mode"]),
                _digest_v3(self._compiled_command_extensions()),
            )
        except (OSError, NativePolicySnapshotError, TypeError, ValueError, RuntimeError):
            current_fingerprint = ("unavailable", "", "")
        # Observation is independent of acknowledgment: unchanged inputs must
        # not reset a failed publication's retry backoff on every database write.
        previous_fingerprint = (
            self._observed_policy_fingerprint
            if self._observed_policy_fingerprint is not None
            else self._published_policy_fingerprint
        )
        self._observed_policy_fingerprint = current_fingerprint
        return force_republish or previous_fingerprint != current_fingerprint

    @staticmethod
    def _resolved_workspace(workspace: Path) -> Path:
        return workspace.expanduser().absolute()

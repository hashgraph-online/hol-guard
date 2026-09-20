"""Publisher input observation and off-path policy compilation."""

from __future__ import annotations

import sqlite3
import stat
from collections.abc import Callable
from pathlib import Path
from threading import Condition
from typing import TYPE_CHECKING, cast

from .mdm.policy import managed_policy_cache_read_only
from .native_cloud_policy_inputs import NativeCloudPolicyInputs, read_native_cloud_policy_inputs
from .native_command_control_authority import AUTHORITY_FILE_NAME
from .native_command_control_binding import read_native_command_control_binding
from .native_policy_publication_lock import hold_policy_publication_mutation
from .native_policy_snapshot_codec import _digest_v3
from .native_policy_snapshot_constants import (
    NATIVE_POLICY_VERIFIER_KEY_NAME,
    NATIVE_RUNTIME_STATE_DIRECTORY,
    NativePolicySnapshotError,
)

if TYPE_CHECKING:
    from .native_policy_snapshot_publisher import NativePolicySnapshotPublisher
    from .runtime.extension_control_runtime import ExtensionControlRuntime
    from .store import GuardStore


class NativePolicySnapshotPublisherInputs:
    """Mixin containing filesystem observation outside synchronous hooks."""

    _command_control_runtime: ExtensionControlRuntime | None = None
    _published_command_control_digest: str | None = None
    _observed_command_control_digest: str | None = None
    guard_home: Path  # pyright: ignore[reportUninitializedInstanceVariable]
    _condition: Condition  # pyright: ignore[reportUninitializedInstanceVariable]
    _scoped_publication_enabled: bool  # pyright: ignore[reportUninitializedInstanceVariable]
    _observed_scoped_digest: str | None  # pyright: ignore[reportUninitializedInstanceVariable]
    _acked: bool  # pyright: ignore[reportUninitializedInstanceVariable]
    _workspace_paths: set[Path]  # pyright: ignore[reportUninitializedInstanceVariable]
    _published_policy_fingerprint: tuple[str, str] | None  # pyright: ignore[reportUninitializedInstanceVariable]
    _observed_policy_fingerprint: tuple[str, str] | None  # pyright: ignore[reportUninitializedInstanceVariable]
    store: GuardStore  # pyright: ignore[reportUninitializedInstanceVariable]
    _wall_clock: Callable[[], float]  # pyright: ignore[reportUninitializedInstanceVariable]
    _published_cloud_inputs: NativeCloudPolicyInputs  # pyright: ignore[reportUninitializedInstanceVariable]
    _observed_cloud_inputs: NativeCloudPolicyInputs  # pyright: ignore[reportUninitializedInstanceVariable]

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

    def _current_resident_fingerprint(self) -> tuple[tuple[str, int, int], ...]:
        """Observe resident generation metadata without policy/config reads."""

        resident_values: list[tuple[str, int, int]] = []
        state_dir = self.guard_home / NATIVE_RUNTIME_STATE_DIRECTORY
        try:
            resident_directories = sorted(
                (entry for entry in state_dir.iterdir() if entry.name.startswith("resident-v3-")),
                key=lambda entry: entry.name,
            )
        except OSError:
            resident_directories = []
        for directory in resident_directories:
            try:
                metadata = directory.stat()
            except OSError:
                continue
            resident_values.append((directory.name, metadata.st_mtime_ns, metadata.st_size))
            try:
                generation_files = sorted(
                    (entry for entry in directory.iterdir() if entry.name.startswith("generation-")),
                    key=lambda entry: entry.name,
                )
            except OSError:
                generation_files = []
            for entry in generation_files:
                try:
                    metadata = entry.stat()
                except OSError:
                    continue
                resident_values.append((f"{directory.name}/{entry.name}", metadata.st_mtime_ns, metadata.st_size))
        return tuple(resident_values)

    def _resident_directory_fingerprint(self) -> tuple[int, int] | None:
        """Read only the runtime-state directory metadata for the commit fence."""

        try:
            metadata = (self.guard_home / NATIVE_RUNTIME_STATE_DIRECTORY).lstat()
        except OSError:
            return None
        if not stat.S_ISDIR(metadata.st_mode):
            return None
        return metadata.st_mtime_ns, metadata.st_size

    def _resident_paths_match(self, observed: tuple[tuple[str, int, int], ...]) -> bool:
        """Recheck sampled resident paths without enumerating the directory."""

        state_dir = self.guard_home / NATIVE_RUNTIME_STATE_DIRECTORY
        for path_key, mtime_ns, size in observed:
            try:
                metadata = (state_dir / path_key).lstat()
            except OSError:
                return False
            if not stat.S_ISREG(metadata.st_mode) and not stat.S_ISDIR(metadata.st_mode):
                return False
            if metadata.st_mtime_ns != mtime_ns or metadata.st_size != size:
                return False
        return True

    def _confirm_resident_fingerprint(
        self,
        before: tuple[tuple[str, int, int], ...],
        observed: tuple[tuple[str, int, int], ...],
        resident_generation: int,
        observed_directory: tuple[int, int] | None,
    ) -> tuple[tuple[str, int, int], ...] | None:
        """Reject ACKs that do not identify the resident observed after push."""

        if before and before != observed:
            return None
        if not self._resident_fingerprint_matches_generation(observed, resident_generation):
            return None
        # Re-read only bounded metadata while the barrier is held. A changed
        # state-directory identity or sampled path means a resident restarted
        # after the full post-ACK sample; the stale ACK must not open readiness.
        if observed_directory is None:
            if observed:
                return None
        elif self._resident_directory_fingerprint() != observed_directory or not self._resident_paths_match(observed):
            return None
        return observed

    @staticmethod
    def _resident_fingerprint_matches_generation(
        fingerprint: tuple[tuple[str, int, int], ...],
        resident_generation: int,
    ) -> bool:
        """Require the ACK generation to be the newest observed resident."""

        generations: list[int] = []
        for path_key, _mtime_ns, _size in fingerprint:
            filename = path_key.rsplit("/", 1)[-1]
            if not filename.startswith("generation-") or not filename.endswith(".json"):
                continue
            raw_generation = filename[len("generation-") : -len(".json")]
            if not raw_generation.isdigit():
                return False
            generations.append(int(raw_generation))
        # Test doubles may acknowledge without materializing state files. A
        # real managed resident always publishes at least one generation file;
        # when files are present, an ACK for anything other than the newest
        # resident is definitively stale.
        return not generations or max(generations) == resident_generation

    def _workspace_policy_paths(self) -> tuple[Path, ...]:
        with self._condition:
            workspaces = tuple(self._workspace_paths)
        paths: list[Path] = []
        for workspace in workspaces:
            paths.extend(workspace / filename for filename in (".ai-plugin-scanner-guard.toml", ".hol-guard.toml"))
        return tuple(paths)

    def _compiled_effective_policy(self, *, cloud_defaults: dict[str, object] | None = None) -> dict[str, object]:
        """Build the native snapshot input off the synchronous hook path."""

        from .config import load_guard_config, overlay_synced_guard_policy
        from .native_managed_capture import compile_configuration_origins

        with self._condition:
            workspaces = tuple(sorted(self._workspace_paths, key=str))
        # Never compile an empty/partial supported write. The condition above
        # is released before this off-path file lock; ACK capture can reenter it.
        with hold_policy_publication_mutation(self.guard_home):
            configs = [load_guard_config(self.guard_home)]
            configs.extend(load_guard_config(self.guard_home, workspace=workspace) for workspace in workspaces)
        configs = [overlay_synced_guard_policy(config, cloud_defaults) for config in configs]
        return compile_configuration_origins(tuple(configs))

    def _compiled_native_policy(self) -> tuple[dict[str, object], NativeCloudPolicyInputs]:
        cloud_inputs = read_native_cloud_policy_inputs(self.store, now=self._wall_clock())
        policy = (
            self._compiled_effective_policy()
            if cloud_inputs.defaults is None
            else self._compiled_effective_policy(cloud_defaults=cloud_inputs.defaults)
        )
        return policy, cloud_inputs

    def _compiled_command_extensions(self) -> dict[str, object]:
        try:
            binding, runtime = read_native_command_control_binding(self.store, self._command_control_runtime)
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
        if changed_paths:
            database_paths = {
                str(self.guard_home / name) for name in ("guard.db", "guard.db-wal", "guard.db-shm", "guard.db-journal")
            }
            # The authority marker is atomically replaced after verified reads.
            # Its bytes, and database commits, are checked below before revoking
            # an unchanged generation merely because an inode was refreshed.
            database_paths.add(str(self.guard_home / NATIVE_RUNTIME_STATE_DIRECTORY / AUTHORITY_FILE_NAME))
            database_only_change = all(path in database_paths for path in changed_paths)
            if not database_only_change:
                # Guard config, workspace overrides, MDM policy files, and
                # verifier state are effective-input boundaries. Republish before the
                # resident is used even when this Python projection cannot
                # yet express a workspace-specific native policy.
                force_republish = True
                # Revoke the old snapshot before potentially slow compilation.
                with self._condition:
                    self._acked = False
                    self._condition.notify_all()
        try:
            command_extensions = self._compiled_command_extensions()
            command_digest = _digest_v3(command_extensions)
        except (OSError, NativePolicySnapshotError, TypeError, ValueError, RuntimeError, sqlite3.Error):
            changed = self._observed_command_control_digest != "unavailable"
            self._observed_command_control_digest = "unavailable"
            with self._condition:
                self._acked = False
                self._condition.notify_all()
            return force_republish or changed
        previous_command_digest = (
            self._observed_command_control_digest
            if self._observed_command_control_digest is not None
            else self._published_command_control_digest
        )
        self._observed_command_control_digest = command_digest
        force_republish |= previous_command_digest != command_digest
        if force_republish:
            with self._condition:
                self._acked = False
                self._condition.notify_all()
        if self._scoped_publication_enabled:
            from .native_policy_snapshot_publisher_scoped import scoped_policy_input_changed

            with managed_policy_cache_read_only():
                return scoped_policy_input_changed(
                    self, force_republish=force_republish, command_extensions=command_extensions
                )
        from .native_policy_snapshot_publisher_context import compiled_v3_compatible_policy

        try:
            with managed_policy_cache_read_only():
                effective_policy, cloud_inputs = compiled_v3_compatible_policy(
                    cast("NativePolicySnapshotPublisher", self), command_extensions=command_extensions
                )
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
            )
        except (OSError, NativePolicySnapshotError, TypeError, ValueError, RuntimeError, sqlite3.Error):
            # Even a malformed new row or managed source changes the required
            # contract. It cannot retain a source-free resident's ready state.
            with self._condition:
                self._acked = False
                self._condition.notify_all()
            changed = (
                self._observed_policy_fingerprint != ("unavailable", "") or self._observed_scoped_digest is not None
            )
            self._observed_policy_fingerprint = ("unavailable", "")
            self._observed_scoped_digest = None
            return force_republish or changed
        # Observation is independent of acknowledgment: unchanged inputs must
        # not reset a failed publication's retry backoff on every database write.
        previous_fingerprint = (
            self._observed_policy_fingerprint
            if self._observed_policy_fingerprint is not None
            else self._published_policy_fingerprint
        )
        self._observed_policy_fingerprint = current_fingerprint
        source_changed = self._observed_scoped_digest != cloud_inputs.input_digest
        self._observed_scoped_digest = cloud_inputs.input_digest
        self._observed_cloud_inputs = cloud_inputs
        changed = force_republish or source_changed or previous_fingerprint != current_fingerprint
        if changed:
            with self._condition:
                self._acked = False
                self._condition.notify_all()
        return changed

    @staticmethod
    def _resolved_workspace(workspace: Path) -> Path:
        return workspace.expanduser().absolute()

"""Publisher input observation and off-path policy compilation."""

from __future__ import annotations

from pathlib import Path
from typing import cast

from .native_policy_snapshot_codec import _digest_v3
from .native_policy_snapshot_constants import (
    NATIVE_POLICY_VERIFIER_KEY_NAME,
    NATIVE_RUNTIME_STATE_DIRECTORY,
    NativePolicySnapshotError,
)
from .native_policy_snapshot_policy import _merge_effective_native_policies, effective_native_policy_v3


class NativePolicySnapshotPublisherInputs:
    """Mixin containing filesystem observation outside synchronous hooks."""

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
        return tuple(values), tuple(resident_values)

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

        with self._condition:
            workspaces = tuple(sorted(self._workspace_paths, key=str))
        configs = [load_guard_config(self.guard_home)]
        configs.extend(load_guard_config(self.guard_home, workspace=workspace) for workspace in workspaces)
        return _merge_effective_native_policies(
            tuple(effective_native_policy_v3(config) | {"mode": config.mode} for config in configs)
        )

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

        if changed_paths:
            config_path = str(self.guard_home / "config.toml")
            database_paths = {
                str(self.guard_home / name) for name in ("guard.db", "guard.db-wal", "guard.db-shm", "guard.db-journal")
            }
            if any(path != config_path and path in database_paths for path in changed_paths):
                return True
            if any(path != config_path for path in changed_paths):
                # Workspace overrides, MDM policy files, and verifier state
                # are all effective-input boundaries. Republish before the
                # resident is used even when this Python projection cannot
                # yet express a workspace-specific native policy.
                return True
        try:
            effective_policy = self._compiled_effective_policy()
            current_fingerprint = (
                cast(str, _digest_v3(effective_policy)),
                cast(str, effective_policy["mode"]),
            )
        except (OSError, NativePolicySnapshotError, TypeError, ValueError, RuntimeError):
            return True
        return self._published_policy_fingerprint != current_fingerprint

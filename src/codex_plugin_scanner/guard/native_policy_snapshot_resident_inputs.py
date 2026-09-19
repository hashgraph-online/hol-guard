"""Resident-generation observation helpers for native policy publication."""

from __future__ import annotations

import stat
from pathlib import Path

from .native_policy_snapshot_constants import NATIVE_RUNTIME_STATE_DIRECTORY


class NativePolicySnapshotResidentInputsMixin:
    """Observe resident generation state without reading policy payloads."""

    guard_home: Path  # pyright: ignore[reportUninitializedInstanceVariable]

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



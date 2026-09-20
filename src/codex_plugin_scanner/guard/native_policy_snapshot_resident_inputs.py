"""Resident-generation observation helpers for native policy publication."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from .native_policy_snapshot_constants import NATIVE_RUNTIME_STATE_DIRECTORY

_UNOBSERVED_RESIDENT_FINGERPRINT = (("", 0, 0),)


def _generation_name(name: str) -> bool:
    return (
        name.startswith("generation-")
        and name.endswith(".json")
        and name[len("generation-") : -len(".json")].isascii()
        and name[len("generation-") : -len(".json")].isdigit()
    )


def _initial_generation_in_retained_namespace(
    before: tuple[tuple[str, int, int], ...],
    observed: tuple[tuple[str, int, int], ...],
) -> bool:
    """Allow creation only after a complete, generation-free namespace scan."""
    if not before or before[0][0] != ".":
        return False
    if any("/" in path and not path.endswith("/.") for path, _, _ in before):
        return False
    identities = {path: (device, inode) for path, device, inode in before if path == "." or path.endswith("/.")}
    observed_identities = {
        path: (device, inode) for path, device, inode in observed if path == "." or path.endswith("/.")
    }
    directories = {path for path, _, _ in before if path != "." and "/" not in path}
    if set(identities) != {".", *(f"{name}/." for name in directories)}:
        return False
    # A never-created namespace may gain its first scope. Retained scopes must
    # remain exactly the same namespace, including each directory identity.
    if directories:
        if identities != observed_identities:
            return False
    elif identities.get(".") != observed_identities.get("."):
        return False
    return any(_generation_name(path.rsplit("/", 1)[-1]) for path, _, _ in observed)


class NativePolicySnapshotResidentInputsMixin:
    """Observe resident generation state without reading policy payloads."""

    guard_home: Path  # pyright: ignore[reportUninitializedInstanceVariable]

    @staticmethod
    def _directory_sample(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
        return (metadata.st_dev, metadata.st_ino, metadata.st_mtime_ns, metadata.st_ctime_ns, metadata.st_size)

    def _current_resident_fingerprint(self) -> tuple[tuple[str, int, int], ...]:
        """Capture a complete namespace or an explicit unobserved sentinel.

        Ordinary rows retain mtime/size. The root ``.`` and scope ``/.``
        rows additionally bind directory device/inode without changing the
        tuple contract. They let a verified inactive retained namespace admit
        its first generation while all post-ACK metadata fences remain live.
        """
        state_dir = self.guard_home / NATIVE_RUNTIME_STATE_DIRECTORY
        try:
            root = state_dir.lstat()
        except FileNotFoundError:
            return ()
        except OSError:
            return _UNOBSERVED_RESIDENT_FINGERPRINT
        if not stat.S_ISDIR(root.st_mode):
            return _UNOBSERVED_RESIDENT_FINGERPRINT
        resident_values = [(".", root.st_dev, root.st_ino)]
        try:
            directories = sorted(
                (entry for entry in state_dir.iterdir() if entry.name.startswith("resident-v3-")),
                key=lambda entry: entry.name,
            )
            for directory in directories:
                before = directory.lstat()
                if not stat.S_ISDIR(before.st_mode):
                    return _UNOBSERVED_RESIDENT_FINGERPRINT
                resident_values.extend(
                    (
                        (directory.name, before.st_mtime_ns, before.st_size),
                        (f"{directory.name}/.", before.st_dev, before.st_ino),
                    )
                )
                generations = sorted(
                    (entry for entry in directory.iterdir() if entry.name.startswith("generation-")),
                    key=lambda entry: entry.name,
                )
                for entry in generations:
                    metadata = entry.lstat()
                    if not stat.S_ISREG(metadata.st_mode) or not _generation_name(entry.name):
                        return _UNOBSERVED_RESIDENT_FINGERPRINT
                    resident_values.append((f"{directory.name}/{entry.name}", metadata.st_mtime_ns, metadata.st_size))
                after = directory.lstat()
                if not stat.S_ISDIR(after.st_mode) or self._directory_sample(before) != self._directory_sample(after):
                    return _UNOBSERVED_RESIDENT_FINGERPRINT
            after_root = state_dir.lstat()
            if not stat.S_ISDIR(after_root.st_mode) or self._directory_sample(root) != self._directory_sample(
                after_root
            ):
                return _UNOBSERVED_RESIDENT_FINGERPRINT
        except OSError:
            return _UNOBSERVED_RESIDENT_FINGERPRINT
        return tuple(resident_values)

    def _resident_directory_fingerprint(self) -> tuple[int, int, int, int] | None:
        """Bind runtime-directory identity and namespace metadata at commit."""
        try:
            metadata = (self.guard_home / NATIVE_RUNTIME_STATE_DIRECTORY).lstat()
        except OSError:
            return None
        if not stat.S_ISDIR(metadata.st_mode):
            return None
        return metadata.st_dev, metadata.st_ino, metadata.st_mtime_ns, metadata.st_size

    def _resident_paths_match(self, observed: tuple[tuple[str, int, int], ...]) -> bool:
        """Recheck sampled resident paths without enumerating the directory."""

        state_dir = self.guard_home / NATIVE_RUNTIME_STATE_DIRECTORY
        for path_key, mtime_ns, size in observed:
            try:
                metadata = (state_dir / path_key).lstat()
            except OSError:
                return False
            if path_key == "." or path_key.endswith("/."):
                if not stat.S_ISDIR(metadata.st_mode) or (metadata.st_dev, metadata.st_ino) != (mtime_ns, size):
                    return False
            else:
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
        observed_directory: tuple[int, int, int, int] | None,
    ) -> tuple[tuple[str, int, int], ...] | None:
        """Reject ACKs that do not identify the resident observed after push."""

        if before == _UNOBSERVED_RESIDENT_FINGERPRINT or observed == _UNOBSERVED_RESIDENT_FINGERPRINT:
            return None
        if before and before != observed and not _initial_generation_in_retained_namespace(before, observed):
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

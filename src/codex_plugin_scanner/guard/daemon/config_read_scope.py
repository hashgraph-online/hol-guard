"""Configuration captures confined to the daemon's admitted canonical paths."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from ..config_source_io import CapturedGuardConfig, GuardConfigSourceError, capture_guard_config
from ..runtime.local_temp_paths import trusted_temporary_root_for_path


@dataclass(frozen=True)
class HookConfigReadScope:
    """Explicit capture dependency shared by a daemon worker and its publisher.

    Hook ingress resolves intentional workspace aliases during admission. A
    later capture must retain that canonical path, and its held directory must
    remain within the same hook root policy. This binds a canonical path, not a
    directory inode across process launches. Standalone CLI readers are unchanged.
    """

    configured_home: Path
    canonical_home: Path
    current_home: Path
    allowed_roots: tuple[Path, ...]

    @classmethod
    def for_guard_home(cls, guard_home: Path) -> HookConfigReadScope:
        configured = guard_home.expanduser().absolute()
        canonical = configured.resolve()
        current_home = Path.home().resolve()
        roots = (current_home,) if canonical.parent.is_relative_to(current_home) else (current_home, canonical.parent)
        return cls(configured, canonical, current_home, roots)

    def __call__(self, path: Path) -> CapturedGuardConfig:
        parent = path.parent.absolute()
        # Preserve the intentional home alias; otherwise canonicalize the parent
        # so it matches the resolve() capture_guard_config performs internally.
        expected = self.canonical_home if parent == self.configured_home else parent.resolve()
        return capture_guard_config(
            expected / path.name, expected_parent=expected, parent_validator=self._validate_held_parent
        )

    def read_toml(self, path: Path) -> dict[str, object]:
        from ..config import _parse_toml

        return _parse_toml(self(path).content)

    def _validate_held_parent(self, parent: Path, metadata: os.stat_result) -> None:
        if any(parent.is_relative_to(root) for root in self.allowed_roots):
            return
        # Preserve the existing owned-temporary workspace exception. The helper
        # identifies a trusted temporary root; authorization compares the held
        # canonical path itself and uses its held owner, never a replacement
        # workspace's pathname stat. Capture verifies the held chain afterward.
        temporary_root = trusted_temporary_root_for_path(parent)
        if temporary_root is not None and parent.is_relative_to(temporary_root):
            getuid = getattr(os, "getuid", None)
            if callable(getuid):
                if metadata.st_uid == getuid():
                    return
            elif temporary_root.is_relative_to(self.current_home):
                return
        raise GuardConfigSourceError("guard_config_unexpected_root")

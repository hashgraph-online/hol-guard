"""The paths a harness operation runs against, and the install plan it prepares."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .runtime_transition import TransitionFile


@dataclass(frozen=True, slots=True)
class HarnessContext:
    """Paths used by harness operations."""

    home_dir: Path
    workspace_dir: Path | None
    guard_home: Path
    executable_overrides: Mapping[str, str] = field(default_factory=dict[str, str])
    home_override_explicit: bool = False
    workspace_override_explicit: bool = False


@dataclass(frozen=True)
class PreparedHarnessInstall:
    files: tuple[TransitionFile, ...]
    manifest: dict[str, object]

    def publish(
        self,
        guard_home: Path,
        *,
        removals: bool = False,
        rollback: bool = True,
        on_write: Callable[[TransitionFile], None] | None = None,
    ) -> dict[str, object]:
        """Publish an ordinary install under ownership; pending transitions use their signed plan.

        ``removals`` admits planned deletions, for a plan that retires files an
        older install left behind. Rollback still restores them. A caller that
        journals the plan itself passes ``rollback=False`` and recovers from its
        own record; ``on_write`` sees each file just after it is written.
        """
        from .native_owned import require_codex_install_owner
        from .native_transition_files import publish_files
        from .runtime_transition import assert_transition_mutation_allowed

        require_codex_install_owner(guard_home)
        assert_transition_mutation_allowed(guard_home)
        publish_files(self.files, removals=removals, rollback=rollback, on_write=on_write)
        return self.manifest

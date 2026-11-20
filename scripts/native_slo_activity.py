"""Optional measurement activity; the default installed proof never creates it."""

from __future__ import annotations

from contextlib import AbstractContextManager
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from scripts.native_slo_session import AdapterSession


class SloActivity(Protocol):
    def session(self, runtime: Path) -> AdapterSession: ...

    def prepare(self, guard: Path, workspace: Path) -> None: ...

    def background(self, label: str, guard: Path, workspace: Path) -> AbstractContextManager[None]: ...

    def after_restart(self, label: str, guard: Path, workspace: Path) -> None: ...

    def contained(
        self, label: str, final: dict | None, prior: dict | None = None, recovery: dict | None = None
    ) -> None: ...

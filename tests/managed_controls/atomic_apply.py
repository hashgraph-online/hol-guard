"""Atomic policy and Extension-control application with last-known-good state."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Generic, TypeVar

T = TypeVar("T")


class AtomicApplyError(RuntimeError):
    """Raised without committing a partial Managed Controls state."""


@dataclass(frozen=True, slots=True)
class AppliedManagedControls(Generic[T]):
    revision: int
    bundle_hash: str
    catalog_digest: str
    effective_digest: str
    value: T

    def __post_init__(self) -> None:
        if type(self.revision) is not int or self.revision < 0:
            raise AtomicApplyError("managed controls revision cannot be negative")
        for value in (self.bundle_hash, self.catalog_digest, self.effective_digest):
            if not isinstance(value, str) or not value:
                raise AtomicApplyError("managed controls digest is required")


@dataclass(frozen=True, slots=True)
class PreparedProjection:
    """A staged projection whose externally visible commit can be undone."""

    commit: Callable[[], None]
    rollback: Callable[[], None]


class AtomicManagedControlsStore(Generic[T]):
    def __init__(self, initial: AppliedManagedControls[T] | None = None) -> None:
        self._current = initial
        self._last_known_good = initial

    @property
    def current(self) -> AppliedManagedControls[T] | None:
        return self._current

    @property
    def last_known_good(self) -> AppliedManagedControls[T] | None:
        return self._last_known_good

    def apply(
        self,
        candidate: AppliedManagedControls[T],
        *,
        validate: Callable[[AppliedManagedControls[T]], None],
        compile_projection: Callable[[AppliedManagedControls[T]], PreparedProjection],
    ) -> AppliedManagedControls[T]:
        previous = self._current
        prepared: PreparedProjection | None = None
        try:
            if previous is not None and candidate.revision <= previous.revision:
                raise AtomicApplyError("managed controls revision must increase")
            validate(candidate)
            prepared = compile_projection(candidate)
            if not isinstance(prepared, PreparedProjection):
                raise AtomicApplyError("managed controls projection was not staged")
            prepared.commit()
        except Exception as error:
            if prepared is not None:
                try:
                    prepared.rollback()
                except Exception as rollback_error:
                    raise AtomicApplyError("managed controls apply and rollback failed") from rollback_error
            self._current = previous
            if isinstance(error, AtomicApplyError):
                raise
            raise AtomicApplyError("managed controls apply failed") from error
        self._current = candidate
        self._last_known_good = candidate
        return candidate

    def restore_last_known_good(self) -> AppliedManagedControls[T]:
        if self._last_known_good is None:
            raise AtomicApplyError("no last-known-good managed controls state")
        self._current = self._last_known_good
        return self._last_known_good

"""The error a caller sees when the Guard daemon is still starting."""

from __future__ import annotations


class GuardDaemonStillStartingError(RuntimeError):
    """The daemon accepted the start but has not answered yet."""


__all__ = ["GuardDaemonStillStartingError"]

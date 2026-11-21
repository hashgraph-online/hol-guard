"""Error the approval store raises when its native transport is unavailable."""

from __future__ import annotations


class NativeSignalProjectionUnavailableError(RuntimeError):
    """Projection transport failed independently of persisted decision validity."""

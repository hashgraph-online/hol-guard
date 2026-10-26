"""Mode rules for files a runtime transition publishes."""

from __future__ import annotations

import os
from collections.abc import Mapping


def publishes_user_file(
    *,
    before: object,
    after: object,
    before_mode: int,
    after_mode: int,
    expected_digest: object,
    artifact_identity: object,
) -> bool:
    """Whether a change rewrites a file whose published mode may be normalized.

    Dependency pins (digest/artifact identity) are never rewritten, and unchanged
    content with an unchanged mode is never published, so neither is normalized.
    """
    if expected_digest is not None or artifact_identity is not None:
        return False
    return before != after or before_mode != after_mode


def normalized_after_mode(after_mode: int) -> int:
    """Clear group/world-write from a published mode (e.g. umask 0002 dotfiles at 0664).

    Setuid/setgid/sticky bits stay rejected by the validators; this only drops
    write bits Guard must never publish.
    """
    if os.name == "nt" or isinstance(after_mode, bool) or after_mode & ~0o777:
        return after_mode
    return after_mode & ~0o022


def recorded_noop(change: Mapping[str, object]) -> bool:
    """An unchanged, unpinned file is never published, so its mode is not validated."""
    return (
        change.get("expected_digest") is None
        and change.get("artifact_identity") is None
        and change["before"] == change["after"]
        and change["before_mode"] == change["after_mode"]
    )

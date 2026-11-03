"""Assertions for compound developer inspection."""

from __future__ import annotations


def assert_leading_cd_inspection_allowed(artifact: dict[str, object] | None) -> None:
    """Require the leading ``cd`` inspection to be allowed on every host.

    The live hook resolves the root of a leading ``cd`` against the verified
    working directory, with each host's own path semantics, so a Windows drive
    path bounds the inspection the same way a POSIX path does.
    """

    assert artifact is None

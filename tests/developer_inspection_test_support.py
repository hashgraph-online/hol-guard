"""Assertions for compound developer inspection on hosts with different path models."""

from __future__ import annotations

import os

from codex_plugin_scanner.guard.models import GuardArtifact


def assert_leading_cd_inspection_allowed(artifact: GuardArtifact | None) -> None:
    """Require the POSIX allow and an explicit review on Windows.

    The native developer-inspection kernel recovers the root of a leading
    ``cd`` through POSIX path text, so a Windows drive path does not resolve
    to a bounded inspection root. The command then falls back to review
    instead of being allowed. Keep that boundary closed until the kernel has
    Windows path semantics.
    """

    if os.name == "nt":
        assert artifact is not None
        assert artifact.metadata["guard_default_action"] == "require-reapproval"
    else:
        assert artifact is None

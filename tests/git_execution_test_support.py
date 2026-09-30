"""Assertions for host Git proofs on platforms with different trust metadata."""

from __future__ import annotations

import os
from pathlib import Path

from codex_plugin_scanner.guard.runtime.git_execution_safety import trusted_git_binary_for_cwd


def assert_host_git_proof_result(result: bool, *, cwd: Path) -> None:
    """Require a positive POSIX proof and explicit unavailable proof on Windows."""

    if os.name == "nt":
        # The host verifier requires POSIX ownership and permission evidence.
        # Windows stat mode bits do not establish equivalent executable ACLs.
        # Keep that boundary closed until a Windows identity proof is provided.
        assert trusted_git_binary_for_cwd(cwd) is None
        assert result is False
    else:
        assert result is True

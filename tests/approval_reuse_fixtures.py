"""Real resident setup for approval-reuse contract tests."""

from pathlib import Path

import pytest


@pytest.fixture
def native_approval_reuse_runtime(native_hook_force: Path, _native_context_home: Path) -> Path:
    """Require the pinned native authority in the isolated session home."""
    from codex_plugin_scanner.guard.runtime.approval_reuse import (
        APPROVAL_REUSE_NO_SAVED_DECISION,
        evaluate_approval_reuse,
    )

    result = evaluate_approval_reuse("review")
    assert result is not None, "The pinned native resident did not answer approval_reuse_decide"
    assert result.reason_code == APPROVAL_REUSE_NO_SAVED_DECISION
    return native_hook_force

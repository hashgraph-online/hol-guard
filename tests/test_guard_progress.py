from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.cli.progress import GuardProgress


def test_progress_finishes_with_failure_state_when_step_raises(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(RuntimeError), GuardProgress(total=2, title="Guard Sync", use_rich=False) as progress:
        progress.step("Syncing local proof to Guard Cloud...")
        raise RuntimeError("offline")

    stderr = capsys.readouterr().err
    assert "[ 50%] Syncing local proof to Guard Cloud..." in stderr
    assert "✗ Guard Sync did not complete" in stderr

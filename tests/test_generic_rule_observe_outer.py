"""Actual generic saved-policy rules retain their separate Observe projection."""

import json
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.models import GuardAction, PolicyDecision
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_canonical_policy_row_authority import _ARTIFACT, _NOW, _activated_store
from tests.test_generic_managed_benign_outer import _config, _invoke
from tests.test_generic_managed_origin_outer import Mode


@pytest.mark.parametrize("mode", ("enforce", "observe"))
@pytest.mark.parametrize("current", ("allow", "warn"))
@pytest.mark.parametrize("source", ("local", "signed-bundle"))
def test_actual_generic_rule_block_observe_projection_retains_the_original_decision(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    mode: Mode,
    current: GuardAction,
    source: str,
) -> None:
    if source == "signed-bundle":
        store = _activated_store(tmp_path, action="block")
    else:
        store = GuardStore(tmp_path / "guard")
        store.upsert_policy(
            PolicyDecision(harness="codex", scope="artifact", action="block", artifact_id=_ARTIFACT, source="local"),
            _NOW,
        )
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    config = _config(store, workspace, mode, {"default_action": current})
    code = _invoke(
        store,
        workspace,
        config,
        "Shell",
        "printf Synthetic",
        runtime_expected=False,
        payload_hints={"artifact_id": _ARTIFACT},
    )
    output = cast(dict[str, object], json.loads(capsys.readouterr().out))
    composition = output["policy_composition"]
    assert isinstance(composition, dict)
    assert composition["current_composed_action"] == current
    assert composition["saved_policy_action"] == "block"
    assert composition["observed_policy_action"] == ("block" if mode == "observe" else None)
    assert output["policy_action"] == ("allow" if mode == "observe" else "block")
    assert code == (0 if mode == "observe" else 1)
    assert store.list_receipts(limit=1)[0]["policy_decision"] == output["policy_action"]

from __future__ import annotations

import json
import subprocess

import pytest

from codex_plugin_scanner.guard.runtime.native_command_extension_evidence import (
    NativeCommandExtensionEvidenceError,
)
from tests import native_command_test_support as native_support
from tests.native_command_test_support import (
    project_native_review_fixture,
    real_native_review_fixtures,
)


def test_batch_preserves_order_and_matches_independent_runtime_command_models() -> None:
    commands = ("pwd", "git reset --hard", "git push origin feature")
    expected = (("allow", None), ("review", "command.git.hard-reset"), ("review", "command.git.push"))
    fixtures = real_native_review_fixtures(commands)
    assert tuple(fixture.command for fixture in fixtures) == commands
    _compiler, runtime = native_support._native_binaries()
    for command, fixture, (minimum_action, rule_id) in zip(commands, fixtures, expected, strict=True):
        # Exercise the separate runtime CLI, keeping both responses untouched.
        # Their authority snapshots differ, but command parsing must agree.
        completed = subprocess.run(
            [str(runtime), "pre-tool", "--stdin"],
            input=json.dumps({"command": command}).encode(),
            capture_output=True,
            check=False,
            timeout=10,
        )
        assert completed.returncode == 0, completed.stderr.decode(errors="replace")
        runtime_payload = json.loads(completed.stdout)
        assert fixture.payload["command_model"] == runtime_payload["command_model"]
        assert fixture.payload["minimum_action"] == minimum_action
        evaluation = project_native_review_fixture(fixture).evaluation
        matched_rule_ids = {owned.match.rule.rule_id for owned in evaluation.matches}
        if rule_id is None:
            assert matched_rule_ids == set()
        else:
            assert rule_id in matched_rule_ids


def test_projection_rejects_native_failure_without_changing_evidence() -> None:
    fixture = real_native_review_fixtures(("x" * 32_769,))[0]
    assert fixture.payload["minimum_action"] == "block"
    assert fixture.payload.get("command_extensions") is None
    original = json.dumps(fixture.payload, sort_keys=True)
    with pytest.raises(NativeCommandExtensionEvidenceError):
        project_native_review_fixture(fixture)
    assert json.dumps(fixture.payload, sort_keys=True) == original


def test_batch_keeps_managed_disable_above_local_enable() -> None:
    enabled = (("permission", "command.git.permission.hard-reset", "enabled"),)
    disabled = (("permission", "command.git.permission.hard-reset", "disabled"),)
    local = real_native_review_fixtures(("git reset --hard",), controls=enabled)[0]
    managed = real_native_review_fixtures(("git reset --hard",), controls=enabled, managed_controls=disabled)[0]
    assert local.snapshot.managed_revision == 0
    assert managed.snapshot.managed_revision == 1
    assert local.snapshot.effective_digest != managed.snapshot.effective_digest
    assert local.payload["minimum_action"] != "block"
    assert managed.payload["minimum_action"] == "block"
    assert managed.payload["reason_code"] == "native_command_permission_disabled"


@pytest.mark.parametrize("commands", [(), ("pwd",) * 257])
def test_batch_bounds_fail_before_starting_native_evaluation(commands: tuple[str, ...]) -> None:
    with pytest.raises(ValueError, match="between 1 and 256"):
        real_native_review_fixtures(commands)

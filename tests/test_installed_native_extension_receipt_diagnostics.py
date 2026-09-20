"""A failed installed receipt comparison emits only bounded evidence."""

from __future__ import annotations

import json

import pytest

from ci.native_runtime import probe_installed_native_extensions as probe
from codex_plugin_scanner.guard.native_approval_errors import NATIVE_COMMAND_CONTROL_ERROR_CODES


@pytest.mark.parametrize("reason", sorted(NATIVE_COMMAND_CONTROL_ERROR_CODES))
def test_diagnostic_keeps_the_exact_approved_command_control_reason(reason: str) -> None:
    assert probe.receipt_binding_diagnostic({"reason_code": reason}, {}, {}, [])["http_reason_code"] == reason


def test_stale_receipt_diagnostic_distinguishes_pre_worker_admission_failure() -> None:
    expected = {"control_revision": 5, "observations_digest": "new"}
    receipt = {"decision_id": "prior", "command_extensions": {**expected, "observations_digest": "old"}}
    response = {"reason_code": "native_policy_not_ready", "hookSpecificOutput": {"permissionDecision": "allow"}}

    diagnostic = probe.receipt_binding_diagnostic(response, receipt, expected, ["prior"])

    assert diagnostic["http_reason_code"] == "native_policy_not_ready"
    assert diagnostic["http_decision"] == "allow"
    assert diagnostic["receipt_id_repeated"] is True
    assert diagnostic["mismatched_binding_fields"] == ["observations_digest"]
    assert diagnostic["expected_control_revision"] == diagnostic["receipt_control_revision"] == 5
    with pytest.raises(RuntimeError, match="receipt_generation_mismatch"):
        probe.require(receipt["command_extensions"] == expected, "receipt_generation_mismatch")


def test_current_receipt_with_different_control_binding_remains_distinct() -> None:
    expected = {"control_revision": 5}
    receipt = {"decision_id": "current", "command_extensions": {"control_revision": 4}}
    diagnostic = probe.receipt_binding_diagnostic({}, receipt, expected, ["prior"])
    assert diagnostic["receipt_id_repeated"] is False
    assert diagnostic["mismatched_binding_fields"] == ["control_revision"]
    assert diagnostic["expected_control_revision"] == 5
    assert diagnostic["receipt_control_revision"] == 4


@pytest.mark.parametrize("revision", [True, -1, 2**64, "secret", None])
def test_diagnostic_drops_unbounded_fields_and_invalid_revision(revision: object) -> None:
    private = "private-request-path-or-secret"
    response = {"reason_code": private, "reason": private, "hookSpecificOutput": {"permissionDecision": private}}
    receipt = {"decision_id": private, "command_extensions": {"control_revision": revision, private: private}}
    diagnostic = probe.receipt_binding_diagnostic(response, receipt, {}, [])
    assert diagnostic["http_reason_code"] is None
    assert diagnostic["http_decision"] is None
    assert diagnostic["receipt_control_revision"] is None
    assert private not in json.dumps(diagnostic)
    assert "secret" not in json.dumps(diagnostic)

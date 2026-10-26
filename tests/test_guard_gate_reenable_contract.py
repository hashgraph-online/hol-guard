"""Contract for the dashboard's disabled-gate password setup flow, decided by the resident."""

import json

import pytest

from codex_plugin_scanner.guard import approval_gate


def test_reenable_retained_gate_requires_confirmed_password(tmp_path, native_hook_force):
    created = approval_gate._approval_gate_native(
        "create_verifier", tmp_path, params={"password": "synthetic-old-password"}, provision_prerequisite=True
    )
    assert created is not None
    retained = {"enabled": False, "verifier": created, "totp_enabled": True}
    state_path = tmp_path / "approval-gate.json"
    state_path.write_text(json.dumps(retained), encoding="utf-8")

    def validate(payload):
        approval_gate.validate_settings_update(tmp_path, payload, approval_gate_grant=None, now=None)

    with pytest.raises(approval_gate.ApprovalGateError) as missing:
        validate({"enabled": True, "totp_code": "000000"})
    assert missing.value.code == "approval_gate_password_required"
    with pytest.raises(approval_gate.ApprovalGateError):
        validate(
            {
                "enabled": True,
                "new_password": "synthetic-new-password",
                "confirm_password": "different-synthetic-password",
            }
        )

    validate({"enabled": True, "new_password": "synthetic-new-password", "confirm_password": "synthetic-new-password"})
    # Validation never persists: the retained state is exactly what was seeded.
    assert json.loads(state_path.read_text(encoding="utf-8")) == retained

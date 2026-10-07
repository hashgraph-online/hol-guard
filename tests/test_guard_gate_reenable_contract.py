"""Offline contract for the dashboard's disabled-gate password setup flow."""

import pytest

from codex_plugin_scanner.guard import approval_gate


def test_reenable_retained_gate_requires_confirmed_password(tmp_path, monkeypatch):
    retained = {
        "enabled": False,
        "verifier": approval_gate.create_verifier("synthetic-old-password"),
        "totp_enabled": True,
    }
    monkeypatch.setattr(approval_gate, "_load_state", lambda home: dict(retained))

    def validate(payload):
        return approval_gate._next_settings_state(tmp_path, payload, approval_gate_grant=None, now=None)

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

    next_state = validate(
        {"enabled": True, "new_password": "synthetic-new-password", "confirm_password": "synthetic-new-password"}
    )
    assert next_state["enabled"] is True
    assert next_state["totp_enabled"] is True
    assert retained["enabled"] is False
    assert not list(tmp_path.iterdir())

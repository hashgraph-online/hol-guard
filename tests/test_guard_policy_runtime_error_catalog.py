"""HGP-190: runtime policy error catalog maps codes to owners and next actions."""

from __future__ import annotations

from codex_plugin_scanner.guard.policy_runtime_error_catalog import (
    explain_policy_runtime_error,
    policy_runtime_error_catalog,
)

_REQUIRED = {
    "untrusted_signing_key",
    "remote_exact_request_stale",
    "remote_exact_wrong_target",
    "remote_exact_replayed",
    "cloud_review_capability_revoked",
    "remote_exact_step_up_required",
    "catalog-digest-mismatch",
    "unknown-permission-target",
    "pending_request_requeue_failed",
    "telemetry_degradation",
}


def test_catalog_covers_acceptance_matrix_without_raw_traceback_only() -> None:
    codes = {entry["code"] for entry in policy_runtime_error_catalog()}
    assert _REQUIRED <= codes
    for code in _REQUIRED:
        entry = explain_policy_runtime_error(code)
        assert entry["owner"]
        assert entry["next_action"]
        assert entry["explanation"]
        assert "Traceback" not in str(entry["explanation"])
    unknown = explain_policy_runtime_error("ValueError: boom")
    assert unknown["next_action"]
    assert unknown["explanation"]

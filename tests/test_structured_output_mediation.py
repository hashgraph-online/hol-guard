from pathlib import Path

import pytest

from tests.structured_output_mediation_support import _config, _NativeRouteFixture


@pytest.mark.parametrize("variant", ["malformed", "missing", "revoked"])
def test_native_route_does_not_skip_configured_authority_failures(tmp_path: Path, variant: str) -> None:
    config = _config(status="revoked" if variant == "revoked" else "active")
    if variant == "malformed":
        config.managed_policy.settings["data_control"]["structured_output"]["onMatch"] = "allow"
    elif variant == "missing":
        config.managed_policy = None
    fixture = _NativeRouteFixture(config)
    response, native_used = fixture._review_native_edge_with_snapshot(
        payload={
            "hook_event_name": "PostToolUse",
            "structured_output_json": '{"employee":{"email":"","id":7},"note":"x"}',
        },
        harness="pi",
        event_name="PostToolUse",
        default_harness="pi",
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard",
        workspace=tmp_path,
        deadline=None,
        policy_snapshot={"mode": "enforce"},
        recording_only=False,
    )
    assert native_used is True
    mediation = response["structured_content_mediation"]
    assert isinstance(mediation, dict)
    assert mediation["action"] == "withhold"
    assert mediation["reason_code"] in {
        "structured_managed_policy_invalid",
        "structured_managed_policy_missing",
        "structured_managed_authority_revoked",
    }

"""Actual Store receipt outcomes preserve bounded Cloud delivery refusals."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.cli.commands_sync_output import sync_success_payload
from codex_plugin_scanner.guard.cli.render import emit_guard_payload
from codex_plugin_scanner.guard.runtime import runner
from codex_plugin_scanner.guard.runtime.sync_auth_handoff import hold_sync_auth_handoff
from codex_plugin_scanner.guard.store import GuardStore
from tests.policy_bundle_signing_helpers import policy_bundle_test_keyring
from tests.test_guard_runtime import _seed_guard_cloud
from tests.test_policy_bundle_activation_atomicity import _activate_bundle, _signed_bundle
from tests.test_policy_bundle_sync_outcomes import _stub_http
from tests.test_receipt_runner_preference_integration import _ordinary_auth, _ready

NOW = "2026-09-20T00:00:00Z"
CANARY = "SYNTHETIC_PRIVATE_DELIVERY_CANARY"


@pytest.fixture(autouse=True)
def isolate_legacy_auth_override(monkeypatch: pytest.MonkeyPatch) -> None:
    # The legacy bundle helper sets a module override; scoped OAuth cases need the real resolver.
    monkeypatch.setattr(runner, "_test_sync_auth_context_override", None)


def store_at(path: Path) -> GuardStore:
    store = GuardStore(path)
    _seed_guard_cloud(store, workspace_id="workspace-1")
    return store


def response(status: str = "unavailable", code: object = "extension_bundle_incompatible") -> dict[str, object]:
    return {
        "syncedAt": NOW,
        "receiptsStored": 0,
        "policyDeliveryOutcome": {
            "status": status,
            "code": code,
            "message": CANARY * 1000,
            "correlationId": CANARY,
            "nextAction": CANARY,
            "receiptCursorAdvanced": True,
        },
        "policyBundleNegotiation": {"diagnostics": [{"ruleId": CANARY, "remediation": CANARY}]},
    }


@pytest.mark.parametrize("retained", [False, True])
@pytest.mark.parametrize("status", ["unavailable", "invalid"])
def test_server_refusal_is_distinct_from_upload_and_actual_application(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    retained: bool,
    status: str,
) -> None:
    store = store_at(tmp_path / "guard")
    if retained:
        store.set_sync_payload("policy_bundle_keyring", policy_bundle_test_keyring(workspace_id="workspace-1"), NOW)
        assert _activate_bundle(store, _signed_bundle(rollout_state="enforcing"), NOW) is not None
        # Complete the ordinary legacy ACK transition before measuring refusal.
        _stub_http(monkeypatch, {"syncedAt": NOW, "receiptsStored": 0})
        assert runner.sync_receipts(store)["policy_application_status"] == "retained"
    before = {
        key: store.get_sync_payload(key)
        for key in ("policy_bundle", "policy_bundle_ack", "policy_bundle_last_good")
    }
    _stub_http(monkeypatch, response(status))
    summary = runner.sync_receipts(store)
    assert summary["receipt_upload_status"] == "success"
    assert summary["policy_validation_status"] == "omitted"
    assert summary["policy_application_status"] == ("retained" if retained else "no_authority")
    assert summary["policy_delivery_status"] == status
    assert summary["policy_delivery_reason"] == "extension_bundle_incompatible"
    assert "Cloud" in str(summary["policy_delivery_remediation"])
    assert CANARY not in json.dumps(summary)
    assert store.get_sync_payload("sync_summary") == summary
    assert {key: store.get_sync_payload(key) for key in before} == before
    _stub_http(monkeypatch, {"syncedAt": NOW, "receiptsStored": 0})
    cleared = runner.sync_receipts(store)
    assert "policy_delivery_status" not in cleared
    assert "policy_delivery_status" not in (store.get_sync_payload("sync_summary") or {})
    assert cleared["policy_application_status"] == ("retained" if retained else "no_authority")


@pytest.mark.parametrize("command", ["status", "sync"])
@pytest.mark.parametrize("as_json", [False, True])
def test_actual_status_and_sync_render_only_fixed_delivery_guidance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    command: str,
    as_json: bool,
) -> None:
    home = tmp_path / "guard"
    store = store_at(home)
    _stub_http(monkeypatch, response())
    summary = runner.sync_receipts(store)
    # Neither persisted nor response-supplied prose is a display authority.
    store.set_sync_payload("sync_summary", {**summary, "policy_delivery_remediation": CANARY}, NOW)
    capsys.readouterr()
    if command == "status":
        assert main(["guard", "status", "--home", str(home), *(["--json"] if as_json else [])]) == 0
    else:
        emit_guard_payload(
            "sync",
            sync_success_payload(
                {
                    "receipts": {**summary, "policy_delivery_remediation": CANARY},
                    "policy_delivery_remediation": CANARY,
                }
            ),
            as_json,
        )
    output = capsys.readouterr().out
    assert CANARY not in output
    assert "unavailable" in output
    assert "Cloud" in output
    if as_json:
        payload = json.loads(output)
        assert payload["policy_delivery_status"] == "unavailable"
        assert payload["policy_application_status"] == "no_authority"


@pytest.mark.parametrize("outcome", [None, [], {"status": "ready"}, {"status": "applied"}, {"status": CANARY}])
def test_unrecognized_delivery_claim_never_creates_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    outcome: object,
) -> None:
    store = store_at(tmp_path / "guard")
    _stub_http(monkeypatch, {"syncedAt": NOW, "policyDeliveryOutcome": outcome})
    summary = runner.sync_receipts(store)
    assert summary["receipt_upload_status"] == "success"
    assert summary["policy_application_status"] == "no_authority"
    assert "policy_delivery_status" not in summary
    assert store.get_sync_payload("policy_bundle") is None
    assert store.get_sync_payload("policy_bundle_ack") is None
    assert CANARY not in json.dumps(summary)


@pytest.mark.parametrize("code", [CANARY, CANARY * 1000, [CANARY], None])
def test_unknown_delivery_code_has_fixed_generic_explanation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    code: object,
) -> None:
    store = store_at(tmp_path / "guard")
    _stub_http(monkeypatch, response(code=code))
    summary = runner.sync_receipts(store)
    assert summary["policy_delivery_reason"] == "policy_download_failed"
    assert summary["policy_application_status"] == "no_authority"
    assert CANARY not in json.dumps(summary)


@pytest.mark.parametrize("change", ["replacement", "disconnect", "same-values"])
def test_delivery_refusal_cannot_overwrite_newer_connection_summary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    change: str,
) -> None:
    store, inputs = _ready(tmp_path)
    peer = GuardStore(store.guard_home, allow_system_keyring=False)
    connection = store.capture_oauth_connection()
    assert connection is not None
    context = _ordinary_auth(store)
    marker = {"source": "newer-connection"}

    def transport(*, request, prepare_request, validate_request, **_kwargs):
        validate_request()
        prepare_request(request)
        return response()

    monkeypatch.setattr(runner, "_urlopen_json_with_timeout_retry", transport)
    original_metrics = runner._build_value_metrics

    def metrics(value):
        result = original_metrics(value)
        if change == "disconnect":
            peer.clear_oauth_local_credentials()
        else:
            replacement = inputs.copy()
            if change == "replacement":
                replacement["workspace_id"] = "newer-workspace"
            peer.set_oauth_local_credentials(**replacement)
        peer.set_sync_payload("sync_summary", marker, NOW)
        return result

    monkeypatch.setattr(runner, "_build_value_metrics", metrics)
    with (
        hold_sync_auth_handoff(store, context, connection),
        pytest.raises(RuntimeError, match="connection changed"),
    ):
        runner.sync_receipts(store, auth_context=context)
    assert peer.get_sync_payload("sync_summary") == marker


def test_actual_verified_bundle_clears_prior_delivery_refusal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = store_at(tmp_path / "guard")
    _stub_http(monkeypatch, response())
    assert runner.sync_receipts(store)["policy_delivery_status"] == "unavailable"
    bundle = _signed_bundle(rollout_state="enforcing")
    store.set_sync_payload("policy_bundle_keyring", policy_bundle_test_keyring(workspace_id="workspace-1"), NOW)
    _stub_http(monkeypatch, {"syncedAt": NOW, "receiptsStored": 0, "policyBundle": bundle})
    summary = runner.sync_receipts(store)
    assert summary["policy_validation_status"] == "accepted"
    assert summary["policy_application_status"] == "applied"
    assert "policy_delivery_status" not in summary
    stored_bundle = store.get_sync_payload("policy_bundle")
    acknowledgement = store.get_sync_payload("policy_bundle_ack")
    assert isinstance(stored_bundle, dict) and stored_bundle["bundleHash"] == bundle["bundleHash"]
    assert isinstance(acknowledgement, dict) and acknowledgement["bundleHash"] == bundle["bundleHash"]
    # This V1 oracle fixture records receipt synchronization, not a native ACK.
    assert acknowledgement["status"] == "synced"
    assert store.get_sync_payload("sync_summary") == summary

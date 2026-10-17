"""Receipt sync carries the fleet posture once per cycle and reports policy acks promptly."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from jsonschema import Draft202012Validator

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli.oauth_client import generate_dpop_key_pair
from codex_plugin_scanner.guard.models import GuardReceipt
from codex_plugin_scanner.guard.runtime import fleet_posture as fp
from codex_plugin_scanner.guard.runtime import runner as guard_runner_module
from codex_plugin_scanner.guard.store import GuardStore
from tests.policy_bundle_signing_helpers import policy_bundle_test_keyring, sign_policy_bundle
from tests.support.network import stub_authenticated_urlopen

SCHEMA = json.loads(
    (Path(__file__).resolve().parents[1] / "contracts" / "fleet-posture" / "v1" / "schema.json").read_text(
        encoding="utf-8"
    )
)
FOLLOWUP_KEY = "fleet_posture_bundle_followup"

pytestmark = [pytest.mark.usefixtures("native_hook_force")]


class _Adapter:
    harness = "claude-code"

    def diagnostics(self, _context: HarnessContext) -> dict[str, object]:
        return {"setup_status": "active", "config_paths": ["/cfg"], "artifacts": [], "installed": True}

    def setup_contract(self) -> SimpleNamespace:
        return SimpleNamespace(
            coverage=SimpleNamespace(
                native_hooks=True,
                browser_fallback=False,
                mcp_proxy=True,
                prompt_hooks=False,
                blind_spots=(),
            )
        )


class _Response:
    def __init__(self, payload: dict[str, object]) -> None:
        self._payload = payload

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False

    def read(self) -> bytes:
        return json.dumps(self._payload).encode("utf-8")


def _seed_cloud(store: GuardStore) -> None:
    key_material = generate_dpop_key_pair()
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="demo-token",
        dpop_private_key_pem=key_material.private_key_pem,
        dpop_public_jwk=key_material.public_jwk,
        dpop_public_jwk_thumbprint=key_material.public_jwk_thumbprint,
        grant_id="grant-1",
        machine_id="machine-1",
        workspace_id="workspace-1",
        now="2026-05-19T00:00:00Z",
    )
    guard_runner_module._test_sync_auth_context_override = {
        "sync_url": "https://hol.org/api/guard/receipts/sync",
        "access_token": "demo-token",
        "dpop_key_material": None,
    }


def _add_receipts(store: GuardStore, count: int) -> None:
    for index in range(count):
        store.add_receipt(
            GuardReceipt(
                receipt_id=f"receipt-{index}",
                timestamp="2026-10-16T00:00:00+00:00",
                harness="claude-code",
                artifact_id=f"artifact-{index}",
                artifact_hash=f"sha256:{index:064x}",
                policy_decision="review",
                capabilities_summary="requests file write",
                changed_capabilities=("fs_write",),
                provenance_summary="local workspace",
                artifact_name=f"artifact-{index}",
                source_scope="workspace",
            )
        )


@pytest.fixture
def store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> GuardStore:
    from codex_plugin_scanner.guard import adapters

    guard_store = GuardStore(tmp_path / "guard-home")
    _seed_cloud(guard_store)
    monkeypatch.setattr(adapters, "list_adapters", lambda: [_Adapter()])
    monkeypatch.setattr(guard_runner_module, "sync_pain_signals", lambda _store, auth_context=None: 0)
    yield guard_store
    guard_runner_module._test_sync_auth_context_override = None


def _install_transport(
    monkeypatch: pytest.MonkeyPatch,
    *,
    extra: dict[str, object] | None = None,
    fail_after: int | None = None,
) -> list[dict[str, object]]:
    bodies: list[dict[str, object]] = []

    def fake_urlopen(request, timeout):
        if request.full_url.endswith("/api/v1/guard/events"):
            return _Response({"statuses": []})
        body = json.loads(request.data.decode("utf-8"))
        bodies.append(body)
        if fail_after is not None and len(bodies) > fail_after:
            raise OSError("transport down")
        stamp = datetime(2026, 10, 16, 12, 0, len(bodies) % 60, tzinfo=timezone.utc).isoformat()
        payload: dict[str, object] = {"syncedAt": stamp, "receiptsStored": len(body["receipts"])}
        payload.update(extra or {})
        return _Response(payload)

    stub_authenticated_urlopen(monkeypatch, fake_urlopen)
    return bodies


def test_session_capabilities_advertise_fleet_posture() -> None:
    assert fp.CAPABILITY == "fleet-posture/v1"
    assert guard_runner_module.FLEET_POSTURE_CAPABILITY == "fleet-posture/v1"


def test_posture_rides_only_on_the_first_batch_and_is_schema_valid(
    store: GuardStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    _add_receipts(store, guard_runner_module._RECEIPT_SYNC_BATCH_SIZE * 2 + 5)
    bodies = _install_transport(monkeypatch)

    summary = guard_runner_module.sync_receipts(store)

    assert summary["receipts"] == guard_runner_module._RECEIPT_SYNC_BATCH_SIZE * 2 + 5
    assert len(bodies) == 3
    posture = bodies[0]["syncContext"]["fleetPosture"]
    Draft202012Validator(SCHEMA).validate(posture)
    assert posture["aiTools"][0]["harness"] == "claude-code"
    assert posture["aiTools"][0]["protectionState"] == "protected"
    assert all("fleetPosture" not in body["syncContext"] for body in bodies[1:])
    assert store.get_sync_payload(fp.LAST_SENT_STATE_KEY)


def test_second_cycle_sends_a_delta_not_a_full_inventory(store: GuardStore, monkeypatch: pytest.MonkeyPatch) -> None:
    _add_receipts(store, 1)
    bodies = _install_transport(monkeypatch)

    guard_runner_module.sync_receipts(store)
    guard_runner_module.sync_receipts(store)

    first = bodies[0]["syncContext"]["fleetPosture"]
    second = bodies[1]["syncContext"]["fleetPosture"]
    assert first["inventory"]["mode"] == "full"
    assert second["inventory"]["mode"] == "delta"
    Draft202012Validator(SCHEMA).validate(second)


def test_cloud_full_inventory_request_is_honoured_on_the_next_build(
    store: GuardStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    _add_receipts(store, 1)
    reply: dict[str, object] = {"fleetPostureRequest": {"inventory": "full"}}
    bodies = _install_transport(monkeypatch, extra=reply)

    guard_runner_module.sync_receipts(store)
    assert fp.full_inventory_requested(store)
    reply.clear()
    guard_runner_module.sync_receipts(store)

    assert bodies[1]["syncContext"]["fleetPosture"]["inventory"]["mode"] == "full"
    assert not fp.full_inventory_requested(store)


def test_posture_is_not_committed_when_the_request_fails(store: GuardStore, monkeypatch: pytest.MonkeyPatch) -> None:
    _add_receipts(store, 1)
    _install_transport(monkeypatch, fail_after=0)

    with pytest.raises(Exception):  # noqa: B017 - any transport failure surfaces from sync_receipts
        guard_runner_module.sync_receipts(store)

    assert not store.get_sync_payload(fp.LAST_SENT_STATE_KEY)


def test_posture_failure_never_blocks_receipt_sync(store: GuardStore, monkeypatch: pytest.MonkeyPatch) -> None:
    _add_receipts(store, 1)
    bodies = _install_transport(monkeypatch)

    def boom(*_args, **_kwargs):
        raise RuntimeError("builder exploded")

    monkeypatch.setattr(guard_runner_module, "build_fleet_posture_state", boom)

    summary = guard_runner_module.sync_receipts(store)

    assert summary["receipts"] == 1
    assert "fleetPosture" not in bodies[0]["syncContext"]


def _signed_bundle(version: str) -> dict[str, object]:
    return sign_policy_bundle(
        {
            "contractVersion": "guard-policy-bundle.v1",
            "bundleVersion": version,
            "bundleHash": "",
            "issuedAt": "2026-10-16T11:00:00+00:00",
            "expiresAt": None,
            "verifier": {"algorithm": "rsa-pss-sha256", "keyId": "guard-policy-bundle-v1", "signature": None},
            "rolloutState": "enforcing",
            "policyDefaults": {
                "mode": "enforce",
                "defaultAction": "warn",
                "unknownPublisherAction": "review",
                "changedHashAction": "require-reapproval",
                "newNetworkDomainAction": "warn",
                "subprocessAction": "block",
                "telemetryEnabled": False,
                "syncEnabled": True,
            },
            "rules": [],
            "acknowledgements": [],
        }
    )


def test_new_bundle_is_acknowledged_in_the_same_cycle_with_one_followup(
    store: GuardStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    store.set_sync_payload("policy_bundle_keyring", policy_bundle_test_keyring(), "2026-10-16T10:00:00Z")
    bundle = _signed_bundle("policy-2026-10-16.1")
    bodies = _install_transport(monkeypatch, extra={"policyBundle": bundle})

    guard_runner_module.sync_receipts(store)

    # One request with the previous (empty) ack, then exactly one follow-up carrying the new ack.
    assert len(bodies) == 2
    assert "policyBundleAcknowledgement" not in bodies[0]["syncContext"]
    followup = bodies[1]
    assert followup["receipts"] == []
    ack = followup["syncContext"]["policyBundleAcknowledgement"]
    assert ack["bundleHash"] == bundle["bundleHash"]
    assert ack["status"] == "synced"
    Draft202012Validator(SCHEMA).validate(followup["syncContext"]["fleetPosture"])
    assert followup["syncContext"]["fleetPosture"]["policy"]["appliedBundleVersion"] in (None, 1)
    recorded = store.get_sync_payload(FOLLOWUP_KEY)
    assert isinstance(recorded, dict)
    assert recorded["bundleHash"] == bundle["bundleHash"]


def test_followup_is_not_repeated_for_the_same_bundle(store: GuardStore, monkeypatch: pytest.MonkeyPatch) -> None:
    store.set_sync_payload("policy_bundle_keyring", policy_bundle_test_keyring(), "2026-10-16T10:00:00Z")
    bundle = _signed_bundle("policy-2026-10-16.2")
    bodies = _install_transport(monkeypatch, extra={"policyBundle": bundle})

    guard_runner_module.sync_receipts(store)
    sent_after_first_cycle = len(bodies)
    guard_runner_module.sync_receipts(store)

    # The next cycle already carries the ack, so it sends one request and no follow-up.
    assert len(bodies) == sent_after_first_cycle + 1
    assert bodies[-1]["syncContext"]["policyBundleAcknowledgement"]["bundleHash"] == bundle["bundleHash"]


def test_failed_followup_is_recorded_and_never_loops(store: GuardStore, monkeypatch: pytest.MonkeyPatch) -> None:
    store.set_sync_payload("policy_bundle_keyring", policy_bundle_test_keyring(), "2026-10-16T10:00:00Z")
    bundle = _signed_bundle("policy-2026-10-16.3")
    bodies = _install_transport(monkeypatch, extra={"policyBundle": bundle}, fail_after=1)

    guard_runner_module.sync_receipts(store)

    assert len(bodies) == 2
    recorded = store.get_sync_payload(FOLLOWUP_KEY)
    assert isinstance(recorded, dict)
    assert recorded["bundleHash"] == bundle["bundleHash"]


def test_followup_updates_the_in_memory_context(store: GuardStore, monkeypatch: pytest.MonkeyPatch) -> None:
    store.set_sync_payload("policy_bundle_keyring", policy_bundle_test_keyring(), "2026-10-16T10:00:00Z")
    bundle = _signed_bundle("policy-2026-10-16.4")
    _install_transport(monkeypatch, extra={"policyBundle": bundle})
    seen: list[dict[str, object]] = []
    original = guard_runner_module._send_policy_ack_followup

    def spy(store_arg, *, sync_context, **kwargs):
        original(store_arg, sync_context=sync_context, **kwargs)
        seen.append(dict(sync_context))

    monkeypatch.setattr(guard_runner_module, "_send_policy_ack_followup", spy)

    guard_runner_module.sync_receipts(store)

    assert seen
    ack = guard_runner_module._sync_context_acknowledgement(seen[0])
    assert ack is not None
    assert ack["bundleHash"] == bundle["bundleHash"]

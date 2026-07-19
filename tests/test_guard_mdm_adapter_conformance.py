from __future__ import annotations

import base64
import json
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from codex_plugin_scanner.guard.mdm.adapter_conformance import (
    AdapterConformanceError,
    ObserverAdapterConformanceHarness,
    RemediationAdapterConformanceHarness,
)

NOW = datetime(2026, 7, 19, 12, 0, tzinfo=timezone.utc)
PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
PUBLIC_KEY = PRIVATE_KEY.public_key()


def signed(payload: dict[str, object], key_id: str) -> bytes:
    unsigned = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    value = base64.b64encode(PRIVATE_KEY.sign(unsigned)).decode()
    envelope = {
        **payload,
        "signature": {"algorithm": "ed25519", "keyId": key_id, "value": value},
    }
    return json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode()


def assertion(**updates: object) -> bytes:
    payload: dict[str, object] = {
        "schemaVersion": "observer-assertion.v1",
        "assertionId": "assertion-a",
        "workspaceId": "workspace-a",
        "observerId": "observer-a",
        "adapterId": "vendor-neutral-v1",
        "externalDeviceId": "external-device-a",
        "observedAt": "2026-07-19T11:59:30Z",
        "expiresAt": "2026-07-19T12:09:30Z",
        "detection": {
            "state": "present",
            "endpointOnline": True,
            "version": "3.1.0a9",
            "packageIdentity": "org.hiero.hol-guard",
            "reasonCodes": ["observer_current_present"],
        },
        "remediation": {"state": "none", "jobId": None},
    }
    payload.update(updates)
    return signed(payload, "observer-key-a")


def remediation(**updates: object) -> bytes:
    payload: dict[str, object] = {
        "schemaVersion": "remediation-job.v1",
        "jobId": "job-a",
        "workspaceId": "workspace-a",
        "deviceId": "device-a",
        "installationGeneration": "a" * 32,
        "action": "repair",
        "targetVersion": None,
        "idempotencyKey": "repair-device-a-generation-a",
        "issuedAt": "2026-07-19T11:59:30Z",
        "validForSeconds": 900,
        "attemptLimit": 3,
    }
    payload.update(updates)
    return signed(payload, "cloud-remediation-key-a")


def reason(exc: pytest.ExceptionInfo[AdapterConformanceError]) -> str:
    return str(exc.value)


def test_accepts_signed_assertion_and_treats_exact_duplicate_as_idempotent() -> None:
    harness = ObserverAdapterConformanceHarness()
    payload = assertion()
    first = harness.evaluate(payload, mapping_candidates=1, now=NOW, public_key=PUBLIC_KEY)
    duplicate = harness.evaluate(payload, mapping_candidates=1, now=NOW, public_key=PUBLIC_KEY)
    assert first.outcome == "accepted"
    assert duplicate.outcome == "duplicate"
    assert duplicate.digest == first.digest


def test_rejects_replay_with_changed_payload_and_bad_signature() -> None:
    harness = ObserverAdapterConformanceHarness()
    harness.evaluate(assertion(), mapping_candidates=1, now=NOW, public_key=PUBLIC_KEY)
    with pytest.raises(AdapterConformanceError) as replay:
        harness.evaluate(
            assertion(detection={"state": "absent", "endpointOnline": True, "version": None,
                                 "packageIdentity": None, "reasonCodes": ["observer_current_absent"]}),
            mapping_candidates=1,
            now=NOW,
            public_key=PUBLIC_KEY,
        )
    assert reason(replay) == "adapter_assertion_replay_conflict"

    tampered = bytearray(assertion())
    tampered[-10] = ord("B")
    with pytest.raises(AdapterConformanceError):
        ObserverAdapterConformanceHarness().evaluate(
            bytes(tampered), mapping_candidates=1, now=NOW, public_key=PUBLIC_KEY
        )


def test_enforces_clock_skew_expiry_and_partial_evidence() -> None:
    with pytest.raises(AdapterConformanceError) as skew:
        ObserverAdapterConformanceHarness().evaluate(
            assertion(observedAt="2026-07-19T12:01:01Z", expiresAt="2026-07-19T12:10:00Z"),
            mapping_candidates=1,
            now=NOW,
            public_key=PUBLIC_KEY,
        )
    assert reason(skew) == "adapter_clock_skew"

    with pytest.raises(AdapterConformanceError) as expired:
        ObserverAdapterConformanceHarness().evaluate(
            assertion(observedAt="2026-07-19T11:40:00Z", expiresAt="2026-07-19T11:50:00Z"),
            mapping_candidates=1,
            now=NOW,
            public_key=PUBLIC_KEY,
        )
    assert reason(expired) == "adapter_assertion_expired"

    with pytest.raises(AdapterConformanceError) as partial:
        ObserverAdapterConformanceHarness().evaluate(
            assertion(detection={"state": "partial", "endpointOnline": True, "version": None,
                                 "packageIdentity": None, "reasonCodes": []}),
            mapping_candidates=1,
            now=NOW,
            public_key=PUBLIC_KEY,
        )
    assert reason(partial) == "adapter_partial_without_reason"


def test_quarantines_mapping_collisions_and_represents_outage_without_evidence() -> None:
    collision = ObserverAdapterConformanceHarness().evaluate(
        assertion(), mapping_candidates=2, now=NOW, public_key=PUBLIC_KEY
    )
    outage = ObserverAdapterConformanceHarness().evaluate(
        None,
        mapping_candidates=0,
        now=NOW,
        public_key=PUBLIC_KEY,
        transport_error="vendor_timeout",
    )
    assert (collision.outcome, collision.reason) == ("quarantined", "mapping_not_unique")
    assert (outage.outcome, outage.reason, outage.digest) == (
        "outage",
        "observer_unavailable",
        None,
    )


def test_remediation_is_signed_allowlisted_bounded_and_replay_safe() -> None:
    harness = RemediationAdapterConformanceHarness()
    payload = remediation()
    assert harness.evaluate(payload, now=NOW, public_key=PUBLIC_KEY).outcome == "accepted"
    assert harness.evaluate(payload, now=NOW, public_key=PUBLIC_KEY).outcome == "duplicate"

    with pytest.raises(AdapterConformanceError) as action:
        RemediationAdapterConformanceHarness().evaluate(
            remediation(action="shell"), now=NOW, public_key=PUBLIC_KEY
        )
    assert reason(action) == "adapter_remediation_action_denied"

    with pytest.raises(AdapterConformanceError) as replay:
        harness.evaluate(remediation(action="policy-refresh"), now=NOW, public_key=PUBLIC_KEY)
    assert reason(replay) == "adapter_remediation_replay_conflict"


def test_remediation_rejects_expired_and_generationless_jobs() -> None:
    with pytest.raises(AdapterConformanceError) as expired:
        RemediationAdapterConformanceHarness().evaluate(
            remediation(issuedAt="2026-07-19T11:00:00Z", validForSeconds=60),
            now=NOW,
            public_key=PUBLIC_KEY,
        )
    assert reason(expired) == "adapter_remediation_expired"

    with pytest.raises(AdapterConformanceError) as generation:
        RemediationAdapterConformanceHarness().evaluate(
            remediation(installationGeneration="old-generation"), now=NOW, public_key=PUBLIC_KEY
        )
    assert reason(generation) == "adapter_remediation_invalid"

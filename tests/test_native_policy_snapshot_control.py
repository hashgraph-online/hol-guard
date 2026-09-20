from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_policy_snapshot_control as control
from codex_plugin_scanner.guard.native_policy_snapshot_codec import _canonical_json_bytes_v3 as canonical
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError

KEY = bytes([53] * 32)
RUNTIME = "a" * 64


def signed(response: dict[str, object], domain: bytes) -> bytes:
    return canonical(
        {"response": response, "mac": hmac.new(KEY, domain + canonical(response), hashlib.sha256).hexdigest()}
    )


def response_for(payload: bytes, *, authority: object = None) -> tuple[dict[str, object], bytes]:
    outer = json.loads(payload)
    request = outer["request"]
    intent = request["intent"]
    observe = outer["operation"] == "policy_snapshot_observe"
    request_domain = control._OBSERVATION_DOMAIN if observe else control._WITHDRAWAL_DOMAIN
    assert request["mac"] == hmac.new(KEY, request_domain + canonical(intent), hashlib.sha256).hexdigest()
    assert 1 <= outer["deadline_budget_ms"] <= 9_000
    assert len(payload) <= 4096
    base = {
        "runtime_identity": intent["runtime_identity"],
        "scope_digest": intent["scope_digest"],
        "resident_generation": 13,
        "request_sha256": hashlib.sha256(canonical(request)).hexdigest(),
    }
    if observe:
        return (
            {
                **base,
                "schema": "guard-policy-snapshot-observation-response.v1",
                "nonce": intent["nonce"],
                "authority": authority,
            },
            control._OBSERVATION_RESPONSE_DOMAIN,
        )
    return (
        {
            **base,
            "schema": "guard-policy-snapshot-withdrawal-response.v1",
            "status": "withdrawn",
            "generation": intent["retirement_generation"],
            "policy_digest": intent["retirement_policy_digest"],
        },
        control._WITHDRAWAL_RESPONSE_DOMAIN,
    )


def observe(home: Path, client, *, deadline: float | None = None):
    return control.observe_native_authority(
        executable=home / "synthetic",
        guard_home=home,
        runtime_identity=RUNTIME,
        verifier_key=KEY,
        deadline_monotonic=deadline or time.monotonic() + 1,
        client=client,
    )


def client_with_authority(authority=None):
    def client(**kwargs):
        response, domain = response_for(kwargs["payload"], authority=authority)
        return signed(response, domain)

    return client


def reference():
    return {"fingerprint": "b" * 64, "generation_floor": 7, "policy_digest": "c" * 64, "usable_snapshot": True}


@pytest.mark.parametrize("authority", [None, reference(), {**reference(), "usable_snapshot": False}])
def test_observation_and_retirement_preserve_exact_subject_and_existing_deadline(tmp_path, authority):
    deadline = time.monotonic() + 0.5
    calls = []

    def client(**kwargs):
        calls.append(kwargs)
        assert kwargs["deadline_monotonic"] <= deadline
        response, domain = response_for(kwargs["payload"], authority=authority)
        return signed(response, domain)

    observation = observe(tmp_path, client, deadline=deadline)
    assert observation.resident_generation == 13
    assert (observation.authority is None) == (authority is None)
    retirement = control.withdraw_native_authority(
        executable=tmp_path / "synthetic",
        guard_home=tmp_path,
        observation=observation,
        retirement_generation=10,
        retirement_policy_digest="d" * 64,
        verifier_key=KEY,
        deadline_monotonic=deadline,
        client=client,
    )
    assert retirement == control.NativeAuthorityRetirement(RUNTIME, observation.scope_digest, 13, 10, "d" * 64)
    assert len(calls) == 2
    sent = json.loads(calls[1]["payload"])["request"]["intent"]
    assert sent["expected_authority"] == authority
    assert sent["resident_generation"] == observation.resident_generation


def test_actual_rust_signed_response_vectors_are_accepted_only_for_exact_request():
    vectors = json.loads((Path(__file__).parent / "fixtures/native_policy_control_vectors.json").read_text())
    assert vectors["source_head"] == "592e18dc9c75dec582ad30cee87b77bc39888102"
    key = bytes.fromhex(vectors["synthetic_verifier_key_hex"])
    for vector in vectors["vectors"]:
        domain = (
            control._OBSERVATION_RESPONSE_DOMAIN
            if vector["operation"] == "policy_snapshot_observe"
            else control._WITHDRAWAL_RESPONSE_DOMAIN
        )
        response = control._response(canonical(vector["response"]), vector["request"], key, domain)
        assert response == vector["response"]["response"]
        wrong_request: dict[str, object] = {**vector["request"], "mac": "0" * 64}
        with pytest.raises(NativePolicySnapshotError, match="subject_changed"):
            control._response(canonical(vector["response"]), wrong_request, key, domain)
        with pytest.raises(NativePolicySnapshotError, match="unauthenticated"):
            control._response(canonical(vector["response"]), vector["request"], b"x" * 32, domain)


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema", "unknown"),
        ("runtime_identity", "b" * 64),
        ("scope_digest", "c" * 64),
        ("resident_generation", True),
        ("resident_generation", 0),
        ("resident_generation", 2**64),
        ("nonce", "d" * 64),
        ("request_sha256", "e" * 64),
        ("extra", False),
    ],
)
def test_signed_observation_mismatches_are_refused(tmp_path, field, value):
    def client(**kwargs):
        response, domain = response_for(kwargs["payload"])
        response[field] = value
        return signed(response, domain)

    with pytest.raises(NativePolicySnapshotError):
        observe(tmp_path, client)


@pytest.mark.parametrize(
    "field,value",
    [
        ("fingerprint", "UPPER"),
        ("generation_floor", False),
        ("generation_floor", 0),
        ("generation_floor", 2**64),
        ("policy_digest", None),
        ("usable_snapshot", 1),
        ("extra", True),
    ],
)
def test_signed_unknown_authority_never_becomes_authenticated_absence(tmp_path, field, value):
    authority = reference()
    authority[field] = value
    with pytest.raises(NativePolicySnapshotError):
        observe(tmp_path, client_with_authority(authority))


@pytest.mark.parametrize(
    "output",
    [
        None,
        b"",
        b"x" * 4097,
        b"{}",
        b"null",
        b'{"x":1,"x":2}',
        b"[" * 1000 + b"]" * 1000,
        b'{"error":"synthetic private error"}',
        b'{"response": {}, "mac": "bad"}',
    ],
)
def test_malformed_bounded_and_private_outputs_refuse_finitely(tmp_path, output):
    with pytest.raises(NativePolicySnapshotError) as raised:
        observe(tmp_path, lambda **_: output)
    assert str(raised.value) in {
        "native_policy_snapshot_control_transport_failed",
        "native_policy_snapshot_control_response_invalid",
    }
    assert "synthetic private" not in str(raised.value)


@pytest.mark.parametrize("mutation", ["mac", "purpose", "noncanonical"])
def test_wrong_mac_purpose_and_encoding_are_refused(tmp_path, mutation):
    def client(**kwargs):
        response, domain = response_for(kwargs["payload"])
        if mutation == "purpose":
            domain = control._WITHDRAWAL_RESPONSE_DOMAIN
        output = signed(response, domain)
        if mutation == "mac":
            value = json.loads(output)
            value["mac"] = "0" * 64
            output = canonical(value)
        if mutation == "noncanonical":
            output = b" " + output
        return output

    with pytest.raises(NativePolicySnapshotError):
        observe(tmp_path, client)


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema", "unknown"),
        ("status", "accepted"),
        ("runtime_identity", "b" * 64),
        ("scope_digest", "c" * 64),
        ("resident_generation", 14),
        ("resident_generation", True),
        ("generation", 9),
        ("generation", True),
        ("policy_digest", "e" * 64),
        ("request_sha256", "f" * 64),
        ("extra", True),
    ],
)
def test_signed_withdrawal_mismatch_never_authorizes_commit(tmp_path, field, value):
    observation = observe(tmp_path, client_with_authority(reference()))

    def client(**kwargs):
        response, domain = response_for(kwargs["payload"])
        response[field] = value
        return signed(response, domain)

    with pytest.raises(NativePolicySnapshotError):
        control.withdraw_native_authority(
            executable=tmp_path / "synthetic",
            guard_home=tmp_path,
            observation=observation,
            retirement_generation=10,
            retirement_policy_digest="d" * 64,
            verifier_key=KEY,
            deadline_monotonic=time.monotonic() + 1,
            client=client,
        )


@pytest.mark.parametrize("generation", [0, 7, True, 2**64])
def test_invalid_retirement_generation_never_sends(tmp_path, generation):
    observation = observe(tmp_path, client_with_authority(reference()))

    def client(**_):
        pytest.fail("invalid retirement must not send")

    with pytest.raises(NativePolicySnapshotError):
        control.withdraw_native_authority(
            executable=tmp_path / "synthetic",
            guard_home=tmp_path,
            observation=observation,
            retirement_generation=generation,
            retirement_policy_digest="d" * 64,
            verifier_key=KEY,
            deadline_monotonic=time.monotonic() + 1,
            client=client,
        )


def test_swapped_home_and_lost_ack_cannot_be_inferred_success(tmp_path):
    observation = observe(tmp_path, client_with_authority(reference()))
    calls = []

    def client(**kwargs):
        calls.append(kwargs)
        return None

    for candidate in [replace(observation, scope_digest="0" * 64), observation]:
        with pytest.raises(NativePolicySnapshotError):
            control.withdraw_native_authority(
                executable=tmp_path / "synthetic",
                guard_home=tmp_path,
                observation=candidate,
                retirement_generation=10,
                retirement_policy_digest="d" * 64,
                verifier_key=KEY,
                deadline_monotonic=time.monotonic() + 1,
                client=client,
            )
    assert len(calls) == 1


def test_original_deadline_expiry_and_transport_exception_are_finite(tmp_path, monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(control.time, "monotonic", lambda: clock[0])
    with pytest.raises(NativePolicySnapshotError, match="deadline_exceeded"):
        observe(tmp_path, lambda **_: pytest.fail("expired"), deadline=99.0)

    def late(**kwargs):
        assert kwargs["deadline_monotonic"] == 100.5
        response, domain = response_for(kwargs["payload"])
        clock[0] = 100.5
        return signed(response, domain)

    with pytest.raises(NativePolicySnapshotError, match="deadline_exceeded"):
        observe(tmp_path, late, deadline=100.5)
    clock[0] = 100.0

    def broken(**_):
        raise OSError("synthetic private path")

    with pytest.raises(NativePolicySnapshotError, match="control_transport_failed") as raised:
        observe(tmp_path, broken, deadline=100.5)
    assert "private" not in str(raised.value)
    assert raised.value.__suppress_context__


@pytest.mark.parametrize("deadline", [True, float("inf"), float("nan"), -(10**500), 10**500])
def test_invalid_deadline_never_sends_and_refuses_finitely(tmp_path, deadline):
    with pytest.raises(NativePolicySnapshotError, match="deadline_exceeded"):
        control.observe_native_authority(
            executable=tmp_path / "synthetic",
            guard_home=tmp_path,
            runtime_identity=RUNTIME,
            verifier_key=KEY,
            deadline_monotonic=deadline,
            client=lambda **_: pytest.fail("invalid deadline"),
        )


def test_replayed_observation_and_explicit_native_refusal_are_never_retried(tmp_path):
    captured = []

    def first(**kwargs):
        response, domain = response_for(kwargs["payload"])
        captured.append(signed(response, domain))
        return captured[0]

    observe(tmp_path, first)
    with pytest.raises(NativePolicySnapshotError, match="subject_changed"):
        observe(tmp_path, lambda **_: captured[0])
    calls = []

    def refused(**kwargs):
        calls.append(kwargs)
        return canonical({"error": "native_policy_snapshot_writer_busy", "retryable": True})

    with pytest.raises(NativePolicySnapshotError, match="writer_busy"):
        observe(tmp_path, refused)
    assert len(calls) == 1

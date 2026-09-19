"""Actual private generation storage and strict ACK binding for scoped publication."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import Any, TypedDict, cast

import pytest

from codex_plugin_scanner.guard import native_policy_snapshot_v4_generation as generation
from codex_plugin_scanner.guard import native_policy_snapshot_v4_transport as transport
from codex_plugin_scanner.guard.native_policy_authority_contract import NativePolicyAuthorityCapabilities
from codex_plugin_scanner.guard.native_policy_authority_decode import native_policy_authority_from_mapping
from codex_plugin_scanner.guard.native_policy_authority_read import NativeVerifiedPolicyInputs
from codex_plugin_scanner.guard.native_policy_snapshot_codec import derive_native_policy_verifier_key
from codex_plugin_scanner.guard.native_policy_snapshot_constants import (
    _MAX_GENERATION,
    _NATIVE_POLICY_SNAPSHOT_PENDING_NAME,
    NATIVE_POLICY_SNAPSHOT_CACHE_NAME,
    POLICY_SNAPSHOT_ACK_REQUIRES_NEW_GENERATION,
    NativePolicySnapshotError,
)
from codex_plugin_scanner.guard.native_policy_snapshot_contract import build_policy_snapshot_v3
from codex_plugin_scanner.guard.native_policy_snapshot_storage import (
    _read_v3_generation_state,
    _write_v3_snapshot_file,
)
from codex_plugin_scanner.guard.native_policy_snapshot_v4 import ACK_SCHEMA, verify_snapshot_v4
from tests.native_policy_snapshot_test_fixtures import _config

_MASTER = b"s" * 32
_CAPABILITIES = NativePolicyAuthorityCapabilities(4, frozenset({"policy-scoped-authority-v1"}))


def _inputs(expiry: int | None = 2000):
    authority = native_policy_authority_from_mapping(
        {
            "schema": "guard-native-policy-authority.v1",
            "generic_precedence": "specificity-recency.v1",
            "rows": [
                {
                    "decision_id": 7,
                    "harness": "codex",
                    "scope": "artifact",
                    "action": "block",
                    "source_kind": "signed-bundle",
                    "updated_at_us": 1,
                    "artifact_id": "synthetic",
                    "artifact_hash": None,
                    "workspace": None,
                    "publisher": None,
                    "expires_at_ms": None,
                    "exact_command_sha256": None,
                    "requires_exact_context": False,
                }
            ],
            "managed": None,
        }
    )
    return NativeVerifiedPolicyInputs(authority, None, "[]", "d" * 64, expiry, ())


class _Arguments(TypedDict):
    config: dict[str, object]
    guard_home: Path
    runtime_identity: str
    rule_digest: str
    master_key: bytes
    inputs: NativeVerifiedPolicyInputs
    capabilities: NativePolicyAuthorityCapabilities


def _arguments(tmp_path: Path, **updates: Any) -> _Arguments:
    home = tmp_path / "guard"
    home.mkdir(mode=0o700, exist_ok=True)
    values = {
        "config": _config(),
        "guard_home": home,
        "runtime_identity": "a" * 64,
        "rule_digest": "b" * 64,
        "master_key": _MASTER,
        "inputs": _inputs(),
        "capabilities": _CAPABILITIES,
        **updates,
    }
    # Fault-injection cases deliberately vary typed generation inputs.
    return cast(_Arguments, cast(object, values))


def _reserve(tmp_path, **updates):
    return generation.reserve_snapshot_v4(**_arguments(tmp_path, **updates), issued_at_ms=1000)


def _ack(snapshot, **updates):
    return {
        "schema": ACK_SCHEMA,
        "status": "accepted",
        "generation": snapshot["generation"],
        "policy_digest": snapshot["policy_digest"],
        "source_input_digest": snapshot["source_input_digest"],
        "idempotent": False,
        "resident_generation": 3,
        **updates,
    }


def _publish(tmp_path, client, **updates):
    return transport.publish_snapshot_v4(
        **_arguments(tmp_path),
        executable=tmp_path / "synthetic-runtime",
        client=client,
        wall_clock=lambda: 1.0,
        monotonic_clock=lambda: 10.0,
        **updates,
    )


def test_each_attempt_reserves_fresh_signed_bytes_and_frozen_source(tmp_path):
    inputs = _inputs()
    first = _reserve(tmp_path, inputs=inputs)
    second = _reserve(tmp_path, inputs=inputs)
    assert first.snapshot["generation"] == 1
    assert second.snapshot["generation"] == 2
    assert first.snapshot_bytes != second.snapshot_bytes
    assert second.inputs is inputs
    verify_snapshot_v4(
        second.snapshot,
        verifier_key=derive_native_policy_verifier_key(_MASTER),
        expected_runtime_identity="a" * 64,
        expected_rule_digest="b" * 64,
        minimum_generation=2,
        now_ms=1000,
    )
    assert _read_v3_generation_state(tmp_path / "guard") == (2, second.snapshot["policy_digest"])
    exposed = cast(dict[str, Any], second.snapshot)
    exposed["scoped_authority"]["rows"][0]["action"] = "allow"
    assert cast(dict[str, Any], second.snapshot)["scoped_authority"]["rows"][0]["action"] == "block"
    with pytest.raises(FrozenInstanceError):
        second.__setattr__("snapshot_bytes", b"{}")


def test_actual_shared_generation_lock_serializes_concurrent_reservations(tmp_path):
    arguments = _arguments(tmp_path)
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: generation.reserve_snapshot_v4(**arguments, issued_at_ms=1000), range(8)))
    assert sorted(cast(int, item.snapshot["generation"]) for item in results) == list(range(1, 9))
    assert len({item.snapshot_bytes for item in results}) == 8
    state = _read_v3_generation_state(tmp_path / "guard")
    assert state is not None and state[0] == 8


def test_pending_v3_journal_is_recovered_before_v4_reservation(tmp_path):
    arguments = _arguments(tmp_path)
    home = arguments["guard_home"]
    pending = build_policy_snapshot_v3(
        config=_config(),
        guard_home=home,
        runtime_identity="a" * 64,
        rule_digest="b" * 64,
        verifier_key=derive_native_policy_verifier_key(_MASTER),
        generation=6,
        issued_at_ms=1000,
        expires_at_ms=2000,
    )
    _write_v3_snapshot_file(home, _NATIVE_POLICY_SNAPSHOT_PENDING_NAME, pending)
    candidate = generation.reserve_snapshot_v4(**arguments, issued_at_ms=1000)
    assert candidate.snapshot["generation"] == 7
    assert not (home / "native-runtime" / _NATIVE_POLICY_SNAPSHOT_PENDING_NAME).exists()
    assert json.loads((home / "native-runtime" / NATIVE_POLICY_SNAPSHOT_CACHE_NAME).read_bytes()) == pending
    assert _read_v3_generation_state(home) == (7, candidate.snapshot["policy_digest"])


def test_corrupt_pending_transaction_cannot_be_skipped(tmp_path):
    arguments = _arguments(tmp_path)
    home = arguments["guard_home"]
    directory = home / "native-runtime"
    directory.mkdir(mode=0o700)
    path = directory / _NATIVE_POLICY_SNAPSHOT_PENDING_NAME
    path.write_bytes(b"{}")
    path.chmod(0o600)
    with pytest.raises(NativePolicySnapshotError):
        generation.reserve_snapshot_v4(**arguments, issued_at_ms=1000)
    assert _read_v3_generation_state(home) is None


def test_failed_signing_does_not_advance_counter_or_send_payload(tmp_path, monkeypatch):
    first = _reserve(tmp_path)
    before = _read_v3_generation_state(tmp_path / "guard")
    original = generation.build_policy_snapshot_v4

    def fail_actual(**kwargs):
        if kwargs["generation"] > 1:
            raise NativePolicySnapshotError("synthetic_signing_failure")
        return original(**kwargs)

    monkeypatch.setattr(generation, "build_policy_snapshot_v4", fail_actual)
    calls = []
    with pytest.raises(NativePolicySnapshotError, match="synthetic_signing_failure"):
        _publish(tmp_path, lambda **kwargs: calls.append(kwargs))
    assert calls == []
    assert _read_v3_generation_state(tmp_path / "guard") == before == (1, first.snapshot["policy_digest"])


def test_counter_write_failure_never_transmits_signed_candidate(tmp_path, monkeypatch):
    calls = []

    def failed_write(*_args, **_kwargs):
        raise NativePolicySnapshotError("synthetic_state_write_failure")

    monkeypatch.setattr(generation, "_write_v3_generation_state", failed_write)
    with pytest.raises(NativePolicySnapshotError, match="synthetic_state_write_failure"):
        _publish(tmp_path, lambda **kwargs: calls.append(kwargs))
    assert calls == []


@pytest.mark.parametrize("expiry", [999, 1000, True])
def test_expired_or_invalid_captured_source_never_reserves(tmp_path, expiry):
    with pytest.raises(NativePolicySnapshotError):
        _reserve(tmp_path, inputs=_inputs(expiry))
    assert _read_v3_generation_state(tmp_path / "guard") is None


def test_snapshot_lease_never_outlives_captured_source(tmp_path):
    assert _reserve(tmp_path).snapshot["expires_at_ms"] == 2000
    assert _reserve(tmp_path, inputs=_inputs(None)).snapshot["expires_at_ms"] == 1000 + 86_400_000
    with pytest.raises(NativePolicySnapshotError, match="exhausted"):
        _reserve(tmp_path, minimum_generation=_MAX_GENERATION)


def test_attempt_snapshot_freezes_config_before_lock_entry(tmp_path, monkeypatch):
    from contextlib import contextmanager

    config = _config()
    _reserve(tmp_path)
    original = generation._v3_generation_lock

    @contextmanager
    def interposed(*args, **kwargs):
        config["default_action"] = "allow"
        with original(*args, **kwargs) as lock:
            yield lock

    monkeypatch.setattr(generation, "_v3_generation_lock", interposed)
    candidate = _reserve(tmp_path, config=config)
    policy = candidate.snapshot["effective_policy"]
    assert isinstance(policy, dict) and policy["default_action"] == "warn"
    state = _read_v3_generation_state(tmp_path / "guard")
    assert state is not None and state[1] == candidate.snapshot["policy_digest"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema", "guard-policy-snapshot-ack.v1"),
        ("status", "refused"),
        ("status", []),
        ("generation", True),
        ("generation", 0),
        ("generation", 1.0),
        ("generation", 2**64),
        ("resident_generation", False),
        ("resident_generation", -1),
        ("resident_generation", "3"),
        ("policy_digest", "A" * 64),
        ("policy_digest", "x" * 63),
        ("source_input_digest", "x" * 64),
        ("idempotent", 1),
        ("extra", "ignored"),
    ],
)
def test_ack_rejects_invalid_field_values(field, value):
    value = _ack({"generation": 1, "policy_digest": "a" * 64, "source_input_digest": "b" * 64}, **{field: value})
    with pytest.raises(NativePolicySnapshotError):
        transport.decode_ack_v4(json.dumps(value).encode())


@pytest.mark.parametrize(
    "field",
    ["schema", "status", "generation", "policy_digest", "source_input_digest", "idempotent", "resident_generation"],
)
def test_ack_requires_every_field(field):
    value = _ack({"generation": 1, "policy_digest": "a" * 64, "source_input_digest": "b" * 64})
    value.pop(field)
    with pytest.raises(NativePolicySnapshotError):
        transport.decode_ack_v4(json.dumps(value).encode())


@pytest.mark.parametrize("value", [None, b"", b"{}", b"{" * 4097, b'{"error":"refused","retryable":false}', b"[]"])
def test_ack_rejects_missing_oversized_or_refused_output(value):
    with pytest.raises(NativePolicySnapshotError):
        transport.decode_ack_v4(value)


def test_ack_rejects_duplicate_status_and_recovery_with_idempotence():
    value = _ack({"generation": 1, "policy_digest": "a" * 64, "source_input_digest": "b" * 64})
    encoded = json.dumps(value).encode().replace(b'"status": "accepted"', b'"status":"refused","status":"accepted"')
    with pytest.raises(NativePolicySnapshotError):
        transport.decode_ack_v4(encoded)
    value.update(status=POLICY_SNAPSHOT_ACK_REQUIRES_NEW_GENERATION, idempotent=True)
    with pytest.raises(NativePolicySnapshotError):
        transport.decode_ack_v4(json.dumps(value).encode())


@pytest.mark.parametrize(
    "field,value",
    [("generation", 9), ("policy_digest", "e" * 64), ("source_input_digest", "e" * 64), ("resident_generation", 4)],
)
def test_authenticated_ack_must_match_exact_candidate_and_known_resident(tmp_path, field, value):
    def client(**kwargs):
        snapshot = json.loads(kwargs["payload"])["request"]["snapshot"]
        return json.dumps(_ack(snapshot, **{field: value})).encode()

    with pytest.raises(NativePolicySnapshotError, match="ack_mismatch"):
        _publish(tmp_path, client, expected_resident_generation=3)


def test_recovery_is_not_accepted_and_retry_uses_fresh_generation(tmp_path):
    attempts = []

    def client(**kwargs):
        request = json.loads(kwargs["payload"])
        assert request["request"]["schema"] == "guard-policy-snapshot-push.v2"
        snapshot = request["request"]["snapshot"]
        assert _read_v3_generation_state(tmp_path / "guard") == (snapshot["generation"], snapshot["policy_digest"])
        attempts.append(snapshot)
        status = POLICY_SNAPSHOT_ACK_REQUIRES_NEW_GENERATION if len(attempts) == 1 else "accepted"
        return json.dumps(_ack(snapshot, status=status)).encode()

    publication = _publish(tmp_path, client)
    assert [item["generation"] for item in attempts] == [1, 2]
    assert publication.candidate.snapshot == attempts[1]
    assert publication.resident_generation == 3


def test_repeated_recovery_and_missing_ack_never_mark_application(tmp_path):
    attempts = []

    def client(**kwargs):
        snapshot = json.loads(kwargs["payload"])["request"]["snapshot"]
        attempts.append(snapshot["generation"])
        return json.dumps(_ack(snapshot, status=POLICY_SNAPSHOT_ACK_REQUIRES_NEW_GENERATION)).encode()

    with pytest.raises(NativePolicySnapshotError, match="ack_mismatch"):
        _publish(tmp_path, client)
    assert attempts == [1, 2]
    with pytest.raises(NativePolicySnapshotError):
        _publish(tmp_path, lambda **_kwargs: None)
    state = _read_v3_generation_state(tmp_path / "guard")
    assert state is not None and state[0] == 3


def test_source_expiry_during_ipc_refuses_even_an_exact_accepted_ack(tmp_path):
    now = [1.0]

    def client(**kwargs):
        now[0] = 2.0
        return json.dumps(_ack(json.loads(kwargs["payload"])["request"]["snapshot"])).encode()

    with pytest.raises(NativePolicySnapshotError, match="expired"):
        transport.publish_snapshot_v4(
            **_arguments(tmp_path),
            executable=tmp_path / "synthetic",
            client=client,
            wall_clock=lambda: now[0],
            monotonic_clock=lambda: 10.0,
        )


def test_scoped_generation_authenticates_and_detaches_command_controls(tmp_path):
    from tests.test_native_command_control_binding import _binding

    binding = _binding()
    candidate = _reserve(tmp_path, command_extensions=binding)
    snapshot = candidate.snapshot
    assert snapshot["command_extensions"] == binding
    verify_snapshot_v4(
        snapshot,
        verifier_key=derive_native_policy_verifier_key(_MASTER),
        expected_runtime_identity="a" * 64,
        expected_rule_digest="b" * 64,
        minimum_generation=1,
        now_ms=1000,
    )
    layers = binding["layers"]
    assert isinstance(layers, list) and isinstance(layers[0], dict)
    layers[0]["global_lockdown"] = True
    retained = candidate.snapshot["command_extensions"]
    assert isinstance(retained, dict)
    retained_layers = retained["layers"]
    assert isinstance(retained_layers, list) and isinstance(retained_layers[0], dict)
    assert retained_layers[0]["global_lockdown"] is False
    del snapshot["command_extensions"]
    with pytest.raises(NativePolicySnapshotError, match="digest_mismatch"):
        verify_snapshot_v4(
            snapshot,
            verifier_key=derive_native_policy_verifier_key(_MASTER),
            expected_runtime_identity="a" * 64,
            expected_rule_digest="b" * 64,
            minimum_generation=1,
            now_ms=1000,
        )
    changed = _reserve(tmp_path, command_extensions=_binding(revision=4))
    assert changed.snapshot["policy_digest"] != candidate.snapshot["policy_digest"]
    assert changed.snapshot["source_input_digest"] == candidate.snapshot["source_input_digest"]

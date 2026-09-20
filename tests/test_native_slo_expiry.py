"""Source orchestration checks; no mocked ACK is installed qualification proof."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_hook_edge, native_resident_client, native_runtime
from codex_plugin_scanner.guard import native_policy_snapshot_acked as acked
from codex_plugin_scanner.guard import native_policy_snapshot_contract as contract
from codex_plugin_scanner.guard import native_policy_snapshot_generation as generation
from codex_plugin_scanner.guard import native_policy_snapshot_storage as storage
from codex_plugin_scanner.guard.native_policy_snapshot_publisher import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.store import GuardStore
from scripts import native_slo_expiry as fixture
from scripts.native_slo_command_fixture import prepare_empty_command_authority
from scripts.native_slo_contract import assert_privacy_safe
from scripts.native_slo_failure import FixtureFailureError, failure_evidence


def test_real_signed_renewal_preserves_protected_control_authority(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard")
    prepare_empty_command_authority(store)
    publisher = NativePolicySnapshotPublisher(store=store)
    try:
        config = publisher._compiled_effective_policy()
        controls = publisher._compiled_command_extensions()
        material = store._policy_integrity_secret_material(create=True)
        assert isinstance(material, tuple) and isinstance(material[0], bytes)
        previous = generation.native_policy_snapshot_v3(
            config=config,
            guard_home=store.guard_home,
            runtime_identity="a" * 64,
            rule_digest="b" * 64,
            policy_integrity_key=material[0],
            command_extensions=controls,
        )
        previous_generation = previous["generation"]
        assert isinstance(previous_generation, int)
        issued = int(fixture.time.time() * 1000)
        renewed = generation.native_policy_snapshot_v3(
            config=config,
            guard_home=store.guard_home,
            runtime_identity="a" * 64,
            rule_digest="b" * 64,
            policy_integrity_key=material[0],
            **fixture._renewal_command_inputs(publisher, previous),
            issued_at_ms=issued,
            expires_at_ms=issued + 3_000,
            renew_after_generation=previous_generation,
        )
        assert controls["health"] == "protected"
        assert "authority" in controls
        renewed_generation = renewed["generation"]
        assert isinstance(renewed_generation, int) and renewed_generation > previous_generation
        assert renewed["policy_digest"] == previous["policy_digest"]
        assert renewed["command_extensions"] == previous["command_extensions"] == controls
        assert renewed["expires_at_ms"] == issued + 3000 and renewed["issued_at_ms"] == issued
        # These are real signed publisher inputs, not a forged resident ACK or
        # authority file. No native resident was started or expiry accepted.
        assert acked.acked_snapshot_binding_for_store(store) is None
    finally:
        publisher.close()


def test_legacy_unbound_snapshot_never_invokes_candidate_only_compiler() -> None:
    assert fixture._renewal_command_inputs(object(), {"generation": 1}) == {}


@pytest.mark.parametrize("changed", (None, {}, {"revision": 2}))
def test_changed_or_malformed_acknowledged_controls_cannot_be_renewed(changed: object) -> None:
    publisher = SimpleNamespace(_compiled_command_extensions=lambda: changed)
    with pytest.raises(RuntimeError, match="command authority changed"):
        fixture._renewal_command_inputs(publisher, {"command_extensions": {"revision": 1}})
    with pytest.raises(RuntimeError, match="command binding invalid"):
        fixture._renewal_command_inputs(publisher, {"command_extensions": None})


def _modeled_session(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, fault: str = "", bound: bool = True):
    clock = SimpleNamespace(wall=100.0, mono=200.0)

    def sleep(seconds):
        clock.wall += seconds
        clock.mono += seconds

    monkeypatch.setattr(
        fixture, "time", SimpleNamespace(time=lambda: clock.wall, monotonic=lambda: clock.mono, sleep=sleep)
    )
    previous: dict[str, Any] = {
        "generation": 2,
        "policy_digest": "a" * 64,
        "mode": "enforce",
        "runtime_identity": "b" * 64,
        "issued_at_ms": 99_000,
        "expires_at_ms": 160_000,
    }
    if bound:
        previous["command_extensions"] = {"revision": 1}
    publisher = SimpleNamespace(
        current_snapshot=lambda: previous,
        _compiled_effective_policy=lambda: {},
        _compiled_command_extensions=lambda: previous["command_extensions"],
        _thread=None,
        closed=False,
    )
    publisher.close = lambda: setattr(publisher, "closed", True)
    store = SimpleNamespace(guard_home=tmp_path, _policy_integrity_secret_material=lambda **_: (b"m" * 32, "master-id"))
    worker = SimpleNamespace(policy_snapshot_publisher=publisher, prepare_workspace_policy=lambda *_a, **_k: None)
    session = SimpleNamespace(
        daemon=SimpleNamespace(_server=SimpleNamespace(hook_worker=worker)),
        store=store,
        guard_home=tmp_path,
        root=tmp_path,
        workspace=tmp_path,
    )
    status = SimpleNamespace(
        identity=SimpleNamespace(path=tmp_path / "never-executed", sha256="b" * 64),
        capabilities=SimpleNamespace(rule_digest="c" * 64),
    )
    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda: status)
    seen: dict[str, Any] = {"native_calls": [], "readbacks": 0}

    def build(**kwargs):
        seen["generation_inputs"] = kwargs
        assert kwargs["issued_at_ms"] == 100_000 and kwargs["expires_at_ms"] == 103_000
        assert kwargs["deadline_monotonic"] == 202.0
        assert kwargs["renew_after_generation"] == previous["generation"]
        if bound:
            assert kwargs["command_extensions"] == previous["command_extensions"]
        else:
            assert "command_extensions" not in kwargs
        result = dict(previous, generation=3, issued_at_ms=100_000, expires_at_ms=103_000)
        if fault == "changed_policy":
            result["policy_digest"] = "d" * 64
        return result

    monkeypatch.setattr(generation, "native_policy_snapshot_v3", build)
    monkeypatch.setattr(contract, "_policy_snapshot_push_bytes_v3", lambda value: json.dumps(value).encode())
    binding = {key: previous[key] for key in ("generation", "policy_digest", "runtime_identity", "mode")}
    binding["generation"] = 3
    if bound:
        binding["command_extensions_bound"] = True

    def readback(_store):
        seen["readbacks"] += 1
        if not seen["native_calls"]:
            result = dict(binding, generation=2)
            if fault == "starting_compact_stripped":
                result.pop("command_extensions_bound", None)
            return result
        if fault == "missing_binding" or (clock.wall >= 103 and fault != "retained_expired"):
            return None
        result = dict(binding)
        if fault.startswith("binding_"):
            field = fault.removeprefix("binding_")
            result[field] = "mismatch"
        if fault == "compact_bound_stripped":
            result.pop("command_extensions_bound", None)
        elif fault == "compact_bound_false":
            result["command_extensions_bound"] = False
        elif fault == "compact_bound_spurious":
            result["command_extensions_bound"] = True
        if fault == "expired_at_readback":
            clock.wall = 103.0
        return result

    monkeypatch.setattr(acked, "acked_snapshot_binding_for_store", readback)

    def full_readback(_path, **kwargs):
        assert isinstance(kwargs["verifier_key"], bytes)
        assert kwargs["maximum_bytes"] > 0
        if not seen["native_calls"]:
            accepted = dict(previous)
            if fault == "starting_full_stripped":
                accepted.pop("command_extensions", None)
            elif fault == "starting_full_mutated":
                accepted["command_extensions"] = {"revision": 2}
        else:
            accepted = dict(previous, generation=3, issued_at_ms=100_000, expires_at_ms=103_000)
            if fault == "readback_full_missing":
                return None
            if fault == "readback_controls_stripped":
                accepted.pop("command_extensions", None)
            elif fault == "readback_controls_mutated":
                accepted["command_extensions"] = {"revision": 2}
            elif fault == "readback_expiry_changed":
                accepted["expires_at_ms"] = 160_000
        return accepted, b"modeled-authenticated-file"

    monkeypatch.setattr(storage, "_read_v3_snapshot_file", full_readback)

    def encode(**kwargs):
        assert kwargs["snapshot"] == binding
        assert kwargs["deadline_budget_ms"] == 1000
        return b"modeled-expiry-probe"

    monkeypatch.setattr(native_hook_edge, "_encode_hook_envelope", encode)

    def request(**kwargs):
        seen["native_calls"].append(kwargs)
        if kwargs.get("raw_hook_envelope"):
            assert clock.wall > 103.0
            assert kwargs["deadline_monotonic"] == clock.mono + 1.0
            if fault == "expired_unavailable":
                return None
            if fault == "expired_allow":
                return b'{"decision":"allow"}'
            if fault == "expired_contradictory":
                return b'{"error":"snapshot_expired","result":{"decision":"allow"}}'
            return b'{"error":"snapshot_expired","retryable":false}'
        assert kwargs["deadline_monotonic"] == 202.0
        if fault == "unavailable":
            return None
        if fault == "rejected_binding":
            return b'{"error":"native_command_control_binding_removed","retryable":false}'
        response = {
            "status": "accepted",
            "generation": 3,
            "policy_digest": "a" * 64,
            "idempotent": False,
            "resident_generation": 7,
        }
        if fault == "ack_generation":
            response["generation"] = 2
        elif fault == "ack_digest":
            response["policy_digest"] = "d" * 64
        elif fault == "ack_resident":
            response["resident_generation"] = 0
        return json.dumps(response).encode()

    monkeypatch.setattr(native_resident_client, "native_resident_client_request", request)
    return session, seen


@pytest.mark.parametrize("bound", (True, False))
def test_orchestration_requires_actual_ack_readback_and_explicit_expiry_rejection(tmp_path, monkeypatch, bound):
    session, seen = _modeled_session(tmp_path, monkeypatch, bound=bound)
    result = fixture.expire_acknowledged_authority(session)
    assert result["expired_resident_authority"] is result["policy_prepare_rejected"] is True
    assert result["short_lived_acknowledged"] is result["authenticated_readback"] is True
    assert result["policy_preserved"] is result["control_binding_preserved"] is True
    assert result["control_binding_present"] is bound
    assert result["refresh_suspended"] is True
    assert len(seen["native_calls"]) == 2 and seen["readbacks"] == 3


@pytest.mark.parametrize(
    "fault",
    (
        "unavailable",
        "rejected_binding",
        "ack_generation",
        "ack_digest",
        "ack_resident",
        "missing_binding",
        "binding_generation",
        "binding_policy_digest",
        "binding_runtime_identity",
        "binding_mode",
        "expired_at_readback",
        "compact_bound_stripped",
        "compact_bound_false",
        "compact_bound_spurious",
        "readback_full_missing",
        "readback_controls_stripped",
        "readback_controls_mutated",
        "readback_expiry_changed",
    ),
)
def test_unproven_short_lived_authority_fails_with_bounded_stage_evidence(tmp_path, monkeypatch, fault):
    session, seen = _modeled_session(tmp_path, monkeypatch, fault=fault, bound=fault != "compact_bound_spurious")
    with pytest.raises(FixtureFailureError) as error:
        fixture.expire_acknowledged_authority(session)
    detail = json.loads(json.dumps(assert_privacy_safe(failure_evidence(error.value))))
    assert detail["short_lived_ttl_ms"] == 3000
    assert detail["policy_preserved"] is detail["control_input_preserved"] is True
    assert detail["expiry_stage"] in {"publication", "authenticated_readback"}
    assert len(seen["native_calls"]) == 1
    if fault == "rejected_binding":
        assert detail["native_error"] == "native_command_control_binding_removed"
    if fault.startswith("binding_") or fault == "missing_binding":
        assert detail["authenticated_binding_matches"] is False
    assert str(tmp_path) not in json.dumps(detail)


@pytest.mark.parametrize("fault", ("starting_compact_stripped", "starting_full_stripped", "starting_full_mutated"))
def test_starting_authority_must_match_full_publisher_snapshot_and_real_compact_shape(tmp_path, monkeypatch, fault):
    session, seen = _modeled_session(tmp_path, monkeypatch, fault=fault)
    with pytest.raises(RuntimeError, match="starting authority readback mismatch"):
        fixture.expire_acknowledged_authority(session)
    assert seen["native_calls"] == []
    assert session.daemon._server.hook_worker.policy_snapshot_publisher.closed is False


@pytest.mark.parametrize(
    "fault", ("changed_policy", "retained_expired", "expired_unavailable", "expired_allow", "expired_contradictory")
)
def test_changed_or_unrejected_authority_never_counts_as_expired(tmp_path, monkeypatch, fault):
    session, _seen = _modeled_session(tmp_path, monkeypatch, fault=fault)
    with pytest.raises(RuntimeError):
        fixture.expire_acknowledged_authority(session)

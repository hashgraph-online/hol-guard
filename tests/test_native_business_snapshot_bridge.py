"""Native business content bridge and durable publisher identity regressions."""

from __future__ import annotations

import copy
import json
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_policy_snapshot as api
from codex_plugin_scanner.guard.native_policy_snapshot_business_bridge import validate_business_snapshot_content


def binding(action: str = "block") -> dict[str, object]:
    return {"schema": "guard.native-business-policy.v1", "version": 1, "defaultAction": action, "rules": []}


def build(home: Path, business: dict[str, object]) -> dict[str, object]:
    return api.build_policy_snapshot_v3(
        config={},
        guard_home=home,
        runtime_identity="a" * 64,
        rule_digest="b" * 64,
        verifier_key=b"k" * 32,
        generation=1,
        issued_at_ms=100,
        expires_at_ms=1000,
        business_policy=business,
    )


def test_business_content_requires_native_consumer_without_python_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HOL_GUARD_NATIVE", "off")
    with pytest.raises(api.NativePolicySnapshotError, match="native_business_policy_consumer_unavailable"):
        build(tmp_path, binding())


def test_native_consumer_without_retained_floor_refuses_before_constructor_receives_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_plugin_scanner.guard import native_runtime

    old = SimpleNamespace(
        available=True,
        compatible=True,
        identity=SimpleNamespace(path=tmp_path / "unused"),
        capabilities=SimpleNamespace(features=("native-policy-snapshot-build-v1", "native-policy-snapshot-inspect-v1")),
    )
    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda **kwargs: old)

    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("An older consumer must not receive a constructor request or verifier key")

    monkeypatch.setattr(native_runtime, "_run_native_process", forbidden)
    with pytest.raises(api.NativePolicySnapshotError, match="native_business_policy_consumer_unavailable"):
        build(tmp_path, binding())


def test_constructor_failure_drops_owned_key_references_without_zeroization_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_plugin_scanner.guard import native_policy_snapshot_business_bridge as bridge

    observed = []

    def fail(request: dict[str, object], **kwargs: object) -> dict[str, object]:
        observed.extend((request, request["verifier_key"]))
        raise api.NativePolicySnapshotError("synthetic_constructor_failure")

    monkeypatch.setattr(bridge, "build_native_business_snapshot", fail)
    with pytest.raises(api.NativePolicySnapshotError, match="synthetic_constructor_failure"):
        build(tmp_path, binding())
    assert "verifier_key" not in observed[0]
    assert observed[1] == []


def test_refused_business_declaration_does_not_provision_verifier(
    tmp_path: Path,
    native_hook_force: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_plugin_scanner.guard import native_policy_snapshot_generation as generation

    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("A refused business declaration must not provision a resident key")

    monkeypatch.setattr(generation, "provision_native_policy_verifier_key", forbidden)
    inputs = dict(
        config={}, guard_home=tmp_path, runtime_identity="a" * 64, rule_digest="b" * 64, policy_integrity_key=b"m" * 32
    )
    with pytest.raises(api.NativePolicySnapshotError, match="content_invalid"):
        api.native_policy_snapshot_v3(**inputs, business_policy={**binding(), "private_canary": True})
    monkeypatch.setenv("HOL_GUARD_NATIVE", "off")
    with pytest.raises(api.NativePolicySnapshotError, match="consumer_unavailable"):
        api.native_policy_snapshot_v3(**inputs, business_policy=binding())


def test_expired_publication_deadline_refuses_before_native_probe_or_key_provision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_plugin_scanner.guard import native_policy_snapshot_generation as generation
    from codex_plugin_scanner.guard import native_runtime

    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("Expired publication must not probe, spawn or provision")

    monkeypatch.setattr(native_runtime, "native_runtime_status", forbidden)
    monkeypatch.setattr(generation, "provision_native_policy_verifier_key", forbidden)
    with pytest.raises(api.NativePolicySnapshotError, match="deadline_exceeded"):
        api.native_policy_snapshot_v3(
            config={},
            guard_home=tmp_path,
            runtime_identity="a" * 64,
            rule_digest="b" * 64,
            policy_integrity_key=b"m" * 32,
            business_policy=binding(),
            deadline_monotonic=time.monotonic() - 1,
        )


def test_inspection_cache_is_content_only_and_subprocess_uses_remaining_deadline(
    tmp_path: Path,
    native_hook_force: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_plugin_scanner.guard import native_policy_snapshot_business_bridge as bridge
    from codex_plugin_scanner.guard import native_runtime

    snapshot = build(tmp_path, binding())
    snapshot["generation"] = 7
    observed = []
    real = native_runtime._run_native_process

    def recording(*args: object, **kwargs: object) -> str | None:
        observed.append(kwargs["timeout_seconds"])
        return real(*args, **kwargs)

    monkeypatch.setattr(native_runtime, "_run_native_process", recording)
    token = bridge.begin_business_deadline(time.monotonic() + 0.75)
    try:
        validate_business_snapshot_content(snapshot)
        validate_business_snapshot_content(snapshot)
    finally:
        bridge.end_business_deadline(token)
    assert len(observed) == 1 and 0 < observed[0] <= 0.75
    monkeypatch.setenv("HOL_GUARD_NATIVE", "off")
    with pytest.raises(api.NativePolicySnapshotError, match="consumer_unavailable"):
        validate_business_snapshot_content(snapshot)


def test_native_business_builder_preserves_binding_and_cache_authentication(
    tmp_path: Path,
    native_hook_force: Path,
) -> None:
    home = tmp_path / "guard"
    home.mkdir(mode=0o700)
    snapshot = build(home, binding())
    assert snapshot["business_policy"] == binding()
    api._write_v3_snapshot_cache(home, snapshot)
    cached = api._read_v3_snapshot_cache(home, verifier_key=b"k" * 32)
    assert cached is not None and cached[0] == snapshot
    with pytest.raises(api.NativePolicySnapshotError, match="integrity_invalid"):
        api._read_v3_snapshot_cache(home, verifier_key=b"z" * 32)


def test_native_business_content_success_does_not_authenticate_forged_mac(
    tmp_path: Path,
    native_hook_force: Path,
) -> None:
    home = tmp_path / "guard"
    home.mkdir(mode=0o700)
    snapshot = build(home, binding())
    snapshot["integrity"]["mac"] = "0" * 64
    validate_business_snapshot_content(snapshot)
    api._write_v3_snapshot_cache(home, snapshot)
    with pytest.raises(api.NativePolicySnapshotError, match="integrity_invalid"):
        api._read_v3_snapshot_cache(home, verifier_key=b"k" * 32)


def test_full_source_identity_and_fixed_expiry_survive_python_bridge(
    tmp_path: Path,
    native_hook_force: Path,
) -> None:
    business = {
        **binding(),
        "sourceDocumentDigest": "a" * 64,
        "rules": [
            {
                "id": "rule.send",
                "action": "review",
                "match": {
                    "schema": "guard.business-policy-match.v1",
                    "version": 1,
                    "services": ["google_gmail"],
                    "operations": ["mail_send"],
                },
                "expiresAt": "2026-07-16T12:00:00.123456789Z",
            }
        ],
    }
    inputs = dict(
        config={}, guard_home=tmp_path, runtime_identity="a" * 64, rule_digest="b" * 64, policy_integrity_key=b"m" * 32
    )
    first = api.native_policy_snapshot_v3(**inputs, business_policy=business)
    assert first["business_policy"] == business
    validate_business_snapshot_content(first)
    changed = copy.deepcopy(business)
    changed["sourceDocumentDigest"] = "b" * 64
    updated = api.native_policy_snapshot_v3(**inputs, business_policy=changed)
    assert updated["generation"] == first["generation"] + 1
    assert updated["policy_digest"] != first["policy_digest"]
    assert updated["integrity"]["mac"] != first["integrity"]["mac"]
    tampered = copy.deepcopy(first)
    tampered["business_policy"]["sourceDocumentDigest"] = "b" * 64
    with pytest.raises(api.NativePolicySnapshotError, match="digest_mismatch"):
        validate_business_snapshot_content(tampered)


def test_changed_business_content_and_each_claimed_digest_are_refused(
    tmp_path: Path,
    native_hook_force: Path,
) -> None:
    original = build(tmp_path, binding())
    for field in ("config_digest", "policy_digest", "business_policy"):
        tampered = copy.deepcopy(original)
        tampered[field] = binding("allow") if field == "business_policy" else "f" * 64
        with pytest.raises(api.NativePolicySnapshotError, match="digest_mismatch"):
            validate_business_snapshot_content(tampered)
    for value in (None, {**binding(), "private_canary": "not-reflected"}):
        tampered = {**original, "business_policy": value}
        with pytest.raises(api.NativePolicySnapshotError, match="content_invalid"):
            validate_business_snapshot_content(tampered)


def test_business_binding_rotates_generation_and_reuses_exact_cache(
    tmp_path: Path,
    native_hook_force: Path,
) -> None:
    home = tmp_path / "guard"
    home.mkdir(mode=0o700)
    inputs = dict(
        config={}, guard_home=home, runtime_identity="a" * 64, rule_digest="b" * 64, policy_integrity_key=b"m" * 32
    )
    first = api.native_policy_snapshot_v3(**inputs, business_policy=binding())
    again = api.native_policy_snapshot_v3(**inputs, business_policy=binding())
    changed = api.native_policy_snapshot_v3(**inputs, business_policy=binding("allow"))
    assert first == again
    assert changed["generation"] == first["generation"] + 1
    assert changed["policy_digest"] != first["policy_digest"]
    renewed = api.native_policy_snapshot_v3(
        **inputs,
        business_policy=binding("allow"),
        renew_after_generation=changed["generation"],
    )
    assert renewed["generation"] > changed["generation"]
    assert renewed["policy_digest"] == changed["policy_digest"]


@pytest.mark.parametrize("clock_offset", [-1_000_000.0, 1_000_000.0])
def test_business_transport_receives_real_native_ack_without_provider_dispatch(
    tmp_path: Path,
    native_hook_force: Path,
    monkeypatch: pytest.MonkeyPatch,
    clock_offset: float,
) -> None:
    from codex_plugin_scanner.guard.native_command_control_binding import read_native_command_control_binding
    from codex_plugin_scanner.guard.native_policy_snapshot_publisher_transport import _publish_snapshot_v3
    from codex_plugin_scanner.guard.native_resident_client import close_native_residents, native_resident_client_request
    from codex_plugin_scanner.guard.native_runtime import native_runtime_status
    from codex_plugin_scanner.guard.store import GuardStore
    from tests.test_native_business_document_compile import document
    from tests.test_native_business_source_store import _grant, _install

    # Keep command authority and snapshot signing on the same synthetic master;
    # this test must never ask a real credential store for integrity material.
    monkeypatch.setattr(GuardStore, "_policy_integrity_secret_material", lambda self, **kwargs: (b"m" * 32, "fixture"))
    home = tmp_path / "guard"
    status = native_runtime_status()
    assert status.compatible and status.identity is not None and status.capabilities is not None
    store = GuardStore(home)
    candidate = document()
    installed = _install(store, candidate, _grant(store, candidate))
    business = json.loads(installed.source.binding_bytes)
    controls, _ = read_native_command_control_binding(store)
    publisher = SimpleNamespace(
        guard_home=home,
        _snapshot=None,
        _wall_clock=time.time,
        _monotonic_clock=lambda: time.monotonic() + clock_offset,
    )

    def client(**kwargs: object) -> bytes | None:
        assert 0 < kwargs["deadline_monotonic"] - time.monotonic() <= 9.0
        return native_resident_client_request(**kwargs)

    try:
        snapshot, resident_generation = _publish_snapshot_v3(
            publisher=publisher,
            identity=status.identity,
            capabilities=status.capabilities,
            config={},
            command_extensions=controls,
            master_key=b"m" * 32,
            client=client,
            renew_after_generation=None,
            business_policy=business,
        )
        assert snapshot["business_policy"] == business
        assert resident_generation >= snapshot["generation"]
        cached = api._read_v3_snapshot_cache(home, verifier_key=api.derive_native_policy_verifier_key(b"m" * 32))
        assert cached is not None and cached[0] == snapshot
        # Verify the native-written combined record through both Python
        # readers; a copied MAC formula alone is not cross-runtime evidence.
        from codex_plugin_scanner.guard.native_command_control_authority_store import read_native_control_floor_for_home
        from codex_plugin_scanner.guard.native_policy_snapshot_constants import (
            _RUST_SNAPSHOT_STATE_NAME,
            NATIVE_RUNTIME_STATE_DIRECTORY,
            POLICY_SNAPSHOT_AUTHORITY_MAX_BYTES,
        )

        verifier = api.derive_native_policy_verifier_key(b"m" * 32)
        control_floor = read_native_control_floor_for_home(home, verifier)
        assert (control_floor is not None) == (controls["health"] == "protected")
        retained = api._read_v3_snapshot_file(
            home / NATIVE_RUNTIME_STATE_DIRECTORY / _RUST_SNAPSHOT_STATE_NAME,
            verifier_key=verifier,
            maximum_bytes=POLICY_SNAPSHOT_AUTHORITY_MAX_BYTES,
        )
        assert retained is not None and retained[0] == snapshot
        assert len(json.loads(retained[1])["business_policy_floor"]) == 64
    finally:
        assert close_native_residents(home, deadline_monotonic=time.monotonic() + 5.0)


def test_business_cache_requires_removal_authority_and_cannot_be_skipped_for_older_consumer(
    tmp_path: Path,
    native_hook_force: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "guard"
    home.mkdir(mode=0o700)
    inputs = dict(
        config={}, guard_home=home, runtime_identity="a" * 64, rule_digest="b" * 64, policy_integrity_key=b"m" * 32
    )
    first = api.native_policy_snapshot_v3(**inputs, business_policy=binding())
    with pytest.raises(api.NativePolicySnapshotError, match="removal_requires_authority"):
        api.native_policy_snapshot_v3(**inputs)
    monkeypatch.setenv("HOL_GUARD_NATIVE", "off")
    with pytest.raises(api.NativePolicySnapshotError, match="consumer_unavailable"):
        api.native_policy_snapshot_v3(**inputs)
    monkeypatch.setenv("HOL_GUARD_NATIVE", "force")
    preserved = api._read_v3_snapshot_cache(home, verifier_key=api.derive_native_policy_verifier_key(b"m" * 32))
    assert preserved is not None and preserved[0] == first

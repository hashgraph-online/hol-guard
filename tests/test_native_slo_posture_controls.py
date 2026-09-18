"""Source control tests with declared transport doubles and real config/locks."""

from __future__ import annotations

import time
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard.config import load_guard_config
from codex_plugin_scanner.guard.native_policy_snapshot import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.store import GuardStore
from scripts import native_slo_posture_controls as module
from scripts.native_slo_posture_controls import PostureControls
from scripts.native_slo_posture_witness import binding_key
from scripts.native_slo_workloads import configuration_text
from tests.native_policy_snapshot_test_fixtures import _ack, _status


def _session(tmp_path: Path, publisher: Any, store: Any = None) -> Any:
    return SimpleNamespace(
        root=tmp_path,
        guard_home=tmp_path / "guard",
        workspace=tmp_path / "initial",
        store=store,
        daemon=SimpleNamespace(
            _server=SimpleNamespace(hook_worker=SimpleNamespace(policy_snapshot_publisher=publisher))
        ),
    )


def _snapshot() -> dict[str, Any]:
    return {
        "generation": 2,
        "policy_digest": "a" * 64,
        "runtime_identity": "b" * 64,
        "mode": "enforce",
        "issued_at_ms": 1000,
        "expires_at_ms": 4000,
        "effective_policy": {"sandbox_analysis": "strict"},
        "command_extensions": {"revision": 2},
    }


@pytest.mark.parametrize(
    "fault", ("", "compact_mode", "full_control", "prepared_generation", "old_generation", "late", "not_strict")
)
def test_ack_requires_full_authenticated_readback_with_one_original_deadline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    clock = SimpleNamespace(now=100.0)
    deadlines = []
    snapshot = _snapshot()
    compact = {key: snapshot[key] for key in ("generation", "policy_digest", "runtime_identity", "mode")}
    compact["command_extensions_bound"] = True
    accepted = deepcopy(snapshot)
    prepared = dict(compact)
    if fault == "compact_mode":
        compact["mode"] = "observe"
    if fault == "full_control":
        accepted["command_extensions"] = {"revision": 1}
    if fault == "prepared_generation":
        prepared["generation"] = 3
    if fault == "not_strict":
        snapshot["effective_policy"]["sandbox_analysis"] = "off"
        accepted["effective_policy"]["sandbox_analysis"] = "off"
    publisher = SimpleNamespace(current_snapshot=lambda: snapshot)
    session = _session(tmp_path, publisher)

    def prepare(_workspace, *, deadline):
        deadlines.append(deadline)
        clock.now += 0.5 if fault == "late" else 0.1
        return prepared

    session.daemon._server.hook_worker.prepare_workspace_policy = prepare
    monkeypatch.setattr(
        module,
        "time",
        SimpleNamespace(monotonic=lambda: clock.now, sleep=lambda value: setattr(clock, "now", clock.now + value)),
    )
    monkeypatch.setattr(module, "_authenticated_readback", lambda _store: (compact, accepted))
    controls = PostureControls(session)
    if fault:
        with pytest.raises(RuntimeError, match="acknowledgment deadline"):
            controls.ack(previous=2 if fault == "old_generation" else 1, strict=True)
        assert not controls.known
    else:
        assert controls.ack(previous=1, strict=True) == snapshot
        assert controls.known == {binding_key(snapshot)}
    assert deadlines and set(deadlines) == {100.4}


def _publisher(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    home = tmp_path / "guard"
    home.mkdir(mode=0o700)
    (home / "config.toml").write_text(configuration_text("normal"))
    store = GuardStore(home)
    monkeypatch.setattr(store, "_policy_integrity_secret_material", lambda *, create: (b"p" * 32, "source-test-master"))
    calls = []

    def transport(**kwargs):
        # The actual native transport is intentionally absent in this source
        # test. Never use this fixture as installed qualification evidence.
        calls.append(kwargs)
        return _ack(kwargs["payload"])

    publisher = NativePolicySnapshotPublisher(store=store, status_provider=_status, client_request=transport)
    session = _session(tmp_path, publisher, store)
    session.workspace.mkdir(mode=0o700)
    return publisher, session, calls


def test_first_workspace_uses_real_file_and_registration_barrier_without_allowing_workspace_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    publisher, session, _ = _publisher(tmp_path, monkeypatch)
    controls = PostureControls(session)
    publisher._publish_once()
    before = publisher.current_snapshot()
    assert before is not None
    probes = []

    def probe(scope, required):
        probes.append((scope, required))
        if scope == "strict":
            assert publisher.register_workspace(controls.strict_workspace)
        assert publisher.current_snapshot_binding() is None

    def acknowledged(*, previous, strict):
        assert strict and previous == before["generation"]
        publisher._publish_once()
        result = publisher.current_snapshot()
        assert result is not None
        return result

    monkeypatch.setattr(controls, "ack", acknowledged)
    try:
        result = controls.apply("first_strict_workspace", before, probe)
        assert result is not None and result["mode"] == "enforce"
        assert result["effective_policy"]["sandbox_analysis"] == "strict"
        assert result["policy_digest"] != before["policy_digest"]
        assert probes == [("strict", "unavailable"), ("initial", "unavailable")]
        assert controls.progress["previously_unregistered"] is True
        assert controls.progress["first_use_withdrew_ack"] is True
        config = load_guard_config(session.guard_home, workspace=controls.strict_workspace)
        assert config.mode == "enforce" and config.sandbox_analysis == "strict"
    finally:
        publisher.close()


def test_real_generation_lock_makes_public_mutation_fail_before_transport(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    publisher, session, calls = _publisher(tmp_path, monkeypatch)
    publisher.start()
    assert publisher.wait_until_ready(time.monotonic() + 2.0)
    before = publisher.current_snapshot()
    assert before is not None
    initial_calls = len(calls)
    controls = PostureControls(session)
    witnessed = []

    def probe(scope, required):
        assert scope == "initial" and required == "unavailable"
        assert publisher.last_error == "native_policy_snapshot_generation_lock_timeout"
        assert publisher.current_snapshot_binding() is None
        # The physical lock stopped generation publication before the source
        # transport double; no fake rejected ACK drove this outcome.
        assert len(calls) == initial_calls
        witnessed.append(True)

    def acknowledged(*, previous):
        from codex_plugin_scanner.guard.native_policy_snapshot_storage import _v3_generation_lock

        assert previous == before["generation"]
        # This test verifies the physical fault and release, not a local wall
        # clock recovery SLO. The installed continuation still calls real ack()
        # with 400 ms; its fixed deadline has a separate deterministic test.
        # This deliberately incomplete source result cannot be native authority.
        with _v3_generation_lock(session.guard_home, deadline_monotonic=time.monotonic() + 0.4):
            return {"mode": "observe", "generation": previous + 1}

    monkeypatch.setattr(controls, "ack", acknowledged)
    started = time.monotonic()
    try:
        result = controls.apply("failed_publication", before, probe)
        assert result is not None and result["mode"] == "observe"
        assert witnessed == [True]
        assert controls.progress["publication_failed_at_generation_lock"] is True
        assert controls.progress["mutation_withdrew_ack"] is True
        assert load_guard_config(session.guard_home).mode == "observe"
        assert time.monotonic() - started >= 2.0
    finally:
        publisher.close()


@pytest.mark.parametrize(
    "missing",
    (
        "expired_resident_authority",
        "short_lived_acknowledged",
        "starting_authority_authenticated",
        "authenticated_readback",
        "policy_preserved",
        "control_binding_preserved",
        "policy_prepare_rejected",
        "refresh_suspended",
    ),
)
def test_expiry_cannot_pass_from_closed_publisher_or_partial_fault_proof(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, missing: str
) -> None:
    proof = {
        key: True
        for key in (
            "expired_resident_authority",
            "short_lived_acknowledged",
            "starting_authority_authenticated",
            "authenticated_readback",
            "policy_preserved",
            "control_binding_preserved",
            "policy_prepare_rejected",
            "refresh_suspended",
        )
    }
    proof[missing] = False
    controls = PostureControls(_session(tmp_path, SimpleNamespace()))
    monkeypatch.setattr(module, "expire_acknowledged_authority", lambda _session: proof)
    probes = []
    with pytest.raises(RuntimeError, match="proof incomplete"):
        controls.apply("expiry", _snapshot(), lambda *_args: probes.append(True))
    assert not probes


def test_failed_stop_cannot_claim_recovery_or_request_a_new_ack(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session = _session(tmp_path, SimpleNamespace())
    session.stop_resident = lambda: False
    controls = PostureControls(session)
    controls.mode = "observe"
    monkeypatch.setattr(controls, "ack", lambda **_kwargs: pytest.fail("failed containment cannot prepare recovery"))
    with pytest.raises(RuntimeError, match="containment failed"):
        controls.apply("watch_restart", {**_snapshot(), "mode": "observe"}, lambda *_args: None)
    assert controls.progress["contained"] is False
    assert controls.progress["python_process_restarted"] is False


def test_wrong_starting_mode_cannot_run_a_mode_transition(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    controls = PostureControls(_session(tmp_path, SimpleNamespace()))
    monkeypatch.setattr(
        controls, "_mode_mutation", lambda _mode: pytest.fail("invalid transition cannot mutate policy")
    )
    with pytest.raises(RuntimeError, match="starting mode mismatch"):
        controls.apply("watch_to_enforce", _snapshot(), lambda *_args: None)

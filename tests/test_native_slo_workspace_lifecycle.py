"""Lifecycle collector contracts; source controls are not installed timings."""

from __future__ import annotations

import copy
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import native_slo_workspace_lifecycle as lifecycle
from scripts import native_slo_workspace_lifecycle_service as service
from scripts.native_slo_failure import failure_evidence
from scripts.native_slo_session import AdapterSession


def _authority(tmp_path, monkeypatch):
    snapshot = {
        "generation": 7,
        "policy_digest": "a" * 64,
        "runtime_identity": "b" * 64,
        "mode": "enforce",
        "effective_policy": {"default_action": "allow", "subprocess_action": "allow", "sandbox_analysis": "strict"},
    }
    prepared = {key: snapshot[key] for key in ("generation", "policy_digest", "runtime_identity")}
    calls = []

    def prepare(workspace, *, deadline):
        calls.append((workspace, deadline))
        return prepared

    publisher = SimpleNamespace(current_snapshot=lambda: snapshot)
    worker = SimpleNamespace(prepare_workspace_policy=prepare, policy_snapshot_publisher=publisher)
    session = SimpleNamespace(store=object(), daemon=SimpleNamespace(_server=SimpleNamespace(hook_worker=worker)))
    monkeypatch.setattr(lifecycle, "_authenticated_readback", lambda _: (prepared, snapshot))
    monkeypatch.setattr(lifecycle, "_readback_matches", lambda *_: True)
    clock = [10.0]
    monkeypatch.setattr(lifecycle.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(lifecycle.time, "sleep", lambda _: clock.__setitem__(0, 10.5))
    return session, snapshot, calls


def test_ack_uses_secondary_scope_and_unchanged_accepted_change_deadline(tmp_path, monkeypatch):
    session, snapshot, calls = _authority(tmp_path, monkeypatch)
    secondary = tmp_path / "secondary"
    observed = lifecycle.await_ack(session, minimum=7, action="allow", strict=True, workspace=secondary, deadline=10.4)
    assert observed is snapshot
    assert calls == [(secondary, 10.4)]


@pytest.mark.parametrize(
    "field,value",
    [
        ("generation", 6),
        ("generation", True),
        ("runtime_identity", "bad"),
        ("mode", "observe"),
        ("effective_policy", {"default_action": "allow", "subprocess_action": "allow", "sandbox_analysis": "off"}),
    ],
)
def test_old_malformed_or_weaker_authority_cannot_pass_deadline(tmp_path, monkeypatch, field, value):
    session, snapshot, calls = _authority(tmp_path, monkeypatch)
    snapshot[field] = value
    with pytest.raises(RuntimeError, match="deadline"):
        lifecycle.await_ack(session, minimum=7, action="allow", strict=True, workspace=tmp_path, deadline=10.4)
    assert calls and all(deadline == 10.4 for _, deadline in calls)


def test_plain_matching_dictionary_cannot_replace_authenticated_readback(tmp_path, monkeypatch):
    session, _, _ = _authority(tmp_path, monkeypatch)
    monkeypatch.setattr(lifecycle, "_readback_matches", lambda *_: False)
    with pytest.raises(RuntimeError, match="deadline"):
        lifecycle.await_ack(session, minimum=7, action="allow", strict=True, workspace=tmp_path, deadline=10.4)


def test_late_matching_publication_chain_cannot_extend_original_deadline(monkeypatch):
    from scripts import native_slo_workspace_trace as trace

    monkeypatch.setattr(lifecycle.time, "monotonic", lambda: 10.4)
    monkeypatch.setattr(trace, "phase_chain", lambda *args, **kwargs: {"matched": True})
    # _chain holds the live imported callable; replace the collector dependency.
    monkeypatch.setattr(lifecycle, "phase_chain", trace.phase_chain)
    observer = SimpleNamespace(rows=lambda _: [], started=9.0)
    with pytest.raises(RuntimeError, match="deadline"):
        lifecycle._chain(observer, {}, 10.0, 10.4)


@pytest.mark.parametrize("count", [1, 10, 100])
def test_two_real_python_service_instances_preserve_owned_home_and_stricter_scope(count, monkeypatch):
    # The native transport is disabled by conftest. This verifies actual Python
    # service ownership/containment, not native verdicts or restart performance.
    session = AdapterSession(Path("unused-native-runtime"))
    workspaces = [session.workspace]
    for index in range(1, count):
        path = session.root / f"workspace-{index}"
        path.mkdir(mode=0o700)
        workspaces.append(path)
    strict = workspaces[-1] / ".hol-guard.toml"
    strict.write_text('sandbox_analysis = "strict"\n')
    original, old_store, temporary = session.daemon, session.store, session.temporary
    stops = []
    monkeypatch.setattr(session, "stop_resident", lambda: stops.append("resident-contained") or True)
    session.daemon.start()
    try:
        proof = service.replace_service(session, tuple(workspaces))
        assert proof["service_instances"] == 2 and proof["old_service_contained"]
        assert proof["python_process_restarted"] is False
        assert stops == ["resident-contained"]
        assert session.daemon is not original and session.store is not old_store
        assert session.temporary is temporary and session.root.is_dir()
        assert original._finish_service_completed and original._owner_lock is None
        publisher = session.daemon._server.hook_worker.policy_snapshot_publisher
        service.register_scopes(publisher, tuple(workspaces))
        assert publisher._workspace_paths == set(workspaces)
        assert strict.read_text() == 'sandbox_analysis = "strict"\n'
        session.daemon.start()
        assert session.daemon._owner_lock is not None
    finally:
        session.daemon.stop()
        original.stop()
        session.temporary.cleanup()


@pytest.mark.parametrize("failure", ["publisher", "resident", "service", "owner", "requests"])
def test_replacement_refuses_before_new_constructor_when_prior_containment_is_incomplete(
    tmp_path, monkeypatch, failure
):
    home, workspace = tmp_path / ".hol-guard", tmp_path / "workspace"
    home.mkdir()
    workspace.mkdir()
    calls = []
    publisher = SimpleNamespace(
        closed=failure != "publisher", _thread=None, close=lambda: calls.append("publisher-close")
    )
    previous = SimpleNamespace(
        _server=SimpleNamespace(
            hook_worker=SimpleNamespace(policy_snapshot_publisher=publisher),
            runtime_session_id="old",
            active_hook_requests=int(failure == "requests"),
        ),
        _finish_service_completed=failure != "service",
        _thread=None,
        _owner_lock=object() if failure == "owner" else None,
        stop=lambda: calls.append("service-stop"),
    )
    session = SimpleNamespace(
        root=tmp_path,
        guard_home=home,
        daemon=previous,
        _connection=None,
        stop_resident=lambda: calls.append("resident-stop") or failure != "resident",
    )
    from codex_plugin_scanner.guard import store as store_module

    monkeypatch.setattr(store_module, "GuardStore", lambda *_: pytest.fail("uncontained service replaced"))
    with pytest.raises(RuntimeError, match=r"stop|containment"):
        service.replace_service(session, (workspace,))
    assert session.daemon is previous
    if failure == "publisher":
        assert calls == ["publisher-close"]


def test_existing_scope_cannot_be_claimed_as_new_registration(tmp_path):
    publisher = SimpleNamespace(register_workspace=lambda _: False)
    with pytest.raises(RuntimeError, match="every scope"):
        service.register_scopes(publisher, (tmp_path,))


def test_missing_compiled_scope_is_separate_from_matching_authority():
    row = {
        "kind": "compile",
        "publication": 1,
        "succeeded": True,
        "registered_workspaces": 10,
        "cache_entries": 10,
        "unregistered_loads": 0,
        "config_load_failures": 0,
    }
    observer = SimpleNamespace(rows=lambda _: [copy.copy(row)])
    checks = lifecycle._scope_checks(observer, {"publication": 1}, 10)
    assert checks["all_registered_workspaces_retained"]
    assert not checks["compiled_cache_complete"]


def test_original_cell_failure_survives_publisher_cleanup_failure(tmp_path, monkeypatch):
    home, workspace = tmp_path / ".hol-guard", tmp_path / "workspace"
    home.mkdir()
    workspace.mkdir()
    first, cleanup = ValueError("original_readback_failure"), OSError("original_close_failure")

    def fail_close():
        raise cleanup

    def fail_ack(*args, **kwargs):
        raise first

    publisher = SimpleNamespace(close=fail_close, closed=False, _thread=None)
    worker = SimpleNamespace(policy_snapshot_publisher=publisher)
    session = SimpleNamespace(
        root=tmp_path, guard_home=home, daemon=SimpleNamespace(_server=SimpleNamespace(hook_worker=worker))
    )
    monkeypatch.setattr(lifecycle, "await_ack", fail_ack)
    result = lifecycle.run_lifecycle_cell(session, (workspace,), "lost_metadata_hint")
    assert result["passed"] is False
    assert result["failure"] == failure_evidence(first)
    assert result["cleanup_failures"] == [{"stage": "publisher_close", "failure": failure_evidence(cleanup)}]
    assert result["publisher_contained"] is False

"""Deterministic scheduling control, not an installed latency measurement."""

from __future__ import annotations

import time

import pytest

from codex_plugin_scanner.guard.native_policy_snapshot_publisher import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.store import GuardStore
from scripts.native_slo_contract import MAX_READINESS_P95_MS
from scripts.native_slo_workspace_lifecycle_faults import LostMetadataHints
from tests.native_policy_snapshot_test_fixtures import _ack, _status


class _EndObservation(BaseException):
    pass


class _ScheduledEvent:
    """Advance only the existing requested waits, with normal set semantics."""

    def __init__(self, clock, end):
        self.clock, self.end = clock, end
        self.signalled = False
        self.waits = []

    def set(self):
        self.signalled = True

    def clear(self):
        self.signalled = False

    def wait(self, timeout):
        if self.signalled:
            return True
        self.waits.append(timeout)
        if self.clock[0] + timeout > self.end:
            raise _EndObservation
        self.clock[0] += timeout
        return False


def test_real_stricter_content_is_reconciled_within_readiness_window_when_all_metadata_hints_are_lost(
    tmp_path, monkeypatch
):
    home, workspace = tmp_path / "home", tmp_path / "workspace"
    workspace.mkdir()
    store = GuardStore(home)
    monkeypatch.setattr(store, "_policy_integrity_secret_material", lambda *, create: (b"k" * 32, "test"))
    clock = [time.monotonic()]
    publisher = NativePolicySnapshotPublisher(
        store=store,
        status_provider=_status,
        client_request=lambda **kwargs: _ack(kwargs["payload"]),
        monotonic_clock=lambda: clock[0],
    )
    publisher.register_workspace(workspace)
    publisher._publish_once()
    before = publisher.current_snapshot()
    assert before is not None and before["effective_policy"]["sandbox_analysis"] != "strict"
    accepted = clock[0]
    schedule = _ScheduledEvent(clock, accepted + MAX_READINESS_P95_MS / 1000)
    publisher._publish_event = schedule
    try:
        with LostMetadataHints(publisher) as fault:
            (workspace / ".hol-guard.toml").write_text('sandbox_analysis = "strict"\n')
            with pytest.raises(_EndObservation):
                publisher._run()
            after = publisher.current_snapshot()
            assert fault.report()["actual_changed_hint_observed"]
            assert after is not None and after["effective_policy"]["sandbox_analysis"] == "strict"
            assert after["generation"] > before["generation"]
            assert publisher._workspace_paths == {workspace}
            assert schedule.waits and all(wait == 0.25 for wait in schedule.waits)
    finally:
        publisher.close()


def _ready(tmp_path, monkeypatch):
    store = GuardStore(tmp_path / "home")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setattr(store, "_policy_integrity_secret_material", lambda *, create: (b"k" * 32, "test"))
    publisher = NativePolicySnapshotPublisher(
        store=store, status_provider=_status, client_request=lambda **kwargs: _ack(kwargs["payload"])
    )
    publisher.register_workspace(workspace)
    publisher._publish_once()
    assert publisher.is_ready()
    return publisher, workspace


def test_unchanged_fast_freshness_never_compiles_or_reverifies_command_authority(tmp_path, monkeypatch):
    from codex_plugin_scanner.guard import config
    from codex_plugin_scanner.guard import native_policy_snapshot_publisher_inputs as inputs

    publisher, _ = _ready(tmp_path, monkeypatch)

    def unexpected(*args, **kwargs):
        pytest.fail("unchanged content freshness performed compilation or control verification")

    monkeypatch.setattr(config, "load_guard_config", unexpected)
    monkeypatch.setattr(inputs, "read_native_command_control_binding", unexpected)
    monkeypatch.setattr(publisher, "_policy_input_changed", unexpected)
    monkeypatch.setattr(publisher, "_compiled_effective_policy", unexpected)
    before = publisher.current_snapshot_binding()
    try:
        assert publisher._configuration_input_changed() is False
        assert publisher.current_snapshot_binding() == before
    finally:
        publisher.close()


def test_rejected_real_capture_withdraws_previous_ack_before_publication(tmp_path, monkeypatch):
    publisher, workspace = _ready(tmp_path, monkeypatch)
    (workspace / ".hol-guard.toml").mkdir()
    try:
        assert publisher._configuration_input_changed() is True
        assert publisher.is_ready() is False
        assert publisher.current_snapshot_binding() is None
        assert publisher._workspace_paths == {workspace}
    finally:
        publisher.close()


def test_unchanged_existing_wakeups_keep_full_control_reconciliation_at_one_second(tmp_path, monkeypatch):
    publisher, _ = _ready(tmp_path, monkeypatch)
    clock = [time.monotonic()]
    # This scheduling control starts before the unchanged observation window;
    # it does not change a collector mutation clock or reset any request deadline.
    publisher._monotonic_clock = lambda: clock[0]
    publisher._reconcile_due_monotonic = clock[0] + 1.0
    schedule = _ScheduledEvent(clock, clock[0] + 1.1)
    publisher._publish_event = schedule
    calls = []
    original = publisher._policy_input_changed

    def full(*args, **kwargs):
        calls.append((clock[0], args, kwargs))
        return original(*args, **kwargs)

    monkeypatch.setattr(publisher, "_policy_input_changed", full)
    before = publisher.current_snapshot_binding()
    try:
        with pytest.raises(_EndObservation):
            publisher._run()
        # DB WAL/SHM metadata changes also enter this dispatcher; those are
        # cheap marker hints, not the independently scheduled full check.
        assert sum(not args and not kwargs for _, args, kwargs in calls) == 1
        assert schedule.waits and all(wait == 0.25 for wait in schedule.waits)
        assert publisher.current_snapshot_binding() == before
    finally:
        publisher.close()

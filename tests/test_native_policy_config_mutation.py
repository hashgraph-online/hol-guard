"""Supported config writers serialize with the native ACK observation."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_policy_bundle_ack import commit_native_policy_bundle_acknowledgement
from tests.test_native_policy_bundle_ack import accepted as accepted


@pytest.mark.parametrize("writer", ["settings", "channel", "reset"])
def test_supported_config_writer_cannot_cross_ack_commit_boundary(accepted, monkeypatch, writer):
    import threading

    from codex_plugin_scanner.guard import native_policy_bundle_ack as ack
    from codex_plugin_scanner.guard.config import (
        reset_guard_settings,
        update_guard_settings,
        update_guard_update_channel,
    )

    store, publisher, token, _, _ = accepted
    attempted, finished = threading.Event(), threading.Event()
    write = ack._write_payload
    worker = None

    def change():
        attempted.set()
        if writer == "settings":
            update_guard_settings(store.guard_home, {"mode": "observe"}, skip_approval_gate=True)
        elif writer == "channel":
            update_guard_update_channel(store.guard_home, "alpha")
        else:
            reset_guard_settings(store.guard_home)
        finished.set()

    def interpose(*args):
        nonlocal worker
        if worker is None:
            worker = threading.Thread(target=change)
            worker.start()
            assert attempted.wait(2)
            assert not finished.wait(0.05)
        write(*args)

    monkeypatch.setattr(ack, "_write_payload", interpose)
    result = commit_native_policy_bundle_acknowledgement(publisher, token)
    assert result is not None and result["status"] == "applied"
    assert worker is not None
    worker.join(3)
    assert not worker.is_alive() and finished.is_set()
    # The serialized later config change invalidates current readiness without
    # rewriting the truthful preceding application observation.
    assert not publisher.is_ready()
    assert store.get_sync_payload("policy_bundle_ack") == result


def test_disjoint_supported_config_updates_parse_under_shared_lock(accepted, monkeypatch):
    import threading

    from codex_plugin_scanner.guard import config

    store, _, _, _, _ = accepted
    writing, release, second_done = threading.Event(), threading.Event(), threading.Event()
    write = config._write_guard_config
    first_thread = None

    def interpose(*args):
        if threading.current_thread() is first_thread:
            writing.set()
            assert release.wait(2)
        write(*args)

    def first():
        config.update_guard_settings(store.guard_home, {"mode": "observe"}, skip_approval_gate=True)

    def second():
        config.update_guard_update_channel(store.guard_home, "alpha")
        second_done.set()

    monkeypatch.setattr(config, "_write_guard_config", interpose)
    first_thread = threading.Thread(target=first)
    other = threading.Thread(target=second)
    first_thread.start()
    assert writing.wait(2)
    other.start()
    try:
        assert not second_done.wait(0.05)
    finally:
        release.set()
        first_thread.join(3)
        other.join(3)
    assert not first_thread.is_alive() and not other.is_alive()
    result = config.load_guard_config(store.guard_home)
    assert result.mode == "observe"
    assert result.update_channel == "alpha"


def test_supported_truncated_write_cannot_publish_intermediate_policy(accepted, monkeypatch):
    import threading

    from codex_plugin_scanner.guard import config

    store, publisher, _, _, _ = accepted
    config.update_guard_settings(
        store.guard_home,
        {"default_action": "block"},
        skip_approval_gate=True,
    )
    publisher._publish_once()
    assert publisher.is_ready(), publisher.last_error
    before = publisher.current_snapshot_binding()
    before_policy = publisher._compiled_effective_policy()
    assert before_policy["default_action"] == "block"
    path = store.guard_home / "config.toml"
    truncated, release, started, published = (
        threading.Event(),
        threading.Event(),
        threading.Event(),
        threading.Event(),
    )
    real_open = Path.open
    client = publisher._client_request
    errors = []
    writer_thread = None

    class PausedFile:
        def __init__(self, handle):
            self.handle = handle

        def __enter__(self):
            truncated.set()
            assert release.wait(3)
            return self.handle.__enter__()

        def __exit__(self, *args):
            return self.handle.__exit__(*args)

    def at_truncation(target, *args, **kwargs):
        handle = real_open(target, *args, **kwargs)
        mode = args[0] if args else kwargs.get("mode", "r")
        if target == path and mode == "w" and threading.current_thread() is writer_thread:
            return PausedFile(handle)
        return handle

    def observed_client(**kwargs):
        published.set()
        assert client is not None
        return client(**kwargs)

    def writer():
        try:
            config.update_guard_settings(store.guard_home, {"default_action": "block"}, skip_approval_gate=True)
        except BaseException as error:
            errors.append(error)

    def publication():
        started.set()
        publisher._publish_once()

    monkeypatch.setattr(Path, "open", at_truncation)
    monkeypatch.setattr(publisher, "_client_request", observed_client)
    writer_thread = threading.Thread(target=writer)
    worker = threading.Thread(target=publication)
    writer_thread.start()
    try:
        assert truncated.wait(3)
        assert path.read_text() == ""
        worker.start()
        assert started.wait(2)
        # The ordinary publisher must not issue any snapshot compiled from the
        # paused empty file, even though its metadata is stable during this wait.
        assert not published.wait(0.2)
        assert publisher.current_snapshot_binding() == before
    finally:
        release.set()
        writer_thread.join(4)
        if worker.ident is not None:
            worker.join(4)
    assert not writer_thread.is_alive() and not worker.is_alive()
    assert not errors
    # The writer's notification makes any earlier in-flight epoch obsolete.
    assert not publisher.is_ready()
    publisher._publish_once()
    assert publisher.is_ready(), publisher.last_error
    effective = publisher._compiled_effective_policy()
    assert effective["default_action"] == "block"
    assert effective["harness_actions"] == before_policy["harness_actions"]


def test_mutation_lock_is_reentrant_only_for_own_thread_and_canonical_home(tmp_path):
    import threading

    from codex_plugin_scanner.guard.native_policy_publication_lock import hold_policy_publication_mutation

    home = tmp_path / "guard"
    refused = []

    def contender():
        try:
            with hold_policy_publication_mutation(home, timeout_seconds=0):
                pass
        except TimeoutError:
            refused.append(True)

    with hold_policy_publication_mutation(home):
        with (
            pytest.raises(ValueError, match="nested"),
            hold_policy_publication_mutation(home / ".." / "guard", timeout_seconds=0),
        ):
            raise ValueError("nested")
        worker = threading.Thread(target=contender)
        worker.start()
        worker.join(2)
        assert not worker.is_alive()
        assert refused == [True]
    with hold_policy_publication_mutation(home, timeout_seconds=0):
        pass


def test_inherited_pid_state_cannot_bypass_file_lock(tmp_path, monkeypatch):
    import os

    from codex_plugin_scanner.guard.native_policy_publication_lock import hold_policy_publication_mutation

    home = tmp_path / "guard"
    real_pid = os.getpid()
    # Model the thread-local data copied at fork. The child must attempt the
    # actual OS lock rather than inheriting a parent's Python ownership flag.
    with hold_policy_publication_mutation(home), monkeypatch.context() as patch:
        patch.setattr(os, "getpid", lambda: real_pid + 1)
        with pytest.raises(TimeoutError), hold_policy_publication_mutation(home, timeout_seconds=0):
            pass

"""Lifecycle and barrier tests for native snapshot publication."""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path

import pytest

import codex_plugin_scanner.guard.native_policy_snapshot as snapshot_module
from codex_plugin_scanner.guard.native_policy_snapshot import (
    NATIVE_POLICY_SNAPSHOT_CACHE_NAME,
    NativePolicySnapshotPublisher,
    notify_native_policy_mutation,
    snapshot_bytes_v3,
)
from codex_plugin_scanner.guard.store import GuardStore

from .native_policy_snapshot_test_fixtures import _ack, _config, _status

# Split modules are implementation containers; the compatibility façade imports
# their test functions so the historical test path keeps identical collection.
__test__ = False


def test_publisher_startup_ack_and_mutation_push(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    master = b"k" * 32
    monkeypatch.setattr(store, "_policy_integrity_secret_material", lambda *, create: (master, "master-id"))
    calls: list[bytes] = []

    def client_request(**kwargs: object) -> bytes:
        payload = kwargs["payload"]
        assert isinstance(payload, bytes)
        assert (guard_home / "native-runtime" / "policy-verifier.key").is_file()
        calls.append(payload)
        return _ack(payload)

    publisher = NativePolicySnapshotPublisher(
        store=store,
        status_provider=_status,
        client_request=client_request,
        poll_interval_seconds=0.05,
    )
    publisher.start()
    try:
        assert publisher.wait_until_ready(time.monotonic() + 2.0)
        first = publisher.current_snapshot()
        assert first is not None
        assert len(calls) >= 1

        (guard_home / "config.toml").write_text('mode = "observe"\n', encoding="utf-8")
        notify_native_policy_mutation(guard_home)
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            current = publisher.current_snapshot()
            if current is not None and current.get("mode") == "observe":
                break
            time.sleep(0.01)
        current = publisher.current_snapshot()
        assert current is not None and current["mode"] == "observe"
        assert current["generation"] > first["generation"]
        assert len(calls) >= 2
    finally:
        publisher.close()


def test_publisher_does_not_ack_snapshot_after_concurrent_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    master = b"r" * 32
    monkeypatch.setattr(store, "_policy_integrity_secret_material", lambda *, create: (master, "master-id"))
    entered = threading.Event()
    release = threading.Event()

    def client_request(**kwargs: object) -> bytes:
        payload = kwargs["payload"]
        assert isinstance(payload, bytes)
        entered.set()
        assert release.wait(2.0)
        return _ack(payload)

    publisher = NativePolicySnapshotPublisher(
        store=store,
        status_provider=_status,
        client_request=client_request,
        poll_interval_seconds=0.05,
    )
    publisher._epoch = 1
    worker = threading.Thread(target=publisher._publish_once)
    worker.start()
    assert entered.wait(2.0)
    publisher.request_publish()
    release.set()
    worker.join(timeout=2.0)
    try:
        assert not publisher.is_ready()
    finally:
        publisher.close()


def test_publisher_repushes_after_resident_generation_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    master = b"s" * 32
    monkeypatch.setattr(store, "_policy_integrity_secret_material", lambda *, create: (master, "master-id"))
    calls: list[bytes] = []

    def client_request(**kwargs: object) -> bytes:
        payload = kwargs["payload"]
        assert isinstance(payload, bytes)
        calls.append(payload)
        return _ack(payload, resident_generation=2 if len(calls) > 1 else 1)

    publisher = NativePolicySnapshotPublisher(
        store=store,
        status_provider=_status,
        client_request=client_request,
        poll_interval_seconds=0.05,
    )
    publisher.start()
    try:
        assert publisher.wait_until_ready(time.monotonic() + 2.0)
        assert len(calls) == 1
        resident_state = guard_home / "native-runtime" / "resident-v3-restarted"
        resident_state.mkdir(mode=0o700)
        (resident_state / "generation-2.json").write_text("{}", encoding="utf-8")
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline and len(calls) < 2:
            time.sleep(0.01)
        assert len(calls) >= 2
        assert publisher.is_ready()
    finally:
        publisher.close()


def test_publisher_does_not_republish_for_generation_created_by_own_ack(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    master = b"v" * 32
    monkeypatch.setattr(store, "_policy_integrity_secret_material", lambda *, create: (master, "master-id"))
    calls: list[bytes] = []

    def client_request(**kwargs: object) -> bytes:
        payload = kwargs["payload"]
        assert isinstance(payload, bytes)
        calls.append(payload)
        resident_state = guard_home / "native-runtime" / "resident-v3-owned"
        resident_state.mkdir(mode=0o700)
        (resident_state / "generation-1.json").write_text("{}", encoding="utf-8")
        return _ack(payload)

    publisher = NativePolicySnapshotPublisher(
        store=store,
        status_provider=_status,
        client_request=client_request,
        poll_interval_seconds=0.05,
    )
    publisher.start()
    try:
        assert publisher.wait_until_ready(time.monotonic() + 2.0)
        time.sleep(0.2)
        assert len(calls) == 1
    finally:
        publisher.close()


def test_publisher_rejects_ack_after_resident_restart_before_barrier(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    master = b"y" * 32
    monkeypatch.setattr(store, "_policy_integrity_secret_material", lambda *, create: (master, "master-id"))
    resident_fingerprints = iter(
        (
            (),
            (("resident-v3-test/generation-00000000000000000001.json", 1, 1),),
            (("resident-v3-test/generation-00000000000000000002.json", 2, 1),),
        )
    )

    def client_request(**kwargs: object) -> bytes:
        payload = kwargs["payload"]
        assert isinstance(payload, bytes)
        return _ack(payload, resident_generation=1)

    publisher = NativePolicySnapshotPublisher(
        store=store,
        status_provider=_status,
        client_request=client_request,
        poll_interval_seconds=0.05,
    )
    monkeypatch.setattr(publisher, "_current_resident_fingerprint", lambda: next(resident_fingerprints))
    publisher._epoch = 1
    publisher._publish_once()
    try:
        assert not publisher.is_ready()
        assert publisher.current_snapshot() is None
    finally:
        publisher.close()


def test_publisher_rejects_mutated_ack_without_opening_barrier(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    master = b"t" * 32
    monkeypatch.setattr(store, "_policy_integrity_secret_material", lambda *, create: (master, "master-id"))

    def client_request(**kwargs: object) -> bytes:
        payload = kwargs["payload"]
        assert isinstance(payload, bytes)
        snapshot = json.loads(payload)["request"]["snapshot"]
        return json.dumps(
            {
                "status": "accepted",
                "generation": snapshot["generation"],
                "policy_digest": "c" * 64,
                "idempotent": False,
                "resident_generation": 1,
            }
        ).encode()

    publisher = NativePolicySnapshotPublisher(
        store=store,
        status_provider=_status,
        client_request=client_request,
        poll_interval_seconds=0.05,
    )
    publisher.start()
    try:
        assert not publisher.wait_until_ready(time.monotonic() + 0.5)
        assert publisher.last_error == "native_policy_snapshot_ack_mismatch"
        assert not publisher.is_ready()
    finally:
        publisher.close()


def test_auto_hook_uses_barrier_without_loading_config_per_request(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import codex_plugin_scanner.guard.daemon.hook_worker as hook_worker_module

    wait_deadlines: list[float] = []

    class _Publisher:
        def start(self) -> None:
            return

        def wait_until_ready(self, deadline_monotonic: float) -> bool:
            wait_deadlines.append(deadline_monotonic)
            return False

        def current_snapshot(self) -> None:
            return None

        def close(self) -> None:
            return

    monkeypatch.setattr(hook_worker_module, "native_mode", lambda: "auto")
    monkeypatch.setattr(hook_worker_module, "get_native_policy_snapshot_publisher", lambda _store: _Publisher())
    monkeypatch.setattr(
        hook_worker_module,
        "load_guard_config",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("hook loaded config")),
    )
    monkeypatch.setattr(hook_worker_module, "review_raw_hook_native", lambda **_kwargs: None)

    worker = hook_worker_module.HookWorker(store=GuardStore(tmp_path / "guard-home"))
    started_at = time.monotonic()
    result = worker.review_http_payload(
        payload={"hook_event_name": "PreToolUse", "tool_input": {"command": "pwd"}},
        params={},
        default_harness="codex",
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
    )
    assert result["reason_code"] == "native_pre_tool_unavailable"
    assert len(wait_deadlines) == 2
    assert 0 < wait_deadlines[0] - started_at <= 1.0


def test_prepare_workspace_policy_uses_bounded_first_workspace_handshake(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import codex_plugin_scanner.guard.daemon.hook_worker as hook_worker_module

    registered: list[Path | None] = []
    wait_deadlines: list[float] = []

    class _Publisher:
        def start(self) -> None:
            return

        def register_workspace(self, workspace: Path | None) -> bool:
            registered.append(workspace)
            return True

        def wait_until_ready(self, deadline_monotonic: float) -> bool:
            wait_deadlines.append(deadline_monotonic)
            return True

        def current_snapshot_binding(self) -> dict[str, object]:
            return {
                "generation": 1,
                "policy_digest": "a" * 64,
                "runtime_identity": "b" * 64,
                "mode": "enforce",
            }

        def close(self) -> None:
            return

    monkeypatch.setattr(hook_worker_module, "native_mode", lambda: "auto")
    monkeypatch.setattr(hook_worker_module, "get_native_policy_snapshot_publisher", lambda _store: _Publisher())

    worker = hook_worker_module.HookWorker(store=GuardStore(tmp_path / "guard-home"))
    workspace = tmp_path / "workspace"
    started_at = time.monotonic()
    binding = worker.prepare_workspace_policy(workspace, deadline=started_at + 0.25)

    assert binding is not None
    assert registered == [workspace]
    assert len(wait_deadlines) == 2
    assert wait_deadlines[-1] <= started_at + 0.25


def test_same_generation_retries_reuse_exact_signed_snapshot_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    master = b"u" * 32
    future_ms = int(time.time() * 1_000) + 60_000
    build_calls = 0
    original_builder = snapshot_module.build_policy_snapshot_v3

    def counted_builder(**kwargs: object) -> dict[str, object]:
        nonlocal build_calls
        build_calls += 1
        return original_builder(**kwargs)

    monkeypatch.setattr(snapshot_module, "build_policy_snapshot_v3", counted_builder)
    first = snapshot_module.native_policy_snapshot_v3(
        config=_config(),
        guard_home=guard_home,
        runtime_identity="a" * 64,
        rule_digest="b" * 64,
        policy_integrity_key=master,
        issued_at_ms=future_ms,
        expires_at_ms=future_ms + 60_000,
    )
    first_bytes = snapshot_bytes_v3(first)
    second = snapshot_module.native_policy_snapshot_v3(
        config=_config(),
        guard_home=guard_home,
        runtime_identity="a" * 64,
        rule_digest="b" * 64,
        policy_integrity_key=master,
        issued_at_ms=future_ms + 10_000,
        expires_at_ms=future_ms + 70_000,
    )
    cache_path = guard_home / "native-runtime" / NATIVE_POLICY_SNAPSHOT_CACHE_NAME
    assert second == first
    assert snapshot_bytes_v3(second) == first_bytes
    assert cache_path.read_bytes() == first_bytes
    assert build_calls == 1

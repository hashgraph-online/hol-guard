"""Focused tests for the native policy-snapshot publication barrier."""

from __future__ import annotations

import ctypes
import hashlib
import hmac
import json
import threading
import time
import types
from pathlib import Path
from types import SimpleNamespace

import pytest

import codex_plugin_scanner.guard.native_policy_snapshot as snapshot_module
from codex_plugin_scanner.guard.native_policy_snapshot import (
    NATIVE_POLICY_SNAPSHOT_CACHE_NAME,
    POLICY_SNAPSHOT_ACK_REQUIRES_NEW_GENERATION,
    POLICY_SNAPSHOT_INTEGRITY_DOMAIN,
    POLICY_SNAPSHOT_VERIFIER_DERIVATION_DOMAIN,
    NativePolicySnapshotPublisher,
    build_policy_snapshot_v3,
    derive_native_policy_verifier_key,
    notify_native_policy_mutation,
    provision_native_policy_verifier_key,
    snapshot_bytes_v3,
)
from codex_plugin_scanner.guard.store import GuardStore


def _config() -> dict[str, object]:
    return {
        "mode": "prompt",
        "protection_posture": "protected",
        "security_level": "balanced",
        "default_action": "warn",
        "unknown_publisher_action": "review",
        "changed_hash_action": "require-reapproval",
        "new_network_domain_action": "warn",
        "subprocess_action": "warn",
        "risk_actions": {"prompt_injection": "block"},
        "harness_risk_actions": {},
        "harness_actions": {},
        "publisher_actions": {},
        "artifact_actions": {},
        "sandbox_analysis": "off",
        "receipt_redaction_level": "full",
    }


def _status() -> SimpleNamespace:
    return SimpleNamespace(
        mode="auto",
        available=True,
        compatible=True,
        identity=SimpleNamespace(path=Path("/tmp/hol-guard-runtime"), sha256="a" * 64),
        capabilities=SimpleNamespace(
            rule_digest="b" * 64,
            features=(
                "resident-protocol-v2",
                "policy-snapshot-v3",
                "policy-snapshot-push-v1",
                "native-policy-in-memory-v1",
                "native-resident-client-v1",
            ),
        ),
    )


def _ack(payload: bytes) -> bytes:
    snapshot = json.loads(payload)["request"]["snapshot"]
    return json.dumps(
        {
            "status": "accepted",
            "generation": snapshot["generation"],
            "policy_digest": snapshot["policy_digest"],
            "idempotent": False,
        }
    ).encode()


def test_v3_builder_derives_and_provisions_verifier_before_snapshot_push(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    master = b"m" * 32
    expected = hmac.new(master, POLICY_SNAPSHOT_VERIFIER_DERIVATION_DOMAIN, hashlib.sha256).digest()
    assert derive_native_policy_verifier_key(master) == expected

    key_path = provision_native_policy_verifier_key(guard_home, master)
    assert key_path.read_bytes() == expected
    assert key_path.stat().st_mode & 0o077 == 0

    snapshot = build_policy_snapshot_v3(
        config=_config(),
        guard_home=guard_home,
        runtime_identity="a" * 64,
        rule_digest="b" * 64,
        verifier_key=expected,
        generation=1,
        issued_at_ms=100,
        expires_at_ms=200,
    )
    signing = dict(snapshot)
    integrity = signing.pop("integrity")
    assert isinstance(integrity, dict)
    expected_mac = hmac.new(
        expected,
        POLICY_SNAPSHOT_INTEGRITY_DOMAIN
        + json.dumps(signing, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(),
        hashlib.sha256,
    ).hexdigest()
    assert integrity["mac"] == expected_mac
    assert master not in key_path.read_bytes()


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
    assert len(wait_deadlines) == 1
    assert 0 < wait_deadlines[0] - started_at <= 0.3


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


@pytest.mark.parametrize("boundary", ("cache", "state", "cleanup"))
def test_snapshot_transaction_recovers_each_persistence_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    master = b"z" * 32
    future_ms = int(time.time() * 1_000) + 60_000
    original_cache_writer = snapshot_module._write_v3_snapshot_cache
    original_state_writer = snapshot_module._write_v3_generation_state
    original_cleanup = snapshot_module._clear_v3_snapshot_pending

    def fail_once(*_args: object, **_kwargs: object) -> bytes:
        raise snapshot_module.NativePolicySnapshotError("injected_persistence_crash")

    if boundary == "cache":
        monkeypatch.setattr(snapshot_module, "_write_v3_snapshot_cache", fail_once)
    elif boundary == "state":
        monkeypatch.setattr(snapshot_module, "_write_v3_generation_state", fail_once)
    else:
        monkeypatch.setattr(snapshot_module, "_clear_v3_snapshot_pending", fail_once)
    with pytest.raises(snapshot_module.NativePolicySnapshotError, match="injected_persistence_crash"):
        snapshot_module.native_policy_snapshot_v3(
            config=_config(),
            guard_home=guard_home,
            runtime_identity="a" * 64,
            rule_digest="b" * 64,
            policy_integrity_key=master,
            issued_at_ms=future_ms,
            expires_at_ms=future_ms + 60_000,
        )
    monkeypatch.setattr(snapshot_module, "_write_v3_snapshot_cache", original_cache_writer)
    monkeypatch.setattr(snapshot_module, "_write_v3_generation_state", original_state_writer)
    monkeypatch.setattr(snapshot_module, "_clear_v3_snapshot_pending", original_cleanup)

    recovered = snapshot_module.native_policy_snapshot_v3(
        config=_config(),
        guard_home=guard_home,
        runtime_identity="a" * 64,
        rule_digest="b" * 64,
        policy_integrity_key=master,
        issued_at_ms=future_ms + 10_000,
        expires_at_ms=future_ms + 70_000,
    )
    cache_path = guard_home / "native-runtime" / NATIVE_POLICY_SNAPSHOT_CACHE_NAME
    pending_path = guard_home / "native-runtime" / "policy-snapshot-publisher-v3.pending.json"
    assert recovered["generation"] == 1
    assert cache_path.read_bytes() == snapshot_bytes_v3(recovered)
    assert not pending_path.exists()


def test_lost_ack_retries_identical_payload(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    master = b"v" * 32
    monkeypatch.setattr(store, "_policy_integrity_secret_material", lambda *, create: (master, "master-id"))
    calls: list[bytes] = []

    def client_request(**kwargs: object) -> bytes | None:
        payload = kwargs["payload"]
        assert isinstance(payload, bytes)
        calls.append(payload)
        return None if len(calls) == 1 else _ack(payload)

    publisher = NativePolicySnapshotPublisher(
        store=store,
        status_provider=_status,
        client_request=client_request,
        poll_interval_seconds=0.05,
    )
    publisher.start()
    try:
        assert publisher.wait_until_ready(time.monotonic() + 2.0)
        assert len(calls) >= 2
        assert calls[1] == calls[0]
    finally:
        publisher.close()


def test_floor_only_ack_materializes_strictly_new_generation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    master = b"f" * 32
    monkeypatch.setattr(store, "_policy_integrity_secret_material", lambda *, create: (master, "master-id"))
    calls: list[bytes] = []

    def client_request(**kwargs: object) -> bytes:
        payload = kwargs["payload"]
        assert isinstance(payload, bytes)
        calls.append(payload)
        snapshot = json.loads(payload)["request"]["snapshot"]
        if len(calls) == 1:
            return json.dumps(
                {
                    "status": POLICY_SNAPSHOT_ACK_REQUIRES_NEW_GENERATION,
                    "generation": snapshot["generation"],
                    "policy_digest": "d" * 64,
                    "idempotent": False,
                }
            ).encode()
        return _ack(payload)

    publisher = NativePolicySnapshotPublisher(
        store=store,
        status_provider=_status,
        client_request=client_request,
        poll_interval_seconds=0.05,
    )
    try:
        publisher._publish_once()
        snapshot = publisher.current_snapshot()
        assert snapshot is not None
        assert snapshot["generation"] == 2
        assert json.loads(calls[1])["request"]["snapshot"]["generation"] == 2
        assert calls[1] != calls[0]
        assert publisher.is_ready()
    finally:
        publisher.close()


@pytest.mark.parametrize(
    "response",
    (
        {"error": POLICY_SNAPSHOT_ACK_REQUIRES_NEW_GENERATION, "retryable": False},
        {
            "status": POLICY_SNAPSHOT_ACK_REQUIRES_NEW_GENERATION,
            "generation": 1,
            "policy_digest": "d" * 64,
            "idempotent": True,
        },
        {
            "status": POLICY_SNAPSHOT_ACK_REQUIRES_NEW_GENERATION,
            "generation": 1,
            "policy_digest": "d" * 64,
            "idempotent": False,
            "unexpected": True,
        },
    ),
)
def test_floor_recovery_requires_exact_typed_ack(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    response: dict[str, object],
) -> None:
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    master = b"g" * 32
    monkeypatch.setattr(store, "_policy_integrity_secret_material", lambda *, create: (master, "master-id"))
    calls = 0

    def client_request(**_kwargs: object) -> bytes:
        nonlocal calls
        calls += 1
        return json.dumps(response).encode()

    publisher = NativePolicySnapshotPublisher(
        store=store,
        status_provider=_status,
        client_request=client_request,
        poll_interval_seconds=0.05,
    )
    try:
        publisher._publish_once()
        assert calls == 1
        assert not publisher.is_ready()
        assert publisher.last_error == "native_policy_snapshot_ack_invalid"
    finally:
        publisher.close()


def test_publisher_process_restart_reuses_cached_payload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    master = b"w" * 32
    monkeypatch.setattr(store, "_policy_integrity_secret_material", lambda *, create: (master, "master-id"))
    first_calls: list[bytes] = []

    def first_client(**kwargs: object) -> bytes:
        payload = kwargs["payload"]
        assert isinstance(payload, bytes)
        first_calls.append(payload)
        return _ack(payload)

    first_publisher = NativePolicySnapshotPublisher(
        store=store,
        status_provider=_status,
        client_request=first_client,
        poll_interval_seconds=0.05,
    )
    first_publisher.start()
    assert first_publisher.wait_until_ready(time.monotonic() + 2.0)
    first_publisher.close()

    second_calls: list[bytes] = []

    def second_client(**kwargs: object) -> bytes:
        payload = kwargs["payload"]
        assert isinstance(payload, bytes)
        second_calls.append(payload)
        return _ack(payload)

    second_publisher = NativePolicySnapshotPublisher(
        store=store,
        status_provider=_status,
        client_request=second_client,
        poll_interval_seconds=0.05,
    )
    second_publisher.start()
    try:
        assert second_publisher.wait_until_ready(time.monotonic() + 2.0)
        assert first_calls and second_calls
        assert second_calls[0] == first_calls[0]
    finally:
        second_publisher.close()


class _DeterministicClock:
    def __init__(self) -> None:
        self.wall = time.time()
        self.monotonic = time.monotonic()

    def wall_time(self) -> float:
        return self.wall

    def monotonic_time(self) -> float:
        return self.monotonic


def test_renewal_materializes_higher_generation_before_expiry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    master = b"x" * 32
    monkeypatch.setattr(store, "_policy_integrity_secret_material", lambda *, create: (master, "master-id"))
    clock = _DeterministicClock()
    calls: list[bytes] = []

    def client_request(**kwargs: object) -> bytes:
        payload = kwargs["payload"]
        assert isinstance(payload, bytes)
        calls.append(payload)
        return _ack(payload)

    publisher = NativePolicySnapshotPublisher(
        store=store,
        status_provider=_status,
        client_request=client_request,
        poll_interval_seconds=0.05,
        wall_clock=clock.wall_time,
        monotonic_clock=clock.monotonic_time,
    )
    try:
        publisher._publish_once()
        first = publisher.current_snapshot()
        assert first is not None
        due = publisher._renewal_due_monotonic
        assert due is not None
        assert due < clock.monotonic + 24 * 60 * 60

        clock.monotonic = due + 0.001
        clock.wall += 1.0
        publisher._publish_once(renew_after_generation=first["generation"])
        renewed = publisher.current_snapshot()
        assert renewed is not None
        assert renewed["generation"] > first["generation"]
        assert renewed["expires_at_ms"] > first["expires_at_ms"]
        assert len(calls) == 2
    finally:
        publisher.close()


def test_renewal_failure_keeps_barrier_closed_at_expiry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    master = b"y" * 32
    monkeypatch.setattr(store, "_policy_integrity_secret_material", lambda *, create: (master, "master-id"))
    clock = _DeterministicClock()
    calls = 0

    def client_request(**kwargs: object) -> bytes | None:
        nonlocal calls
        calls += 1
        payload = kwargs["payload"]
        assert isinstance(payload, bytes)
        return _ack(payload) if calls == 1 else None

    publisher = NativePolicySnapshotPublisher(
        store=store,
        status_provider=_status,
        client_request=client_request,
        poll_interval_seconds=0.05,
        wall_clock=clock.wall_time,
        monotonic_clock=clock.monotonic_time,
    )
    try:
        publisher._publish_once()
        first = publisher.current_snapshot()
        assert first is not None
        publisher._publish_once(renew_after_generation=first["generation"])
        assert not publisher.is_ready()
        clock.wall = first["expires_at_ms"] / 1_000
        assert not publisher.is_ready()
    finally:
        publisher.close()


def test_renewal_retry_reuses_candidate_with_bounded_backoff(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    master = b"q" * 32
    monkeypatch.setattr(store, "_policy_integrity_secret_material", lambda *, create: (master, "master-id"))
    clock = _DeterministicClock()
    calls: list[bytes] = []

    def client_request(**kwargs: object) -> bytes | None:
        payload = kwargs["payload"]
        assert isinstance(payload, bytes)
        calls.append(payload)
        return _ack(payload) if len(calls) != 2 else None

    publisher = NativePolicySnapshotPublisher(
        store=store,
        status_provider=_status,
        client_request=client_request,
        poll_interval_seconds=0.05,
        wall_clock=clock.wall_time,
        monotonic_clock=clock.monotonic_time,
    )
    try:
        publisher._publish_once()
        first = publisher.current_snapshot()
        assert first is not None
        publisher._publish_once(renew_after_generation=first["generation"])
        retry_at = publisher._retry_not_before_monotonic
        assert retry_at is not None
        assert clock.monotonic < retry_at <= clock.monotonic + 0.2
        clock.monotonic = retry_at + 0.001
        publisher._publish_once(renew_after_generation=first["generation"])
        renewed = publisher.current_snapshot()
        assert renewed is not None
        assert renewed["generation"] > first["generation"]
        assert len(calls) == 3
        assert calls[2] == calls[1]
    finally:
        publisher.close()


def _fake_windows_snapshot_kernel(
    data: bytes,
    *,
    reported_size: int | None = None,
    read_result: bool = True,
) -> tuple[object, types.SimpleNamespace, list[object]]:
    offset = 0
    closed: list[object] = []
    expected_size = len(data) if reported_size is None else reported_size

    def read_file(
        _handle: object,
        buffer: object,
        request_size: int,
        count_pointer: object,
        _overlapped: object,
    ) -> int:
        nonlocal offset
        if not read_result:
            return 0
        chunk = data[offset : offset + request_size]
        ctypes.memmove(buffer, chunk, len(chunk))
        ctypes.cast(count_pointer, ctypes.POINTER(ctypes.c_uint32)).contents.value = len(chunk)
        offset += len(chunk)
        return 1

    kernel32 = types.SimpleNamespace(ReadFile=read_file)
    information = types.SimpleNamespace(
        nFileSizeHigh=expected_size >> 32,
        nFileSizeLow=expected_size & 0xFFFFFFFF,
    )
    return kernel32, information, closed


def test_windows_cache_reader_verifies_and_reads_one_handle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kernel32, information, closed = _fake_windows_snapshot_kernel(b"signed-cache")
    opened: list[object] = []
    verified: list[object] = []

    def open_handle(*_args: object, **_kwargs: object) -> tuple[object, object, object]:
        handle = object()
        opened.append(handle)
        return kernel32, handle, information

    monkeypatch.setattr(snapshot_module, "_windows_open_handle", open_handle)
    monkeypatch.setattr(snapshot_module, "_windows_owner_sid", lambda: "S-1-5-21-1")
    monkeypatch.setattr(
        snapshot_module,
        "_windows_verify_private_dacl",
        lambda handle, *, owner_sid, directory: verified.append((handle, owner_sid, directory)),
    )
    monkeypatch.setattr(
        snapshot_module,
        "_windows_close_handle",
        lambda _kernel, handle: closed.append(handle),
    )

    payload = snapshot_module._windows_read_snapshot_bytes(Path("C:/Guard/snapshot.json"))

    assert payload == b"signed-cache"
    assert len(opened) == 1
    assert verified == [(opened[0], "S-1-5-21-1", False)]
    assert closed == [opened[0]]


@pytest.mark.parametrize(
    ("failure", "reported_size", "read_result"),
    (
        ("acl", None, True),
        ("short", len(b"short") + 1, True),
        ("oversize", snapshot_module.POLICY_SNAPSHOT_MAX_BYTES + 1, True),
        ("read", None, False),
    ),
)
def test_windows_cache_reader_closes_handle_on_all_failures(
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
    reported_size: int | None,
    read_result: bool,
) -> None:
    data = b"short" if failure == "short" else b"signed-cache"
    kernel32, information, closed = _fake_windows_snapshot_kernel(
        data,
        reported_size=reported_size,
        read_result=read_result,
    )
    handle = object()
    monkeypatch.setattr(
        snapshot_module,
        "_windows_open_handle",
        lambda *_args, **_kwargs: (kernel32, handle, information),
    )
    monkeypatch.setattr(snapshot_module, "_windows_owner_sid", lambda: "S-1-5-21-1")
    if failure == "acl":
        monkeypatch.setattr(
            snapshot_module,
            "_windows_verify_private_dacl",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                snapshot_module.NativePolicySnapshotError("native_policy_windows_acl_not_private")
            ),
        )
    else:
        monkeypatch.setattr(snapshot_module, "_windows_verify_private_dacl", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        snapshot_module,
        "_windows_close_handle",
        lambda _kernel, closed_handle: closed.append(closed_handle),
    )

    with pytest.raises(snapshot_module.NativePolicySnapshotError):
        snapshot_module._windows_read_snapshot_bytes(Path("C:/Guard/snapshot.json"))
    assert closed == [handle]


def test_windows_open_handle_uses_disk_nonreparse_read_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    create_arguments: list[tuple[object, ...]] = []
    closed: list[object] = []

    def create_file(*arguments: object) -> object:
        create_arguments.append(arguments)
        return ctypes.c_void_p(71)

    def get_information(_handle: object, pointer: object) -> int:
        information_type = snapshot_module._windows_file_information_type()
        information = ctypes.cast(pointer, ctypes.POINTER(information_type)).contents
        information.dwFileAttributes = snapshot_module._WINDOWS_FILE_ATTRIBUTE_NORMAL
        return 1

    def close_handle(handle: object) -> int:
        closed.append(handle)
        return 1

    kernel32 = types.SimpleNamespace(
        CreateFileW=create_file,
        CloseHandle=close_handle,
        GetFileInformationByHandle=get_information,
        GetFileType=lambda _handle: snapshot_module._WINDOWS_FILE_TYPE_DISK,
    )
    monkeypatch.setattr(snapshot_module, "_windows_dll", lambda _name: kernel32)

    opened = snapshot_module._windows_open_handle(Path("C:/Guard/snapshot.json"), directory=False)

    assert getattr(opened[1], "value", opened[1]) == 71
    assert create_arguments[0][1] == snapshot_module._WINDOWS_GENERIC_READ
    assert create_arguments[0][2] == snapshot_module._WINDOWS_FILE_SHARE_READ
    assert create_arguments[0][5] & snapshot_module._WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT
    assert closed == []
    snapshot_module._windows_close_handle(*opened[:2])
    assert [getattr(handle, "value", handle) for handle in closed] == [71]


def test_windows_cache_read_rejects_ancestor_reparse_before_open(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(snapshot_module.os, "name", "nt")
    monkeypatch.setattr(snapshot_module, "_windows_path_has_reparse_component", lambda _path: True)
    monkeypatch.setattr(
        snapshot_module,
        "_windows_read_snapshot_bytes",
        lambda _path: (_ for _ in ()).throw(AssertionError("reparse path must not open")),
    )

    with pytest.raises(snapshot_module.NativePolicySnapshotError, match="cache_invalid"):
        snapshot_module._read_v3_snapshot_file(Path("C:/Guard/snapshot.json"))

"""Unit tests for the native context-digest transport adapter.

These exercise the adapter's binding/validation contract only; semantic
parity with the legacy implementation is proven by the parity corpus in
``tests/fixtures/context-digest-parity`` executed by the Rust tests and the
resident integration tests.
"""

from __future__ import annotations

import hashlib
import json
import multiprocessing
import os
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_context
from codex_plugin_scanner.guard.native_runtime import (
    NativeRuntimeCapabilities,
    NativeRuntimeIdentity,
    NativeRuntimeStatus,
)

_FEATURES = (
    "resident-protocol-v2",
    "native-resident-client-v1",
    "native-resident-lifecycle-v1",
    "context-digest-v1",
)


def _status(
    *,
    mode: str = "force",
    available: bool = True,
    compatible: bool = True,
    features: tuple[str, ...] = _FEATURES,
) -> NativeRuntimeStatus:
    identity = NativeRuntimeIdentity(
        path=Path("/runtime/hol-guard-runtime"),
        size=1,
        mtime_ns=1,
        sha256="ab" * 32,
    )
    capabilities = NativeRuntimeCapabilities(
        protocol_version=2,
        runtime_version="0.0.0",
        rule_digest="cd" * 32,
        build_sha="ef" * 32,
        target="test",
        features=features,
    )
    return NativeRuntimeStatus(
        mode=mode,
        available=available,
        compatible=compatible,
        reason="ok",
        identity=identity,
        capabilities=capabilities,
    )


def _request_sha256(request: dict[str, object]) -> str:
    canonical = json.dumps(request, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode(
        "utf-8"
    )
    return hashlib.sha256(canonical).hexdigest()


def _ok_result(request: dict[str, object]) -> bytes:
    return json.dumps(
        {
            "schema": "guard-context-digest-result.v1",
            "request_id": request["request_id"],
            "request_sha256": _request_sha256(request),
            "status": "ok",
            "code": "ok",
            "digest": "00" * 32,
        }
    ).encode("utf-8")


def _prime(
    monkeypatch: pytest.MonkeyPatch,
    *,
    status: NativeRuntimeStatus | None = None,
    response: bytes | None = None,
) -> list[dict[str, object]]:
    """Install a force-mode status and capture outgoing op requests."""
    captured: list[dict[str, object]] = []
    monkeypatch.setattr(native_context, "native_runtime_status", lambda: status or _status())

    def _client(*_args: object, **kwargs: object) -> bytes | None:
        payload = kwargs["payload"]
        assert isinstance(payload, bytes)
        envelope = json.loads(payload)
        captured.append(envelope["request"])
        if response is not None:
            return response
        return _ok_result(captured[-1])

    monkeypatch.setattr(native_context, "native_resident_client_request", _client)
    monkeypatch.setattr(native_context, "_isolated_environment", lambda: {})
    # Provisioning the resident's on-disk prerequisite is exercised on its own;
    # these cases stay at the transport-binding level.
    monkeypatch.setattr(native_context, "ensure_resident_prerequisite", lambda _guard_home: True)
    monkeypatch.setattr(native_context, "native_resident_client_ready", lambda _executable, _guard_home: True)
    return captured


def test_native_context_digest_off_mode_returns_none(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _prime(monkeypatch, status=_status(mode="off"))
    assert native_context.native_context_digest("launch_argv_digest", {"argv": ["x"]}, guard_home=tmp_path) is None


def test_native_context_digest_missing_feature_returns_none(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _prime(
        monkeypatch,
        status=_status(features=tuple(f for f in _FEATURES if f != "context-digest-v1")),
    )
    assert native_context.native_context_digest("launch_argv_digest", {"argv": ["x"]}, guard_home=tmp_path) is None


def test_native_context_digest_incompatible_returns_none(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _prime(monkeypatch, status=_status(compatible=False))
    assert native_context.native_context_digest("launch_argv_digest", {"argv": ["x"]}, guard_home=tmp_path) is None


def _seed_verifier_key(guard_home: Path) -> Path:
    from codex_plugin_scanner.guard.native_policy_snapshot_constants import (
        NATIVE_POLICY_VERIFIER_KEY_NAME,
        NATIVE_RUNTIME_STATE_DIRECTORY,
    )

    key = guard_home / NATIVE_RUNTIME_STATE_DIRECTORY / NATIVE_POLICY_VERIFIER_KEY_NAME
    key.parent.mkdir(parents=True, exist_ok=True)
    key.write_bytes(b"\x07" * 32)
    return key


def _forget_prerequisite_memo(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(native_context, "_RESIDENT_PREREQUISITE_HOMES", set())


def test_resident_prerequisite_accepts_seeded_key_without_opening_a_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A home that already carries the verifier key must not need a store.

    The resident only refuses to serve when that file is missing, so homes
    whose key was seeded by an owner (the test harness, a repair path) must
    keep working even when the home has no policy master to derive from.
    """

    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    _seed_verifier_key(guard_home)
    _forget_prerequisite_memo(monkeypatch)

    def _unexpected(_store: object) -> None:
        raise AssertionError("a seeded home must not be provisioned again")

    from codex_plugin_scanner.guard import native_policy_snapshot_publisher

    monkeypatch.setattr(native_policy_snapshot_publisher, "provision_native_verifier_key_for_store", _unexpected)
    assert native_context.ensure_resident_prerequisite(guard_home) is True


def test_resident_prerequisite_provisions_a_missing_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A home without the key is provisioned from its store, once per process."""

    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    _forget_prerequisite_memo(monkeypatch)
    provisioned: list[Path] = []

    from codex_plugin_scanner.guard import native_policy_snapshot_publisher

    def _provision(store: object) -> None:
        provisioned.append(Path(store.guard_home))
        _seed_verifier_key(guard_home)

    monkeypatch.setattr(native_policy_snapshot_publisher, "provision_native_verifier_key_for_store", _provision)
    assert native_context.ensure_resident_prerequisite(guard_home) is True
    assert native_context.ensure_resident_prerequisite(guard_home) is True
    assert provisioned == [guard_home]


def test_resident_prerequisite_reports_an_unprovisionable_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    _forget_prerequisite_memo(monkeypatch)

    from codex_plugin_scanner.guard import native_policy_snapshot_publisher

    def _fail(_store: object) -> None:
        raise RuntimeError("no policy master")

    monkeypatch.setattr(native_policy_snapshot_publisher, "provision_native_verifier_key_for_store", _fail)
    assert native_context.ensure_resident_prerequisite(guard_home) is False


def test_native_context_digest_does_not_ship_requests_to_an_unprovisionable_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Without the prerequisite every request would fail closed after a spawn."""

    real_prerequisite = native_context.ensure_resident_prerequisite
    captured = _prime(monkeypatch)
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    _forget_prerequisite_memo(monkeypatch)

    from codex_plugin_scanner.guard import native_policy_snapshot_publisher

    def _fail(_store: object) -> None:
        raise RuntimeError("no policy master")

    monkeypatch.setattr(native_policy_snapshot_publisher, "provision_native_verifier_key_for_store", _fail)
    monkeypatch.setattr(native_context, "ensure_resident_prerequisite", real_prerequisite)
    assert native_context.native_context_digest("launch_argv_digest", {"argv": ["x"]}, guard_home=guard_home) is None
    assert captured == []


def test_native_context_digest_grants_the_cold_start_allowance_only_while_the_pool_must_spawn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The allowance pays for a spawn, so it tracks the pool, not a memory.

    A resident the pool has parked answers in milliseconds; one that has never
    started — or that something killed — has to be spawned inside the same
    budget, which a contended runner cannot promise.
    """

    budgets: list[int] = []
    remaining: list[float] = []
    monkeypatch.setattr(native_context, "native_runtime_status", lambda: _status())
    monkeypatch.setattr(native_context, "ensure_resident_prerequisite", lambda _home: True)
    monkeypatch.setattr(native_context, "_isolated_environment", lambda: {})

    def _client(*_args: object, **kwargs: object) -> bytes | None:
        envelope = json.loads(kwargs["payload"])
        budgets.append(envelope["deadline_budget_ms"])
        remaining.append((kwargs["deadline_monotonic"] - time.monotonic()) * 1_000)
        return _ok_result(envelope["request"])

    monkeypatch.setattr(native_context, "native_resident_client_request", _client)
    monkeypatch.setattr(native_context, "native_resident_client_ready", lambda _executable, _home: False)
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    for argv in ("a", "b"):
        assert native_context.native_context_digest("launch_argv_digest", {"argv": [argv]}, guard_home=guard_home)

    monkeypatch.setattr(native_context, "native_resident_client_ready", lambda _executable, _home: True)
    for argv in ("c", "d"):
        assert native_context.native_context_digest("launch_argv_digest", {"argv": [argv]}, guard_home=guard_home)

    warm = int(native_context._TIMEOUT_SECONDS * 1_000)
    cold = warm + int(native_context._COLD_START_ALLOWANCE_SECONDS * 1_000)
    # The client's deadline is what the pool readiness buys: a warm home keeps the
    # tight steady-state budget, a home the pool must spawn does not.
    assert [value > cold - 500 for value in remaining[:2]] == [True, True]
    assert [value < warm + 500 for value in remaining[2:]] == [True, True]
    # The resident's own bound is the retry's, and it is the same on every
    # attempt, so a retry is never bound by the tight budget the first carried.
    retry = warm + native_context._RETRY_ALLOWANCE_MULTIPLIER * int(
        native_context._COLD_START_ALLOWANCE_SECONDS * 1_000
    )
    assert budgets == [retry, retry, retry, retry]


def test_native_context_digest_asks_the_pool_about_the_resolved_runtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The readiness probe must describe the same runtime and home as the request."""

    _prime(monkeypatch)
    seen: list[tuple[Path, Path]] = []

    def _ready(executable: Path, guard_home: Path) -> bool:
        seen.append((executable, guard_home))
        return True

    monkeypatch.setattr(native_context, "native_resident_client_ready", _ready)
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    assert native_context.native_context_digest("launch_argv_digest", {"argv": ["a"]}, guard_home=guard_home)
    status = native_context._native_runtime_status_memo()
    assert seen == [(status.identity.path, guard_home)]


def test_native_context_digest_retries_a_timeout_once_with_the_allowance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The pooled client serialises requests, so a tight budget can lose the lock.

    A sibling's long RPC and a resident that must be spawned look identical
    from here, and the second attempt tells them apart at the cost of one
    round trip.
    """

    remaining: list[float] = []
    monkeypatch.setattr(native_context, "native_runtime_status", lambda: _status())
    monkeypatch.setattr(native_context, "ensure_resident_prerequisite", lambda _home: True)
    monkeypatch.setattr(native_context, "_isolated_environment", lambda: {})
    monkeypatch.setattr(native_context, "native_resident_client_ready", lambda _executable, _home: True)
    monkeypatch.setattr(native_context, "native_resident_client_failure_code", lambda: "native_client_timed_out")
    outcomes: list[bytes | None] = [None]

    def _client(*_args: object, **kwargs: object) -> bytes | None:
        envelope = json.loads(kwargs["payload"])
        remaining.append((kwargs["deadline_monotonic"] - time.monotonic()) * 1_000)
        return outcomes.pop(0) if outcomes else _ok_result(envelope["request"])

    monkeypatch.setattr(native_context, "native_resident_client_request", _client)
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    assert native_context.native_context_digest("launch_argv_digest", {"argv": ["a"]}, guard_home=guard_home)
    assert native_context._DIGEST_ATTEMPTS == 2
    assert len(remaining) == 2
    # The retry is the last word, so it carries more than the bare timeout.
    assert remaining[0] < 1_500
    retry_ms = native_context._RETRY_ALLOWANCE_MULTIPLIER * int(native_context._COLD_START_ALLOWANCE_SECONDS * 1_000)
    assert remaining[1] > retry_ms - 500


def test_native_context_digest_retries_a_timeout_that_already_had_the_allowance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A contended cold start must be retried, not trusted to a single allowance.

    The first attempt's allowance covers a spawn that has not finished; the
    second attempt finds the process resident and its binary in page cache, so
    a timeout there is evidence of contention rather than of a dead runtime.
    """

    remaining: list[float] = []
    monkeypatch.setattr(native_context, "native_runtime_status", lambda: _status())
    monkeypatch.setattr(native_context, "ensure_resident_prerequisite", lambda _home: True)
    monkeypatch.setattr(native_context, "_isolated_environment", lambda: {})
    monkeypatch.setattr(native_context, "native_resident_client_ready", lambda _executable, _home: False)
    monkeypatch.setattr(native_context, "native_resident_client_failure_code", lambda: "native_client_timed_out")
    outcomes: list[bytes | None] = [None]

    def _client(*_args: object, **kwargs: object) -> bytes | None:
        envelope = json.loads(kwargs["payload"])
        remaining.append((kwargs["deadline_monotonic"] - time.monotonic()) * 1_000)
        return outcomes.pop(0) if outcomes else _ok_result(envelope["request"])

    monkeypatch.setattr(native_context, "native_resident_client_request", _client)
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    assert native_context.native_context_digest("launch_argv_digest", {"argv": ["a"]}, guard_home=guard_home)
    allowance_ms = int(native_context._COLD_START_ALLOWANCE_SECONDS * 1_000)
    assert len(remaining) == 2
    assert remaining[0] > allowance_ms - 500
    assert remaining[1] > allowance_ms - 500


def test_native_context_digest_does_not_retry_other_failures(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A failure more time cannot fix must fail once, not twice."""

    calls: list[int] = []
    monkeypatch.setattr(native_context, "native_runtime_status", lambda: _status())
    monkeypatch.setattr(native_context, "ensure_resident_prerequisite", lambda _home: True)
    monkeypatch.setattr(native_context, "_isolated_environment", lambda: {})
    monkeypatch.setattr(native_context, "native_resident_client_ready", lambda _executable, _home: True)
    monkeypatch.setattr(native_context, "native_resident_client_failure_code", lambda: "native_client_exit_nonzero")
    monkeypatch.setattr(native_context, "native_resident_client_request", lambda **_kwargs: calls.append(1))
    monkeypatch.setattr(
        native_context,
        "native_record_resident_failure",
        lambda *_args, **_kwargs: None,
    )
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    assert native_context.native_context_digest("launch_argv_digest", {"argv": ["a"]}, guard_home=guard_home) is None
    assert len(calls) == 1


def _stub_digest_client(
    monkeypatch: pytest.MonkeyPatch,
    *,
    transport: object,
) -> None:
    monkeypatch.setattr(native_context, "native_runtime_status", lambda: _status())
    monkeypatch.setattr(native_context, "ensure_resident_prerequisite", lambda _home: True)
    monkeypatch.setattr(native_context, "_isolated_environment", lambda: {})
    monkeypatch.setattr(native_context, "native_resident_client_ready", lambda _executable, _home: True)
    monkeypatch.setattr(native_context, "native_resident_client_failure_code", lambda: None)
    monkeypatch.setattr(native_context, "native_record_resident_failure", lambda *_a, **_k: None)
    monkeypatch.setattr(native_context, "native_resident_client_request", transport)


def test_native_context_digest_retries_a_resident_deadline_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The resident's own deadline code is "not enough time", so it is retried.

    The resident reports `native_client_deadline_exceeded` when it begins
    serving after the budget the request carried has lapsed — a contended
    runner, not a missing runtime.
    """

    remaining: list[float] = []
    outcomes: list[bytes | None] = [None]
    monkeypatch.setattr(native_context, "native_runtime_status", lambda: _status())
    monkeypatch.setattr(native_context, "ensure_resident_prerequisite", lambda _home: True)
    monkeypatch.setattr(native_context, "_isolated_environment", lambda: {})
    monkeypatch.setattr(native_context, "native_resident_client_ready", lambda _executable, _home: True)
    monkeypatch.setattr(
        native_context, "native_resident_client_failure_code", lambda: "native_client_deadline_exceeded"
    )

    def _client(*_args: object, **kwargs: object) -> bytes | None:
        remaining.append((kwargs["deadline_monotonic"] - time.monotonic()) * 1_000)
        return outcomes.pop(0) if outcomes else _ok_result(json.loads(kwargs["payload"])["request"])

    monkeypatch.setattr(native_context, "native_resident_client_request", _client)
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    assert native_context.native_context_digest("launch_argv_digest", {"argv": ["a"]}, guard_home=guard_home)
    assert len(remaining) == 2
    assert remaining[1] > int(native_context._COLD_START_ALLOWANCE_SECONDS * 1_000) - 500


def test_native_context_digest_names_a_non_json_response(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A truncated or non-JSON frame must say so rather than "result_invalid"."""

    _stub_digest_client(monkeypatch, transport=lambda **_kwargs: b"{not json")
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    assert native_context.native_context_digest("launch_argv_digest", {"argv": ["a"]}, guard_home=guard_home) is None
    assert (
        native_context.native_context_failure_reason()
        == "native_context_digest_result_invalid:response_not_json bytes=9"
    )


def test_native_context_digest_names_unexpected_result_keys(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A frame that is not a digest response at all must name its foreign keys."""

    def _transport(*_args: object, **kwargs: object) -> bytes:
        payload = json.loads(_ok_result(json.loads(kwargs["payload"])["request"]))
        payload["kind"] = "policy_snapshot"
        return json.dumps(payload).encode("utf-8")

    _stub_digest_client(monkeypatch, transport=_transport)
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    assert native_context.native_context_digest("launch_argv_digest", {"argv": ["a"]}, guard_home=guard_home) is None
    reason = native_context.native_context_failure_reason() or ""
    assert reason.startswith("native_context_digest_result_invalid:payload_keys_mismatch")
    assert "'kind'" in reason


def test_native_context_digest_reports_a_resident_error_envelope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A refused request must report the resident's code, not "result invalid"."""

    recorded: list[str] = []
    _stub_digest_client(
        monkeypatch,
        transport=lambda **_kwargs: json.dumps(
            {"error": "native_resident_update_in_progress", "retryable": True}
        ).encode("utf-8"),
    )
    monkeypatch.setattr(
        native_context,
        "native_record_resident_failure",
        lambda *_a, reason=None, **_k: recorded.append(str(reason)),
    )
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    assert native_context.native_context_digest("launch_argv_digest", {"argv": ["a"]}, guard_home=guard_home) is None
    assert native_context.native_context_failure_reason() == "native_resident_update_in_progress"
    assert recorded == ["native_resident_update_in_progress"]


def test_native_context_digest_reports_an_unknown_resident_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An error envelope outside the contract must still name its code."""

    _stub_digest_client(
        monkeypatch,
        transport=lambda **_kwargs: json.dumps({"error": "native_wat", "retryable": False}).encode("utf-8"),
    )
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    assert native_context.native_context_digest("launch_argv_digest", {"argv": ["a"]}, guard_home=guard_home) is None
    reason = native_context.native_context_failure_reason() or ""
    assert reason.startswith("native_context_digest_result_invalid:payload_keys_mismatch")
    assert "error='native_wat'" in reason


def test_native_context_digest_names_a_mismatched_request_id(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A response to somebody else's request must be reported as such."""

    def _transport(*_args: object, **kwargs: object) -> bytes:
        payload = json.loads(_ok_result(json.loads(kwargs["payload"])["request"]))
        payload["request_id"] = "0" * 32
        return json.dumps(payload).encode("utf-8")

    _stub_digest_client(monkeypatch, transport=_transport)
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    assert native_context.native_context_digest("launch_argv_digest", {"argv": ["a"]}, guard_home=guard_home) is None
    reason = native_context.native_context_failure_reason() or ""
    assert "payload_header_mismatch" in reason
    assert "id_matches=False" in reason
    assert "sha_matches=True" in reason


def test_unavailable_errors_report_the_transport_reason(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """`*_unavailable` must say *why*: a callers that has no fallback needs the reason."""

    _prime(monkeypatch, status=_status(mode="off"))
    with pytest.raises(ValueError, match=":native_context_digest_unsupported"):
        native_context.context_runtime_launch_identity("python", guard_home=tmp_path)

    _prime(monkeypatch)
    monkeypatch.setattr(native_context, "native_resident_client_request", lambda **_kwargs: None)
    monkeypatch.setattr(native_context, "native_resident_client_failure_code", lambda: "native_client_timed_out")
    with pytest.raises(ValueError, match="native_runtime_launch_identity_unavailable:native_client_timed_out"):
        native_context.context_runtime_launch_identity("python", guard_home=tmp_path)


def test_native_context_digest_happy_path_binds_request(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    captured = _prime(monkeypatch)
    result = native_context.native_context_digest("launch_argv_digest", {"argv": ["hol-guard"]}, guard_home=tmp_path)
    assert result is not None
    assert result["status"] == "ok"
    assert result["digest"] == "00" * 32
    assert len(captured) == 1
    assert captured[0]["schema"] == "guard-context-digest-request.v1"
    assert captured[0]["kind"] == "launch_argv_digest"
    assert captured[0]["argv"] == ["hol-guard"]


def test_native_context_digest_cache_hit_rebinds_request_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured = _prime(monkeypatch)
    first = native_context.native_context_digest("launch_argv_digest", {"argv": ["hol-guard"]}, guard_home=tmp_path)
    second = native_context.native_context_digest("launch_argv_digest", {"argv": ["hol-guard"]}, guard_home=tmp_path)
    assert first is not None and second is not None
    # The second call must hit the cache — no second resident round trip.
    assert len(captured) == 1
    # Cached payloads stay identical, but the returned envelope is rebound to
    # the caller's request rather than echoing the first request's identity.
    assert second["digest"] == first["digest"] == "00" * 32
    assert second["request_id"] != first["request_id"]
    rebound_request = {
        "schema": "guard-context-digest-request.v1",
        "request_id": second["request_id"],
        "kind": "launch_argv_digest",
        "argv": ["hol-guard"],
    }
    assert second["request_sha256"] == _request_sha256(rebound_request)


def test_native_context_digest_symlinked_home_shares_cache_entry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured = _prime(monkeypatch)
    real_home = tmp_path / "real-home"
    real_home.mkdir()
    linked_home = tmp_path / "linked-home"
    linked_home.symlink_to(real_home, target_is_directory=True)
    first = native_context.native_context_digest("launch_argv_digest", {"argv": ["hol-guard"]}, guard_home=real_home)
    second = native_context.native_context_digest("launch_argv_digest", {"argv": ["hol-guard"]}, guard_home=linked_home)
    assert first is not None and second is not None
    assert len(captured) == 1


def test_native_context_digest_transport_failure_returns_none(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _prime(monkeypatch, response=None)
    monkeypatch.setattr(native_context, "native_resident_client_request", lambda **_kwargs: None)
    assert native_context.native_context_digest("launch_argv_digest", {"argv": ["x"]}, guard_home=tmp_path) is None


@pytest.mark.parametrize(
    "mutate",
    [
        lambda request, result: result.update(schema="other"),
        lambda request, result: result.update(request_id="deadbeef"),
        lambda request, result: result.update(request_sha256="00" * 32),
        lambda request, result: result.update(status="ok", code="native_context_values_invalid"),
        lambda request, result: result.update(extra="field"),
        lambda request, result: result.pop("code"),
        lambda request, result: result.update(digest=42),
    ],
    ids=[
        "bad_schema",
        "bad_request_id",
        "bad_request_sha256",
        "status_code_mismatch",
        "unknown_field",
        "missing_code",
        "non_string_optional",
    ],
)
def test_native_context_digest_rejects_unbound_results(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutate: object,
) -> None:
    def _client(*_args: object, **kwargs: object) -> bytes:
        envelope = json.loads(kwargs["payload"])
        request = envelope["request"]
        result: dict[str, object] = json.loads(_ok_result(request))
        assert callable(mutate)
        mutate(request, result)
        return json.dumps(result).encode("utf-8")

    monkeypatch.setattr(native_context, "native_runtime_status", lambda: _status())
    monkeypatch.setattr(native_context, "native_resident_client_request", _client)
    monkeypatch.setattr(native_context, "_isolated_environment", lambda: {})
    assert native_context.native_context_digest("launch_argv_digest", {"argv": ["x"]}, guard_home=tmp_path) is None


def test_native_context_digest_overload_returns_none(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    overloaded = json.dumps({"status": "error", "code": "native_overloaded"}).encode("utf-8")
    _prime(monkeypatch, response=overloaded)
    assert native_context.native_context_digest("launch_argv_digest", {"argv": ["x"]}, guard_home=tmp_path) is None


def test_native_context_digest_surrogate_component_returns_typed_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # POSIX surrogateescape bytes decode to lone surrogates; they pass the
    # JSON-compatibility pre-check (ensure_ascii=True escapes them) but cannot
    # cross the strict wire format.  The adapter must report the typed input
    # boundary — never raise UnicodeEncodeError or report availability loss.
    calls: list[bytes] = []
    _prime(monkeypatch, response=b"{}")

    def _capture(**kwargs: object) -> bytes:
        payload = kwargs["payload"]
        assert isinstance(payload, bytes)
        calls.append(payload)
        return b"{}"

    monkeypatch.setattr(native_context, "native_resident_client_request", _capture)
    result = native_context.native_context_digest(
        "launch_argv_digest",
        {"argv": ["/tmp/\udcff-dir"]},
        guard_home=tmp_path,
    )
    assert result is not None
    assert result["status"] == "error"
    assert result["code"] == "native_context_component_invalid"
    assert calls == []


def test_native_context_digest_ok_result_requires_output_field(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # An `ok` result without the kind's output field is an incomplete result —
    # reject it instead of letting callers index a missing key.
    _prime(monkeypatch)

    def _client(*_args: object, **kwargs: object) -> bytes:
        request = json.loads(kwargs["payload"])["request"]
        return json.dumps(
            {
                "schema": "guard-context-digest-result.v1",
                "request_id": request["request_id"],
                "request_sha256": _request_sha256(request),
                "status": "ok",
                "code": "ok",
            }
        ).encode("utf-8")

    monkeypatch.setattr(native_context, "native_resident_client_request", _client)
    assert native_context.native_context_digest("launch_argv_digest", {"argv": ["x"]}, guard_home=tmp_path) is None


def test_native_context_digest_validate_kind_requires_reason_field(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Validation callers read `validation_reason`; an `ok` result that omits
    # the field entirely would silently decode to "unchanged" — reject it.
    _prime(monkeypatch)

    def _client(*_args: object, **kwargs: object) -> bytes:
        request = json.loads(kwargs["payload"])["request"]
        return json.dumps(
            {
                "schema": "guard-context-digest-result.v1",
                "request_id": request["request_id"],
                "request_sha256": _request_sha256(request),
                "status": "ok",
                "code": "ok",
            }
        ).encode("utf-8")

    monkeypatch.setattr(native_context, "native_resident_client_request", _client)
    fields = {"saved_token": "guard-approval-context:v1:AAAA", "current_token": "guard-approval-context:v1:AAAA"}
    assert native_context.native_context_digest("validate_approval_context_tokens", fields, guard_home=tmp_path) is None


def test_native_context_digest_validate_kind_accepts_null_reason(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # `validation_reason: null` is the legitimate "unchanged" verdict — the
    # key must be present, but null must not be rejected as missing output.
    _prime(monkeypatch)

    def _client(*_args: object, **kwargs: object) -> bytes:
        request = json.loads(kwargs["payload"])["request"]
        return json.dumps(
            {
                "schema": "guard-context-digest-result.v1",
                "request_id": request["request_id"],
                "request_sha256": _request_sha256(request),
                "status": "ok",
                "code": "ok",
                "validation_reason": None,
            }
        ).encode("utf-8")

    monkeypatch.setattr(native_context, "native_resident_client_request", _client)
    fields = {"saved_token": "guard-approval-context:v1:AAAA", "current_token": "guard-approval-context:v1:AAAA"}
    result = native_context.native_context_digest("validate_approval_context_tokens", fields, guard_home=tmp_path)
    assert result is not None and result.get("validation_reason") is None


def test_native_context_digest_propagates_worker_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def _client(*_args: object, **kwargs: object) -> bytes:
        envelope = json.loads(kwargs["payload"])
        request = envelope["request"]
        return json.dumps(
            {
                "schema": "guard-context-digest-result.v1",
                "request_id": request["request_id"],
                "request_sha256": _request_sha256(request),
                "status": "error",
                "code": "native_context_values_invalid",
            }
        ).encode("utf-8")

    monkeypatch.setattr(native_context, "_native_runtime_status_memo", lambda: _status())
    monkeypatch.setattr(native_context, "native_resident_client_request", _client)
    monkeypatch.setattr(native_context, "_isolated_environment", lambda: {})
    result = native_context.native_context_digest("launch_argv_digest", {"argv": [42]}, guard_home=tmp_path)
    assert result is not None
    assert result["status"] == "error"
    assert result["code"] == "native_context_values_invalid"


def test_bound_context_digest_home_round_trip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The suite-wide ambient fixture replaces the getter; restore the real
    # ContextVar-driven implementation to exercise it directly.
    monkeypatch.setattr(
        native_context,
        "context_digest_guard_home",
        native_context._BOUND_GUARD_HOME.get,
    )
    # Enforcement binds intentionally persist for the context's lifetime —
    # clear any residue bound by earlier tests in this shared process.
    native_context._BOUND_GUARD_HOME.set(None)
    home = Path("/bound/home")
    token = native_context.bind_context_digest_home(home)
    try:
        assert native_context.context_digest_guard_home() == home
        with native_context.bound_context_digest_home(Path("/inner")):
            assert native_context.context_digest_guard_home() == Path("/inner")
        assert native_context.context_digest_guard_home() == home
    finally:
        native_context.reset_context_digest_home(token)
    assert native_context.context_digest_guard_home() is None


def _forked_bind_probe(guard_home: str, queue: multiprocessing.queues.Queue) -> None:
    native_context.bind_context_digest_home(Path(guard_home))
    queue.put("bound")


def test_bind_context_digest_home_does_not_inherit_held_lock_across_fork(tmp_path: Path) -> None:
    # Forked enforcement children (e.g. the guard protect subprocess spawned
    # while a publisher thread is mid-bind) inherit module locks in whatever
    # state the parent's threads left them.  A lock held by a thread that does
    # not exist in the child can never be released; the at-fork reset must
    # rebuild it so the child's bind completes instead of deadlocking.
    fork = multiprocessing.get_context("fork") if "fork" in multiprocessing.get_all_start_methods() else None
    if fork is None:
        pytest.skip("fork start method unavailable on this platform")

    results: multiprocessing.queues.Queue = fork.Queue()
    child = fork.Process(target=_forked_bind_probe, args=(str(tmp_path), results))
    native_context._LAST_BOUND_LOCK.acquire()
    try:
        child.start()
    finally:
        native_context._LAST_BOUND_LOCK.release()
    child.join(timeout=15)
    if child.exitcode is None:
        child.terminate()
        child.join(timeout=5)
    assert child.exitcode == 0
    assert results.get(timeout=1) == "bound"


def test_native_runtime_status_memo_shares_one_probe_within_ttl(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # A digest burst (environment_material hashes one value per env var) must
    # not re-probe the runtime status per digest — memoize the snapshot so the
    # burst shares one binary validation.  The status must point at a real
    # on-disk binary so the per-read (size, mtime_ns) freshness check passes.
    native_context._status_memo = None
    calls = []
    binary = tmp_path / "hol-guard-runtime"
    binary.write_bytes(b"stable-binary")
    st = binary.stat()
    status = NativeRuntimeStatus(
        mode="force",
        available=True,
        compatible=True,
        reason="ok",
        identity=NativeRuntimeIdentity(path=binary, size=st.st_size, mtime_ns=st.st_mtime_ns, sha256="ab" * 32),
        capabilities=NativeRuntimeCapabilities(
            protocol_version=2,
            runtime_version="0.0.0",
            rule_digest="cd" * 32,
            build_sha="ef" * 32,
            target="test",
            features=_FEATURES,
        ),
    )

    def _probe() -> NativeRuntimeStatus:
        calls.append(1)
        return status

    monkeypatch.setattr(native_context, "native_runtime_status", _probe)
    first = native_context._native_runtime_status_memo()
    second = native_context._native_runtime_status_memo()
    assert first is status
    assert second is status
    assert len(calls) == 1


def test_native_runtime_status_memo_reprobes_when_probe_replaced(monkeypatch: pytest.MonkeyPatch) -> None:
    # A monkeypatched ``native_runtime_status`` has a different callable
    # identity, so a memoized snapshot from the prior probe must not mask it —
    # each new probe gets a fresh call within its own TTL.
    native_context._status_memo = None
    first_status = _status()
    monkeypatch.setattr(native_context, "native_runtime_status", lambda: first_status)
    assert native_context._native_runtime_status_memo() is first_status

    second_status = _status(mode="off", available=False)
    monkeypatch.setattr(native_context, "native_runtime_status", lambda: second_status)
    assert native_context._native_runtime_status_memo() is second_status


def test_native_runtime_status_memo_reprobes_when_binary_swapped(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # A binary replaced inside the TTL must not keep the stale status — the
    # memo re-validates on (size, mtime_ns) change instead of trusting the
    # previously-checked path.
    binary = tmp_path / "hol-guard-runtime"
    binary.write_bytes(b"old-binary")
    stat = binary.stat()
    identity = NativeRuntimeIdentity(
        path=binary,
        size=stat.st_size,
        mtime_ns=stat.st_mtime_ns,
        sha256="ab" * 32,
    )
    capabilities = NativeRuntimeCapabilities(
        protocol_version=2,
        runtime_version="0.0.0",
        rule_digest="cd" * 32,
        build_sha="ef" * 32,
        target="test",
        features=_FEATURES,
    )
    first_status = NativeRuntimeStatus(
        mode="force",
        available=True,
        compatible=True,
        reason="ok",
        identity=identity,
        capabilities=capabilities,
    )
    second_status = NativeRuntimeStatus(
        mode="force",
        available=True,
        compatible=True,
        reason="ok",
        identity=None,
        capabilities=None,
    )
    statuses = iter([first_status, second_status])
    calls = []

    def _probe() -> NativeRuntimeStatus:
        calls.append(1)
        return next(statuses)

    monkeypatch.setattr(native_context, "native_runtime_status", _probe)
    native_context._status_memo = None
    assert native_context._native_runtime_status_memo() is first_status

    # Swap the binary: new bytes => different size + mtime_ns.
    binary.write_bytes(b"replaced-binary-longer-content")
    os.utime(binary, ns=(stat.st_atime_ns + 1_000_000, stat.st_mtime_ns + 1_000_000))
    assert native_context._native_runtime_status_memo() is second_status
    assert len(calls) == 2

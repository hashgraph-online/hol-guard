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

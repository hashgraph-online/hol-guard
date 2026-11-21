"""Contained content decode: the worker end to end and fail-closed binding.

End-to-end cases spawn the compiled ``hol-guard-runtime content-decode
--stdin`` worker through the test client in ``content_decode_support``. Fault injection replaces the
bounded process runner or the native transport; it never reaches into coding
semantics, which only the Rust worker owns.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
import socket
import subprocess
import sys
import threading
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard.codex_hook_launch_runtime import BoundedHookProcessResult
from codex_plugin_scanner.guard.store_base import _acquire_advisory_file_lock
from tests import content_decode_support as client

_CORPUS = Path(__file__).resolve().parents[1] / "rust/crates/guard-archive/tests/fixtures/content-coding"
_PLAIN = (_CORPUS / "plain.txt").read_bytes()
_PLAIN_BR = (_CORPUS / "plain.txt.br").read_bytes()
_PLAIN_GZ_BR = (_CORPUS / "plain.txt.gz.br").read_bytes()
_ZEROS_BOMB_BR = (_CORPUS / "zeros-64m.br").read_bytes()
_RUNTIME_SHA = "b" * 64
_CANARY = "guard-content-canary-7f3a9c"
_unix_only = pytest.mark.skipif(not sys.platform.startswith(("darwin", "linux")), reason="unix containment only")


@pytest.fixture
def state_dir(tmp_path: Path) -> Path:
    return tmp_path / "guard-home"


def _decode(raw: bytes, codings: list[str], state_dir: Path, **kwargs: Any) -> client.ManagedContentResult:
    # The debug runtime hashes its own image for identity binding; give it
    # headroom rather than testing latency here.
    kwargs.setdefault("timeout_seconds", 10.0)
    return client.decode_content_native(raw, codings, state_dir=state_dir, **kwargs)


# --- adapter binding (fake worker) -------------------------------------------


def _fake_status(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, features: set[str] | None = None) -> None:
    status = SimpleNamespace(
        available=True,
        compatible=True,
        identity=SimpleNamespace(path=tmp_path / "runtime", sha256=_RUNTIME_SHA),
        capabilities=SimpleNamespace(features={"content-decode-v1"} if features is None else features),
    )
    monkeypatch.setattr(client, "native_runtime_status", lambda **_kw: status)


def _fake_worker(
    monkeypatch: pytest.MonkeyPatch, reply: Any, *, returncode: int = 0, mutate: str = ""
) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []

    def runner(command: list[str], **kwargs: Any) -> BoundedHookProcessResult:
        request = json.loads(kwargs["input_text"])
        calls.append({"command": command, "request": request, **kwargs})
        payload = reply(request) if callable(reply) else dict(reply)
        payload.setdefault("schema", "guard-content-decode-result.v1")
        payload.setdefault("request_id", request["request_id"])
        payload.setdefault("request_sha256", hashlib.sha256(kwargs["input_text"].encode()).hexdigest())
        payload.setdefault("runtime_sha256", _RUNTIME_SHA)
        if mutate == "request_id":
            payload["request_id"] = "0" * 32
        if mutate == "request_sha256":
            payload["request_sha256"] = "0" * 64
        if mutate == "runtime_sha256":
            payload["runtime_sha256"] = "c" * 64
        if mutate == "schema":
            payload["schema"] = "guard-content-decode-result.v0"
        if mutate == "extra":
            payload["destination"] = "https://collector.example.test/"
        return BoundedHookProcessResult(returncode, json.dumps(payload), False, False)

    monkeypatch.setattr(client, "run_isolated_hook_process", runner)
    return calls


def _counters(**values: int) -> dict[str, int]:
    return {"decoder_calls": 0, "input_bytes": 0, "output_bytes": 0, "layers": 0, "elapsed_ms": 1, **values}


def _decoded(body: bytes, **overrides: Any) -> dict[str, Any]:
    return {
        "status": "decoded",
        "code": "content_decoded",
        "message": "The response body was decoded.",
        "body_base64": base64.b64encode(body).decode(),
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "counters": _counters(decoder_calls=1, input_bytes=10, output_bytes=len(body), layers=1),
        **overrides,
    }


def test_worker_gets_no_destination_credentials_or_caller_environment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, state_dir: Path
) -> None:
    _fake_status(monkeypatch, tmp_path)
    calls = _fake_worker(monkeypatch, _decoded(b"plain"))
    monkeypatch.setenv("GUARD_CANARY_TOKEN", _CANARY)
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")

    result = _decode(b"raw", ["br"], state_dir)

    assert result.status == "decoded"
    assert result.body == b"plain"
    (call,) = calls
    assert call["command"][1:] == ["content-decode", "--stdin"]
    assert call["parent_liveness"] is True
    assert set(call["environment"]) <= {"LC_ALL", "SYSTEMROOT", "WINDIR"}
    assert set(call["request"]) == {
        "schema",
        "request_id",
        "content_encoding",
        "body_base64",
        "state_dir",
        "timeout_ms",
        "caps",
    }
    assert _CANARY not in call["input_text"]
    assert call["request"]["content_encoding"] == ["br"]
    assert base64.b64decode(call["request"]["body_base64"]) == b"raw"


@pytest.mark.parametrize("mutate", ["request_id", "request_sha256", "runtime_sha256", "schema", "extra"])
def test_unbound_worker_results_fail_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, state_dir: Path, mutate: str
) -> None:
    _fake_status(monkeypatch, tmp_path)
    _fake_worker(monkeypatch, _decoded(b"plain"), mutate=mutate)

    result = _decode(b"raw", ["br"], state_dir)

    assert (result.status, result.code, result.body) == ("incomplete", "content_decode_incomplete", None)


@pytest.mark.parametrize(
    "reply",
    [
        _decoded(b"plain", body_sha256="0" * 64),
        _decoded(b"plain", counters=_counters(decoder_calls=1, output_bytes=99)),
        _decoded(b"plain", body_base64="not base64!"),
        {**_decoded(b"plain"), "status": "rejected", "code": "content_coding_unsupported"},
        {k: v for k, v in _decoded(b"plain").items() if k != "body_sha256"},
        {"status": "decoded", "code": "content_decoded", "message": "m", "counters": _counters()},
        {"status": "rejected", "code": "content_coding_unsupported", "message": "m", "counters": {"layers": 0}},
        {"status": "allowed", "code": "x", "message": "m", "counters": _counters()},
        {**_decoded(b"plain"), "status": ["decoded"]},
    ],
)
def test_tampered_bodies_and_shapes_are_never_returned(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, state_dir: Path, reply: dict[str, Any]
) -> None:
    _fake_status(monkeypatch, tmp_path)
    _fake_worker(monkeypatch, reply)

    result = _decode(b"raw", ["br"], state_dir, max_output_bytes=64)

    assert result.status == "incomplete"
    assert result.body is None


def test_output_over_the_callers_cap_is_never_returned(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, state_dir: Path
) -> None:
    _fake_status(monkeypatch, tmp_path)
    _fake_worker(monkeypatch, _decoded(b"x" * 65))

    assert _decode(b"raw", ["br"], state_dir, max_output_bytes=64).body is None


def test_containment_unavailable_is_reported_honestly(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, state_dir: Path
) -> None:
    """A platform without proven containment gets a typed incomplete result,
    never a decode in an uncontained process and never the raw body."""
    _fake_status(monkeypatch, tmp_path)
    _fake_worker(
        monkeypatch,
        {
            "status": "incomplete",
            "code": "content_containment_unavailable",
            "message": "Contained content decoding is unavailable on this platform.",
            "counters": _counters(input_bytes=3),
        },
    )

    result = _decode(b"raw", ["br"], state_dir)

    assert (result.status, result.code, result.body) == ("incomplete", "content_containment_unavailable", None)
    assert result.counters is not None and result.counters.decoder_calls == 0


@pytest.mark.parametrize(
    "process",
    [
        BoundedHookProcessResult(None, "", False, True),
        BoundedHookProcessResult(3, "", False, False),
        BoundedHookProcessResult(0, "{}", True, False),
        BoundedHookProcessResult(0, "{}", False, False, containment_failed=True),
        BoundedHookProcessResult(0, "not json", False, False),
    ],
)
def test_worker_process_faults_fail_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, state_dir: Path, process: BoundedHookProcessResult
) -> None:
    _fake_status(monkeypatch, tmp_path)
    monkeypatch.setattr(client, "run_isolated_hook_process", lambda *_a, **_kw: process)

    result = _decode(b"raw", ["br"], state_dir)

    assert result.status == "incomplete"
    assert result.body is None


def test_missing_native_feature_has_no_python_decode_fallback(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, state_dir: Path
) -> None:
    _fake_status(monkeypatch, tmp_path, features={"archive-inspection-v1"})
    monkeypatch.setattr(client, "run_isolated_hook_process", pytest.fail)

    result = _decode(_PLAIN_BR, ["br"], state_dir)

    assert (result.status, result.code, result.body) == ("incomplete", "content_decode_native_unavailable", None)


def test_oversized_raw_bodies_never_reach_the_worker(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, state_dir: Path
) -> None:
    _fake_status(monkeypatch, tmp_path)
    monkeypatch.setattr(client, "run_isolated_hook_process", pytest.fail)

    result = _decode(b"x" * 11, ["br"], state_dir, max_input_bytes=10)

    assert (result.status, result.code) == ("rejected", "content_input_too_large")


@pytest.mark.parametrize(
    "kwargs",
    [
        {"timeout_seconds": 0},
        {"timeout_seconds": float("nan")},
        {"max_input_bytes": 3 * 1024 * 1024 + 1},
        {"max_output_bytes": 0},
        {"max_layers": 0},
    ],
)
def test_invalid_policies_are_refused_before_any_spawn(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, state_dir: Path, kwargs: dict[str, Any]
) -> None:
    _fake_status(monkeypatch, tmp_path)
    monkeypatch.setattr(client, "run_isolated_hook_process", pytest.fail)

    result = client.decode_content_native(b"raw", ["br"], state_dir=state_dir, **kwargs)

    assert (result.status, result.code) == ("incomplete", "content_decode_policy_invalid")


# --- contained worker, end to end --------------------------------------------


@_unix_only
def test_runtime_managed_fetch_safe_brotli(native_hook_force: Path, state_dir: Path) -> None:
    result = _decode(_PLAIN_BR, ["br"], state_dir)

    assert result.status == "decoded"
    assert result.body == _PLAIN
    assert result.counters is not None and result.counters.decoder_calls == 1

    stacked = _decode(_PLAIN_GZ_BR, ["gzip", "br"], state_dir)
    assert stacked.body == _PLAIN
    assert stacked.counters is not None and stacked.counters.layers == 2


@_unix_only
@pytest.mark.parametrize(
    ("codings", "code"),
    [
        (["zstd"], "content_coding_unsupported"),
        (["br;q=1"], "content_coding_unsupported"),
        (["gzip", "dcb"], "content_coding_unsupported"),
        (["gzip, gzip, br"], "content_coding_too_deep"),
    ],
)
def test_runtime_managed_fetch_rejects_before_decode(
    native_hook_force: Path, state_dir: Path, codings: list[str], code: str
) -> None:
    result = _decode(_PLAIN_BR, codings, state_dir)

    assert (result.status, result.code, result.body) == ("rejected", code, None)
    assert result.counters is not None and result.counters.decoder_calls == 0


@_unix_only
def test_runtime_managed_fetch_resource_bounds(native_hook_force: Path, state_dir: Path) -> None:
    """A 106-byte brotli stream that expands to 64 MiB stops at a cap and
    returns no partial body."""
    by_ratio = _decode(_ZEROS_BOMB_BR, ["br"], state_dir, max_ratio=200)
    by_size = _decode(_ZEROS_BOMB_BR, ["br"], state_dir, max_output_bytes=32 * 1024)
    malformed = _decode(_PLAIN_BR[: len(_PLAIN_BR) // 2], ["br"], state_dir)

    assert (by_ratio.status, by_ratio.code, by_ratio.body) == ("rejected", "content_ratio_exceeded", None)
    assert (by_size.status, by_size.code, by_size.body) == ("rejected", "content_output_too_large", None)
    assert (malformed.status, malformed.code, malformed.body) == ("rejected", "content_coding_malformed", None)


@_unix_only
def test_identity_bodies_pass_through_without_a_decoder(native_hook_force: Path, state_dir: Path) -> None:
    result = _decode(b"plain body", ["identity"], state_dir)

    assert result.body == b"plain body"
    assert result.counters is not None and result.counters.decoder_calls == 0


@_unix_only
def test_a_body_exactly_at_the_raw_cap_reaches_the_worker(native_hook_force: Path, state_dir: Path) -> None:
    body = b"a" * client.MANAGED_CONTENT_MAX_RAW_BYTES

    result = _decode(body, [], state_dir)

    assert (result.status, result.code) == ("decoded", "content_decoded")
    assert result.body == body


@_unix_only
def test_identity_bodies_are_held_to_the_output_cap(native_hook_force: Path, state_dir: Path) -> None:
    result = _decode(b"plain body", [], state_dir, max_output_bytes=4)

    assert (result.status, result.code, result.body) == ("rejected", "content_output_too_large", None)
    assert result.counters is not None and result.counters.decoder_calls == 0


@_unix_only
def test_held_lease_is_a_bounded_overload(native_hook_force: Path, state_dir: Path) -> None:
    state_dir.mkdir(parents=True, exist_ok=True)
    holder = (state_dir / "archive-inspect.lock").open("a+b")
    try:
        _acquire_advisory_file_lock(holder)
        result = _decode(_PLAIN_BR, ["br"], state_dir)
    finally:
        holder.close()

    assert (result.status, result.code, result.body) == ("incomplete", "content_decode_overloaded", None)


@pytest.fixture
def collector() -> Iterator[dict[str, Any]]:
    """A loopback listener standing in for an attacker's collector."""
    seen: dict[str, Any] = {"connections": 0, "bytes": b""}
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen()
    server.settimeout(0.2)
    stop = threading.Event()

    def accept() -> None:
        while not stop.is_set():
            try:
                connection, _ = server.accept()
            except OSError:
                continue
            seen["connections"] += 1
            with connection:
                connection.settimeout(0.5)
                with contextlib.suppress(OSError):
                    seen["bytes"] += connection.recv(65536)

    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    seen["url"] = f"http://127.0.0.1:{server.getsockname()[1]}"
    try:
        yield seen
    finally:
        stop.set()
        thread.join(timeout=2)
        server.close()


@_unix_only
def test_runtime_contained_worker_no_secret_egress(
    native_hook_force: Path, state_dir: Path, collector: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Secrets and proxy settings in the caller's environment never reach the
    collector: the adapter strips them, and the worker run directly with them
    present is still denied the network."""
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy"):
        monkeypatch.setenv(key, collector["url"])
    monkeypatch.setenv("GUARD_CANARY_TOKEN", _CANARY)

    via_adapter = _decode(_PLAIN_BR, ["br"], state_dir)

    request = json.dumps(
        {
            "schema": "guard-content-decode.v1",
            "request_id": "0" * 32,
            "content_encoding": ["br"],
            "body_base64": base64.b64encode(_PLAIN_BR).decode(),
            "state_dir": str(state_dir.resolve()),
            "timeout_ms": 10_000,
            "caps": {
                "max_input_bytes": 1024 * 1024,
                "max_output_bytes": 1024 * 1024,
                "max_ratio": 200,
                "max_layers": 2,
                "max_memory_bytes": 512 * 1024 * 1024,
            },
        }
    ).encode()
    direct = subprocess.run(
        [str(native_hook_force), "content-decode", "--stdin"],
        input=request,
        capture_output=True,
        check=False,
        timeout=20,
        env=dict(os.environ),
    )

    assert via_adapter.body == _PLAIN
    assert direct.returncode == 0
    assert base64.b64decode(json.loads(direct.stdout)["body_base64"]) == _PLAIN
    assert _CANARY.encode() not in direct.stdout + direct.stderr
    assert collector["connections"] == 0
    assert collector["bytes"] == b""

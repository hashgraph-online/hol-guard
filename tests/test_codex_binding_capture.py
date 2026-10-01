"""Bounded, opt-in Codex ingress to native-edge receipt diagnostics."""

from __future__ import annotations

import builtins
import json
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.codex_binding_capture import (
    CAPTURE_OUTPUT_PREFIX,
    CAPTURE_OUTPUT_SUFFIX,
    record_bridge_ingress,
    record_native_worker,
)
from codex_plugin_scanner.guard.codex_binding_capture_crypto import (
    open_receipt,
    payload_hmac,
)
from tests.codex_binding_capture_support import (
    _capture_pair,
    _enable_capture,
    _output_path,
    _rows,
    _session,
    _valid_native_receipt,
)


def test_missing_aesgcm_backend_fails_closed_at_seal_and_open_boundaries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seal_home = tmp_path / "seal"
    seal_directory = _enable_capture(seal_home)
    existing_home, existing_rows = _capture_pair(tmp_path / "open")
    payload = {"hook_event_name": "PreToolUse", "tool_use_id": "call-backend"}
    real_import = builtins.__import__

    def missing_backend(
        name: str,
        globals_arg: object = None,
        locals_arg: object = None,
        fromlist: object = (),
        level: int = 0,
    ) -> object:
        if name == "cryptography.hazmat.primitives.ciphers.aead":
            raise ImportError("injected missing AESGCM backend")
        return real_import(name, globals_arg, locals_arg, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", missing_backend)
    assert not record_native_worker(
        guard_home=seal_home,
        payload=payload,
        harness="codex",
        event_name="PreToolUse",
        receipt=_valid_native_receipt(),
    )
    assert not (seal_directory / f"{CAPTURE_OUTPUT_PREFIX}run-1{CAPTURE_OUTPUT_SUFFIX}").exists()
    open_session = _session(existing_home)
    sealed = cast(dict[str, object], existing_rows[1]["sealed_receipt"])
    assert open_receipt(open_session, existing_rows[1], sealed) is None


def test_documented_tool_use_id_is_captured(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    directory = _enable_capture(guard_home)
    raw = json.dumps({"hook_event_name": "PreToolUse", "tool_use_id": "call-use"})
    assert record_bridge_ingress(guard_home=guard_home, raw_payload=raw, event_name="PreToolUse")
    row = _rows(directory)[0]
    assert row["tool_use_id_state"] == "present"
    assert row["tool_use_id"] == "call-use"


def test_bridge_capture_happens_before_forwarded_transport_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_plugin_scanner.guard.adapters import codex_daemon_hook_bridge as bridge

    guard_home = tmp_path / "guard-home"
    directory = _enable_capture(guard_home)
    raw = '{"hook_event_name":"PreToolUse","tool_use_id":"call-early"}'
    monkeypatch.setattr(bridge, "_hook_input", lambda _limit: raw)
    monkeypatch.setattr(
        bridge,
        "_with_browser_wait_process",
        lambda data, *, wait_timeout_seconds: data[:-1] + ',"transport_added":true}',
    )

    bound = bridge._bound_hook_input(
        {"PreToolUse": 10},
        capture_guard_home=guard_home,
    )
    assert bound is not None
    event_name, forwarded, _timeout, _input_ready_at = bound

    assert event_name == "PreToolUse"
    assert json.loads(forwarded)["transport_added"] is True
    row = _rows(directory)[0]
    session = _session(guard_home)
    assert row["raw_payload_hmac_sha256"] == payload_hmac(
        session,
        "raw",
        {"hook_event_name": "PreToolUse", "tool_use_id": "call-early"},
    )
    assert row["forwarded_payload_hmac_sha256"] == payload_hmac(session, "forwarded", json.loads(forwarded))


@pytest.mark.parametrize("harness", ["claude-code", "pi"])
def test_native_worker_capture_is_codex_only(tmp_path: Path, harness: str) -> None:
    guard_home = tmp_path / harness
    directory = _enable_capture(guard_home)
    assert not record_native_worker(
        guard_home=guard_home,
        payload={"hook_event_name": "PreToolUse", "tool_use_id": "call-foreign"},
        harness=harness,
        event_name="PreToolUse",
        receipt=_valid_native_receipt(),
    )
    assert not _output_path(directory).exists()


def test_capture_latency_does_not_extend_bridge_deadline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from codex_plugin_scanner.guard.adapters import codex_daemon_hook_bridge as bridge

    clock = [100.0]
    captured: dict[str, object] = {}
    raw = '{"hook_event_name":"PreToolUse","tool_use_id":"call-deadline"}'
    monkeypatch.setattr(bridge.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(bridge, "_hook_input", lambda _limit: raw)
    monkeypatch.setattr(bridge, "_with_browser_wait_process", lambda data, *, wait_timeout_seconds: data)

    def slow_capture(**_kwargs: object) -> bool:
        clock[0] += 3.0
        return True

    monkeypatch.setattr(bridge, "record_bridge_ingress", slow_capture)

    def review(**kwargs: object) -> tuple[dict[str, object], bool, bool]:
        captured.update(kwargs)
        return {"continue": True}, False, False

    monkeypatch.setattr(bridge, "bridge_review_response", review)
    monkeypatch.setattr(bridge, "_bridge_output", lambda *_args, **_kwargs: "{}")

    assert (
        bridge.main(
            state_path=tmp_path / "guard-home" / "daemon-state.json",
            fallback_command=("fallback",),
            start_command=("start",),
            query="",
            hook_timeouts={"PreToolUse": 10},
        )
        == 0
    )
    assert captured["deadline"] == 108.0
    assert capsys.readouterr().out == "{}"

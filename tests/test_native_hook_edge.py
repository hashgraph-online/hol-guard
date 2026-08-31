from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_command_model
from codex_plugin_scanner.guard.codex_hook_launch_runtime import BoundedHookProcessResult
from codex_plugin_scanner.guard.native_hook_edge import _decode_edge, review_raw_hook_native
from codex_plugin_scanner.guard.native_resident_client import (
    native_resident_client_failure_code,
    native_resident_client_request,
)
from codex_plugin_scanner.guard.native_runtime import (
    NativeRuntimeCapabilities,
    NativeRuntimeIdentity,
    NativeRuntimeStatus,
)


def _edge_result() -> dict[str, object]:
    return {
        "schema": "guard-hook-edge-result.v2",
        "authority": "rust",
        "harness": "claude-code",
        "event_name": "PreToolUse",
        "payload_kind": "inline",
        "result": {"minimum_action": "allow"},
    }


def test_edge_decoder_accepts_omitted_optional_request_id() -> None:
    assert _decode_edge(_edge_result()) == _edge_result()
    with_extra = _edge_result()
    with_extra["semantic_override"] = "allow"
    assert _decode_edge(with_extra) is None


def test_python_launcher_only_invokes_package_bound_native_client(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "hol-guard-runtime"
    executable.write_bytes(b"runtime")
    captured: dict[str, object] = {}

    def fake_run(command: tuple[str, ...], **kwargs: object) -> BoundedHookProcessResult:
        captured.update(command=tuple(command), **kwargs)
        return BoundedHookProcessResult(0, '{"ok":true}\n', False, False)

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_resident_client.run_isolated_hook_process",
        fake_run,
    )
    result = native_resident_client_request(
        executable=executable,
        guard_home=tmp_path / "guard-home",
        environment={"HOME": str(tmp_path)},
        payload=b"{}",
        timeout_seconds=0.5,
        raw_hook_envelope=True,
    )
    assert result == b'{"ok":true}\n'
    assert captured["command"] == (
        str(executable),
        "hook-client",
        "--stdin",
        str(tmp_path / "guard-home" / "native-runtime"),
    )
    assert captured["input_text"] == "{}"
    assert captured["timeout_seconds"] == 0.5
    assert captured["output_limit"] == 2 * 1024 * 1024
    assert captured["windows_kill_on_job_close"] is False
    assert native_resident_client_failure_code() is None


def test_native_client_forwards_absolute_deadline_without_relative_floor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def fake_run(command: tuple[str, ...], **kwargs: object) -> BoundedHookProcessResult:
        captured.update(command=tuple(command), **kwargs)
        return BoundedHookProcessResult(0, '{"ok":true}\n', False, False)

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_resident_client.run_isolated_hook_process",
        fake_run,
    )
    deadline = time.monotonic() + 0.001
    result = native_resident_client_request(
        executable=tmp_path / "runtime",
        guard_home=tmp_path / "guard-home",
        environment={},
        payload=b"{}",
        deadline_monotonic=deadline,
    )

    assert result == b'{"ok":true}\n'
    assert captured["deadline_monotonic"] == deadline
    assert captured["timeout_seconds"] is None


def test_command_model_budget_is_bound_at_resident_envelope_top_level(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = tmp_path / "runtime"
    runtime.write_bytes(b"runtime")
    identity = NativeRuntimeIdentity(
        path=runtime,
        size=runtime.stat().st_size,
        mtime_ns=runtime.stat().st_mtime_ns,
        sha256="a" * 64,
    )
    capabilities = NativeRuntimeCapabilities(
        protocol_version=1,
        runtime_version="test",
        rule_digest="b" * 64,
        build_sha="c" * 40,
        target="test",
        features=(
            "pre-tool-command-model-shadow-v1",
            "resident-command-model-shadow-v1",
            "resident-protocol-v2",
        ),
    )
    monkeypatch.setattr(
        native_command_model,
        "native_runtime_status",
        lambda: NativeRuntimeStatus(
            mode="shadow",
            available=True,
            compatible=True,
            reason="ready",
            identity=identity,
            capabilities=capabilities,
        ),
    )
    captured: dict[str, object] = {}

    def fake_client(**kwargs: object) -> bytes:
        captured.update(kwargs)
        return b"{}"

    monkeypatch.setattr(native_command_model, "native_resident_client_request", fake_client)
    monkeypatch.setattr(
        native_command_model,
        "_decode_command_model",
        lambda *_args, **_kwargs: {"confidence": "exact"},
    )

    result = native_command_model.review_command_model_native(
        "git status",
        guard_home=tmp_path / "guard-home",
        timeout_seconds=0.25,
    )

    assert result == {"confidence": "exact"}
    encoded = captured["payload"]
    assert isinstance(encoded, bytes)
    envelope = json.loads(encoded)
    assert envelope["deadline_budget_ms"] == 250
    assert "deadline_monotonic" in captured
    assert "timeout_seconds" not in captured


def test_native_client_records_only_allowlisted_failure_code(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_resident_client.run_isolated_hook_process",
        lambda *_args, **_kwargs: BoundedHookProcessResult(
            2,
            "",
            False,
            True,
            containment_failed=True,
            stderr="ignored\nnative_resident_start_timeout\nignored",
        ),
    )
    result = native_resident_client_request(
        executable=tmp_path / "runtime",
        guard_home=tmp_path / "guard-home",
        environment={},
        payload=b"{}",
        timeout_seconds=0.5,
    )
    assert result is None
    assert native_resident_client_failure_code() == "native_resident_start_timeout"


@pytest.mark.parametrize(
    ("process_result", "expected_code"),
    (
        (
            BoundedHookProcessResult(7, "", True, True, containment_failed=True),
            "native_client_containment_failed",
        ),
        (BoundedHookProcessResult(7, "", True, True), "native_client_timed_out"),
        (BoundedHookProcessResult(None, "", True, False), "native_client_output_limit_exceeded"),
        (BoundedHookProcessResult(None, "", False, False), "native_client_status_missing"),
        (BoundedHookProcessResult(7, "", False, False), "native_client_exit_nonzero"),
        (BoundedHookProcessResult(0, "", False, False), "native_client_output_missing"),
    ),
)
def test_native_client_classifies_bounded_failure_states(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    process_result: BoundedHookProcessResult,
    expected_code: str,
) -> None:
    def fake_run(*_args: object, **_kwargs: object) -> BoundedHookProcessResult:
        return process_result

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_resident_client.run_isolated_hook_process",
        fake_run,
    )
    assert (
        native_resident_client_request(
            executable=tmp_path / "runtime",
            guard_home=tmp_path / "guard-home",
            environment={},
            payload=b"{}",
            timeout_seconds=0.5,
        )
        is None
    )
    assert native_resident_client_failure_code() == expected_code


def test_raw_hook_bridge_preserves_payload_for_rust_parsing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = tmp_path / "hol-guard-runtime"
    runtime.write_bytes(b"runtime")
    identity = NativeRuntimeIdentity(
        path=runtime,
        size=runtime.stat().st_size,
        mtime_ns=runtime.stat().st_mtime_ns,
        sha256="a" * 64,
    )
    capabilities = NativeRuntimeCapabilities(
        protocol_version=1,
        runtime_version="test",
        rule_digest="b" * 64,
        build_sha="c" * 40,
        target="test",
        features=("hook-envelope-v2", "native-resident-client-v1"),
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_hook_edge.native_runtime_status",
        lambda: NativeRuntimeStatus(
            mode="auto",
            available=True,
            compatible=True,
            reason="ready",
            identity=identity,
            capabilities=capabilities,
        ),
    )
    captured: dict[str, object] = {}

    def fake_client(**kwargs: object) -> bytes:
        captured.update(kwargs)
        return json.dumps(_edge_result(), separators=(",", ":")).encode()

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_hook_edge.native_resident_client_request",
        fake_client,
    )
    raw_payload: dict[str, object] = {
        "hook_event_name": "PreToolUse",
        "tool_input": {"command": "pwd"},
    }
    result = review_raw_hook_native(
        payload=raw_payload,
        harness="claude",
        event="PreToolUse",
        guard_home=tmp_path,
        home_dir=tmp_path,
        cwd=tmp_path,
        source_ref_external_allowed=False,
        observe_mode=False,
        deadline=None,
    )
    assert result == _edge_result()
    encoded = captured["payload"]
    assert isinstance(encoded, bytes)
    envelope = json.loads(encoded)
    assert envelope["raw_payload"] == raw_payload
    assert envelope["harness"] == "claude"
    assert envelope["event"] == "PreToolUse"
    assert captured["raw_hook_envelope"] is True

    for invalid_value in ({"not", "json"}, float("nan")):
        captured.clear()
        invalid_payload = {**raw_payload, "invalid": invalid_value}
        assert (
            review_raw_hook_native(
                payload=invalid_payload,
                harness="claude",
                event="PreToolUse",
                guard_home=tmp_path,
                home_dir=tmp_path,
                cwd=tmp_path,
                source_ref_external_allowed=False,
                observe_mode=False,
                deadline=None,
            )
            is None
        )
        assert captured == {}

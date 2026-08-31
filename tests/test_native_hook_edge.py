from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.codex_hook_launch_runtime import BoundedHookProcessResult
from codex_plugin_scanner.guard.native_hook_edge import _decode_edge, review_raw_hook_native
from codex_plugin_scanner.guard.native_resident_client import native_resident_client_request
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

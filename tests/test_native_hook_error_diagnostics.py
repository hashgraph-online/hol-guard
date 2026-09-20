"""Error diagnostics cannot reinterpret a failure as an authoritative decision."""

from __future__ import annotations

import json
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_hook_edge
from codex_plugin_scanner.guard.native_approval_errors import NATIVE_COMMAND_CONTROL_ERROR_CODES
from codex_plugin_scanner.guard.native_hook_edge import _decode_edge, _native_error_code
from codex_plugin_scanner.guard.native_resident_client import native_resident_client_failure_code


@pytest.mark.parametrize("retryable", [False, True])
def test_known_native_error_is_diagnostic_only(retryable: bool) -> None:
    payload = {"error": "native_policy_snapshot_not_current", "retryable": retryable}
    assert _native_error_code(payload) == "native_policy_snapshot_not_current"
    assert _decode_edge(payload) is None


def test_command_control_diagnostics_match_exact_rust_error_vocabulary() -> None:
    source = (
        Path(__file__).resolve().parents[1] / "rust/crates/guard-contracts/src/native_command_controls.rs"
    ).read_text(encoding="utf-8")
    declaration = source.split("pub const NATIVE_COMMAND_CONTROL_ERROR_CODES:", 1)[1].split("];", 1)[0]
    assert frozenset(re.findall(r'"([^\"]+)"', declaration)) == NATIVE_COMMAND_CONTROL_ERROR_CODES


@pytest.mark.parametrize("code", sorted(NATIVE_COMMAND_CONTROL_ERROR_CODES))
@pytest.mark.parametrize("retryable", [False, True])
def test_command_control_error_is_reported_without_becoming_a_decision(code: str, retryable: bool) -> None:
    payload = {"error": code, "retryable": retryable}
    assert _native_error_code(payload) == code
    assert _decode_edge(payload) is None


def test_raw_hook_bridge_records_control_fence_rejection_without_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    status = SimpleNamespace(
        mode="auto",
        available=True,
        compatible=True,
        identity=SimpleNamespace(path=tmp_path / "runtime", sha256="a" * 64),
        capabilities=SimpleNamespace(
            features=("hook-envelope-v2", "native-resident-client-v1", "pre-tool-generic-authority-v1")
        ),
    )
    calls: list[dict[str, object]] = []
    code = "native_command_control_mutation_in_progress"

    def request(**kwargs: object) -> bytes:
        calls.append(kwargs)
        return json.dumps({"error": code, "retryable": True}).encode()

    monkeypatch.setattr(native_hook_edge, "native_runtime_status", lambda: status)
    monkeypatch.setattr(native_hook_edge, "native_resident_client_request", request)
    result = native_hook_edge.review_raw_hook_native(
        payload={"tool_name": "Bash", "tool_input": {"command": "fixture"}},
        harness="claude-code",
        event="PreToolUse",
        guard_home=tmp_path,
        home_dir=tmp_path,
        cwd=tmp_path,
        source_ref_external_allowed=False,
        observe_mode=False,
        deadline=12345.0,
        policy_snapshot={"generation": 7},
    )
    assert result is None
    assert native_resident_client_failure_code() == code
    assert len(calls) == 1
    assert calls[0]["deadline_monotonic"] == 12345.0


@pytest.mark.parametrize(
    "payload",
    [
        None,
        [],
        {"error": "untrusted stderr containing a path", "retryable": False},
        {"error": "native_command_control_unknown_arbitrary_suffix", "retryable": False},
        {"error": {"secret": "fixture"}, "retryable": False},
        {"error": "native_policy_snapshot_not_current", "retryable": 1},
        {"error": "native_policy_snapshot_not_current"},
        {"error": "native_policy_snapshot_not_current", "retryable": False, "raw": "fixture"},
    ],
)
def test_unknown_or_malformed_native_errors_are_not_exposed(payload: object) -> None:
    assert _native_error_code(payload) is None
    assert _decode_edge(payload) is None

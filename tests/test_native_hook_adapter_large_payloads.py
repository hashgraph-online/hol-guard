"""Large hook payloads against the compiled resident, for every harness.

The resident always parses the complete payload: nothing it reads is ever
elided. These tests send ~2 MiB+ requests, answers near the 2 MiB response cap,
and requests over the 4 MiB cap, and require exact results or an explicit
fail-closed code.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_hook_adapter as adapter

_VECTORS = Path(__file__).resolve().parents[1] / "rust/crates/guard-command/testdata/hook_adapter_vectors.json"
_MIB = 1024 * 1024


def _first_ok_vector_per_harness() -> list[dict[str, object]]:
    vectors = json.loads(_VECTORS.read_text(encoding="utf-8"))["envelope"]
    chosen: dict[str, dict[str, object]] = {}
    for vector in vectors:
        harness = str(vector["harness"])
        if "ok" in vector["expected"] and harness not in chosen:
            chosen[harness] = vector
    return [chosen[key] for key in sorted(chosen)]


_HARNESS_VECTORS = _first_ok_vector_per_harness()
_IDS = [str(vector["harness"]) for vector in _HARNESS_VECTORS]


def _envelope(vector: dict[str, object], payload: dict[str, object], home: Path) -> dict[str, object]:
    return adapter.native_action_envelope(
        str(vector["harness"]),
        str(vector["event_name"]),
        payload,
        workspace=vector["workspace"],  # type: ignore[arg-type]
        home_dir=vector["home_dir"],  # type: ignore[arg-type]
        guard_home=home,
    )


def test_every_supported_harness_is_covered() -> None:
    assert len(_HARNESS_VECTORS) >= 14


@pytest.mark.parametrize("vector", _HARNESS_VECTORS, ids=_IDS)
def test_large_output_blobs_never_change_the_envelope(
    vector: dict[str, object], native_approval_reuse_runtime: Path
) -> None:
    payload = dict(vector["payload"])  # type: ignore[arg-type]
    expected = _envelope(
        vector, {**payload, "tool_response": "x", "stdout": "x", "output": "x"}, native_approval_reuse_runtime
    )
    big = {
        **payload,
        "tool_response": {"stdout": "t" * (700 * 1024)},
        "stdout": "s" * (700 * 1024),
        "output": ["o" * (700 * 1024)],
    }
    assert _envelope(vector, big, native_approval_reuse_runtime) == expected


@pytest.mark.parametrize("vector", _HARNESS_VECTORS, ids=_IDS)
def test_two_mib_payload_keeps_every_policy_field(
    vector: dict[str, object], native_approval_reuse_runtime: Path
) -> None:
    payload = dict(vector["payload"])  # type: ignore[arg-type]
    expected = vector["expected"]["ok"]  # type: ignore[index]
    padded = {**payload, "padding": [f"{index:03d}" + "z" * 60_000 for index in range(36)]}
    result = _envelope(vector, padded, native_approval_reuse_runtime)
    for key, value in expected.items():  # type: ignore[attr-defined]
        if key not in {"raw_payload_redacted"}:
            assert result[key] == value, key


@pytest.mark.parametrize("vector", _HARNESS_VECTORS, ids=_IDS)
def test_oversize_echoes_round_trip_through_digest_references(
    vector: dict[str, object], native_approval_reuse_runtime: Path
) -> None:
    harness = str(vector["harness"])
    base = {"tool_name": "Write", "tool_input": {"file_path": "a.txt", "content": "c" * (2 * _MIB + 17)}}
    if harness in {"cursor", "cline"}:
        pytest.skip("covered by the host-specific tests below")
    prepared = adapter.native_prepare_payload(harness, base, guard_home=native_approval_reuse_runtime)
    assert prepared["tool_input"]["content"] == base["tool_input"]["content"]  # type: ignore[index]


def test_prepared_answer_near_the_response_cap_round_trips(native_approval_reuse_runtime: Path) -> None:
    payload = {f"k{index}": f"{index:02d}" + "z" * 60_000 for index in range(31)}  # ~1.86 MiB echoed
    assert adapter.native_prepare_payload("codex", payload, guard_home=native_approval_reuse_runtime) == payload
    digested = {f"k{index}": f"{index:02d}" + "z" * 100_000 for index in range(30)}  # 2.9 MiB, digests
    assert adapter.native_prepare_payload("codex", digested, guard_home=native_approval_reuse_runtime) == digested


def test_prepared_answer_over_the_response_cap_fails_closed(native_approval_reuse_runtime: Path) -> None:
    payload = {f"k{index}": f"{index:02d}" + "z" * 60_000 for index in range(40)}  # ~2.4 MiB, no digests
    with pytest.raises(adapter.NativeHookAdapterError) as error:
        adapter.native_prepare_payload("codex", payload, guard_home=native_approval_reuse_runtime)
    assert error.value.code == "native_hook_adapter_response_too_large"


def test_request_over_the_transport_cap_fails_closed(native_approval_reuse_runtime: Path) -> None:
    payload = {"tool_input": {"command": "echo " + "a" * (4 * _MIB)}}
    with pytest.raises(adapter.NativeHookAdapterError) as error:
        adapter.native_prepare_payload("codex", payload, guard_home=native_approval_reuse_runtime)
    assert error.value.code == "native_hook_adapter_request_too_large"
    with pytest.raises(adapter.NativeHookAdapterError) as error:
        adapter.native_command_text("Bash", payload["tool_input"], guard_home=native_approval_reuse_runtime)
    assert error.value.code == "native_hook_adapter_request_too_large"


def test_two_mib_command_is_seen_whole_by_the_resident(native_approval_reuse_runtime: Path) -> None:
    command = "echo " + "a" * (2 * _MIB + 5)
    text = adapter.native_command_text("Bash", {"command": command}, guard_home=native_approval_reuse_runtime)
    assert text == command


def test_cline_two_mib_tool_output_is_copied_and_redacted(native_approval_reuse_runtime: Path) -> None:
    vector = next(item for item in _HARNESS_VECTORS if str(item["harness"]).startswith("cline"))
    blob = "x" * (2 * _MIB + 3)
    payload = {
        "hookName": "PostToolUse",
        "tool_result": {"name": "read_files", "input": {"files": ["a"]}, "output": blob},
    }
    prepared = adapter.native_prepare_payload("cline", payload, guard_home=native_approval_reuse_runtime)
    assert prepared["tool_response"] == blob
    assert prepared["output"] == blob
    small = {**payload, "tool_result": {**payload["tool_result"], "output": "x"}}  # type: ignore[dict-item]
    expected = _envelope({**vector, "event_name": "PostToolUse"}, small, native_approval_reuse_runtime)
    big = _envelope({**vector, "event_name": "PostToolUse"}, payload, native_approval_reuse_runtime)
    assert big["action_id"] == expected["action_id"]
    assert big["action_type"] == expected["action_type"]
    assert big["raw_payload_redacted"]["tool_response"] == "[redacted]"  # type: ignore[index]


def test_cursor_two_mib_command_is_prepared_whole(native_approval_reuse_runtime: Path) -> None:
    command = "echo " + "a" * (2 * _MIB + 5)
    payload = {"hook_event_name": "beforeShellExecution", "command": command, "cwd": "/work"}
    prepared = adapter.native_prepare_payload("cursor", payload, guard_home=native_approval_reuse_runtime)
    assert prepared["command"] == command
    assert prepared["tool_input"]["command"] == command  # type: ignore[index]

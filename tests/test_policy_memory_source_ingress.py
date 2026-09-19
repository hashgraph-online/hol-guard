"""Original command source stays bound across normalization and consent changes."""

from __future__ import annotations

import copy

import pytest

from codex_plugin_scanner.guard.cli.commands_support_hook_payload import _normalize_hook_payload
from codex_plugin_scanner.guard.policy_memory_source import (
    capture_hook_policy_memory_source,
    capture_policy_memory_source_input,
    verified_request_policy_memory_source,
)
from codex_plugin_scanner.guard.runtime.command_capability import revoke_command_capability
from tests.test_policy_memory_source_disclosure import _COMMAND, _connected_store, _grant, _queue


def _raw():
    return {"tool_name": "Bash", "tool_input": {"command": _COMMAND}}


def _seal(store, payload, captured):
    return capture_policy_memory_source_input(
        store,
        payload=payload,
        artifact_id="synthetic:tool",
        harness="codex",
        redaction_level="none",
        captured=captured,
    )


def test_actual_normalization_preserves_only_original_consented_source(tmp_path):
    store = _connected_store(tmp_path)
    _grant(store)
    raw = _raw()
    captured = capture_hook_policy_memory_source(store, payload=raw)
    normalized = _normalize_hook_payload(copy.deepcopy(raw), harness="codex")
    assert "tool_input" in normalized and "arguments" in normalized
    assert _seal(store, normalized, None) is None
    request = _queue(store, _seal(store, normalized, captured))
    source = verified_request_policy_memory_source(store, request)
    assert source is not None and source["commandText"] == _COMMAND
    assert source["artifactId"] == "synthetic:tool"
    assert source["localRequestId"] == request["request_id"]


def test_capture_does_not_retain_mutable_input_aliases(tmp_path):
    store = _connected_store(tmp_path)
    _grant(store)
    raw = _raw()
    captured = capture_hook_policy_memory_source(store, payload=raw)
    raw["tool_input"]["command"] = "printf changed"
    sealed = _seal(store, raw, captured)
    assert sealed is not None and sealed["source"]["commandText"] == _COMMAND


@pytest.mark.parametrize("kind", ["duplicate_arguments", "duplicate_tool", "missing_command", "non_shell"])
def test_original_rejected_source_cannot_be_recovered_from_a_later_projection(tmp_path, kind):
    store = _connected_store(tmp_path)
    _grant(store)
    raw = _raw()
    if kind == "duplicate_arguments":
        raw["arguments"] = {"command": _COMMAND}
    elif kind == "duplicate_tool":
        raw["toolName"] = "Bash"
    elif kind == "missing_command":
        raw["tool_input"] = {}
    else:
        raw["tool_name"] = "Read"
    captured = capture_hook_policy_memory_source(store, payload=raw)
    assert captured.command is None
    assert _seal(store, _raw(), captured) is None


def test_later_consent_cannot_disclose_a_preconsent_capture(tmp_path):
    store = _connected_store(tmp_path)
    captured = capture_hook_policy_memory_source(store, payload=_raw())
    assert captured.command is None and captured.authority is None
    _grant(store)
    assert _seal(store, _raw(), captured) is None


@pytest.mark.parametrize("renew", [False, True])
def test_revocation_or_regrant_invalidates_an_original_capture(tmp_path, renew):
    store = _connected_store(tmp_path)
    _grant(store)
    captured = capture_hook_policy_memory_source(store, payload=_raw())
    revoke_command_capability(store)
    if renew:
        _grant(store)
    assert _seal(store, _raw(), captured) is None

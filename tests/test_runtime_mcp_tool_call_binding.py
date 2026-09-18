"""Actual tool-bound forwarding rejects changed request bytes at the final fence."""

from __future__ import annotations

import json
from dataclasses import FrozenInstanceError, replace
from hashlib import sha256
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.proxy import framing, runtime_mcp, tool_call_binding
from codex_plugin_scanner.guard.proxy.tool_call_binding import (
    bind_tool_call,
    current_tool_call_binding,
    use_tool_call_binding,
)
from codex_plugin_scanner.guard.runtime.restricted_archive_download import RestrictedArchiveDownload

from .test_mcp_owned_preparation_pilot import _session


@pytest.mark.parametrize("boundary", ["policy", "quiet", "hostile_method", "owned_arguments", "encoder"])
def test_changed_tool_call_never_reaches_child(tmp_path, monkeypatch, boundary):
    proxy, messages, marker = _session(tmp_path)
    proxy.command[-1] = proxy.command[-1].replace(
        "if method=='tools/call':", "if method not in {'initialize', 'tools/list'}:"
    )
    callbacks = []

    class HostileMethod(str):
        def __eq__(self, other):
            callbacks.append("equality")
            raise AssertionError

        def __ne__(self, other):
            callbacks.append("inequality")
            raise AssertionError

        def __str__(self):
            callbacks.append("string")
            raise AssertionError

    if boundary == "policy":
        original = GuardConfig.resolve_action_override

        def policy(config, *args, **kwargs):
            result = original(config, *args, **kwargs)
            messages[-1]["method"] = "ping"
            return result

        monkeypatch.setattr(GuardConfig, "resolve_action_override", policy)
    elif boundary == "encoder":
        original = framing.encoded_line

        def encode(payload):
            if payload.get("method") == "tools/call":
                previous = payload["params"]["arguments"]["text"]
                payload["params"]["arguments"]["text"] = "changed wire"
                try:
                    return original(payload)
                finally:
                    payload["params"]["arguments"]["text"] = previous
            return original(payload)

        monkeypatch.setattr(framing, "encoded_line", encode)
    else:
        original = proxy._drain_and_validate_catalog_authority

        def drain(**kwargs):
            result = original(**kwargs)
            if kwargs.get("quiet_seconds") == 0.005:
                if boundary == "owned_arguments":
                    # The selected object can be reached by a faulty local
                    # callback; immutable binding must still reject its change.
                    binding = current_tool_call_binding()
                    assert binding is not None
                    binding.owned_message["params"]["arguments"]["text"] = "changed owned input"
                else:
                    messages[-1]["method"] = HostileMethod("ping") if boundary == "hostile_method" else "ping"
            return result

        monkeypatch.setattr(proxy, "_drain_and_validate_catalog_authority", drain)

    result = proxy.run_session(messages)

    assert callbacks == []
    assert not marker.exists()
    assert result["events"][-1]["reason_code"] == "tool_call_request_changed"
    assert result["events"][-1]["session_terminal"] is True


def test_unchanged_tool_call_keeps_complete_request_and_quiet_fence(tmp_path, monkeypatch):
    proxy, messages, marker = _session(tmp_path)
    expected = json.loads(json.dumps(messages[-1]))
    quiet = []
    original = proxy._drain_and_validate_catalog_authority

    def drain(**kwargs):
        if kwargs.get("quiet_seconds") == 0.005:
            quiet.append(kwargs["quiet_seconds"])
        return original(**kwargs)

    monkeypatch.setattr(proxy, "_drain_and_validate_catalog_authority", drain)

    result = proxy.run_session(messages)

    assert json.loads(marker.read_text()) == expected
    assert quiet == [0.005]
    assert result["responses"][-1]["result"]["content"][0]["text"] == "forwarded"


@pytest.mark.parametrize(
    ("initial", "changed"),
    [
        (True, 1),
        (False, 0),
        (1, 1.0),
        (0.0, -0.0),
        ([], {}),
        ([1], (1,)),
        ([[1], 2], [[1, 2]]),
        ({"a": 1, "b": 2}, {"b": 2, "a": 1}),
        ("ordinary", "changed"),
        ("\u20ac", "e"),
    ],
)
def test_binding_preserves_exact_json_types_values_and_order(initial, changed):
    message = {"id": "bound", "method": "tools/call", "params": {"name": "echo", "arguments": {"value": initial}}}
    binding = bind_tool_call(message)
    assert binding is not None
    binding.check()
    assert binding.owned_message is not message
    message["params"]["arguments"]["value"] = changed
    with pytest.raises(framing.ProxyIoLimitError, match="tool_call_request_changed"):
        binding.check()


def test_binding_frame_is_private_and_cannot_be_reassigned():
    message = {"id": 1, "method": "tools/call", "params": {"name": "echo", "arguments": "private-example"}}
    binding = bind_tool_call(message)
    assert binding is not None
    assert "private-example" not in repr(binding)
    with pytest.raises(FrozenInstanceError):
        binding.frame = b"changed\n"


def test_unsupported_custom_inputs_keep_the_uncached_path_without_binding_callbacks():
    callbacks = []

    class CustomDict(dict):
        def items(self):
            callbacks.append("items")
            raise AssertionError

    for value in (CustomDict(value=1), {1: "value"}, (1,), float("inf"), float("nan")):
        message = {"id": 1, "method": "tools/call", "params": {"name": "echo", "arguments": value}}
        assert bind_tool_call(message) is None
    assert callbacks == []


def test_nested_binding_scope_restores_the_outer_request_after_exception():
    outer = bind_tool_call({"id": 1, "method": "tools/call", "params": {"name": "outer"}})
    inner = bind_tool_call({"id": 2, "method": "tools/call", "params": {"name": "inner"}})
    assert outer is not None and inner is not None
    assert current_tool_call_binding() is None
    with use_tool_call_binding(outer):
        with pytest.raises(RuntimeError), use_tool_call_binding(inner):
            assert current_tool_call_binding() is inner
            raise RuntimeError("synthetic inner failure")
        assert current_tool_call_binding() is outer
    assert current_tool_call_binding() is None


def test_mutation_after_completed_bound_write_does_not_rewrite_success(tmp_path, monkeypatch):
    proxy, messages, marker = _session(tmp_path)
    expected = json.loads(json.dumps(messages[-1]))
    original = framing._write_encoded_line
    completed = []

    def write(stream, data, **kwargs):
        result = original(stream, data, **kwargs)
        if json.loads(data).get("method") == "tools/call":
            messages[-1]["params"]["arguments"]["text"] = "changed after completed write"
            completed.append(True)
        return result

    monkeypatch.setattr(framing, "_write_encoded_line", write)

    result = proxy.run_session(messages)

    assert completed == [True]
    assert json.loads(marker.read_text()) == expected
    assert result["responses"][-1]["result"]["content"][0]["text"] == "forwarded"


def test_plain_dict_capture_failure_never_selects_unsupported_fallback(tmp_path, monkeypatch):
    proxy, messages, marker = _session(tmp_path)
    live_arguments = messages[-1]["params"]["arguments"]
    original_own = tool_call_binding._own_plain_json
    changed = []

    def own(value):
        if value is False and not changed:
            # The containing plain dict iterator is already active. Resuming
            # it raises the real RuntimeError from a concurrent size change.
            live_arguments["capture_race_marker"] = True
            changed.append("during_capture")
        return original_own(value)

    original_drain = proxy._drain_and_validate_catalog_authority

    def drain(**kwargs):
        result = original_drain(**kwargs)
        if kwargs.get("quiet_seconds") == 0.005:
            live_arguments["text"] = "changed after authority"
            changed.append("after_authority")
        return result

    monkeypatch.setattr(tool_call_binding, "_own_plain_json", own)
    monkeypatch.setattr(proxy, "_drain_and_validate_catalog_authority", drain)

    result = proxy.run_session(messages)

    assert not marker.exists(), marker.read_text() if marker.exists() else ""
    assert changed == ["during_capture"]
    assert result["events"][-1]["reason_code"] == "tool_call_request_changed"
    assert result["events"][-1]["session_terminal"] is True


@pytest.mark.parametrize("late_value", ["plain", "hostile"])
def test_completed_write_receipt_uses_the_sent_request(tmp_path, monkeypatch, late_value):
    proxy, messages, marker = _session(tmp_path)
    expected = json.loads(json.dumps(messages[-1]))
    callbacks = []
    receipt_arguments = []
    original_write = framing._write_encoded_line
    original_allow = runtime_mcp.allow_tool_call

    class HostileDict(dict):
        def items(self):
            callbacks.append("late_items")
            raise AssertionError("completed request must not inspect a late owned alias")

    def write(stream, data, **kwargs):
        result = original_write(stream, data, **kwargs)
        if json.loads(data).get("method") == "tools/call":
            binding = current_tool_call_binding()
            assert binding is not None
            params = binding.owned_message["params"]
            if late_value == "hostile":
                params["arguments"] = HostileDict(text="changed after completed write")
            else:
                params["arguments"]["text"] = "changed after completed write"
                params["name"] = "changed after completed write"
        return result

    def allow(**kwargs):
        receipt_arguments.append(json.loads(json.dumps(kwargs["arguments"])))
        return original_allow(**kwargs)

    monkeypatch.setattr(framing, "_write_encoded_line", write)
    monkeypatch.setattr(runtime_mcp, "allow_tool_call", allow)

    result = proxy.run_session(messages)

    assert callbacks == []
    assert json.loads(marker.read_text()) == expected
    assert result["responses"][-1]["result"]["content"][0]["text"] == "forwarded"
    assert result["events"][-1]["tool_name"] == expected["params"]["name"]
    assert result["events"][-1]["redacted_params"] == expected["params"]
    assert receipt_arguments == [expected["params"]["arguments"]]
    assert len(proxy.store.list_receipts(limit=10)) == 1


def test_verified_package_handoff_receipt_survives_late_owned_mutation(tmp_path, monkeypatch):
    proxy, messages, marker = _session(tmp_path)
    proxy.config = replace(proxy.config, risk_actions={"mcp_dangerous_tool": "warn"})
    source_url = "https://packages.example.com/synthetic.tgz"
    messages[-1]["params"]["arguments"]["text"] = source_url
    archive_path = tmp_path / "verified.tgz"
    archive_bytes = b"synthetic verified archive"
    archive_path.write_bytes(archive_bytes)
    archive_path.chmod(0o400)
    evaluation = SimpleNamespace(
        external_archive_downloads=(
            RestrictedArchiveDownload(
                path=archive_path,
                sha256=sha256(archive_bytes).hexdigest(),
                size=len(archive_bytes),
                source_url=source_url,
                final_url=source_url,
            ),
        ),
        reasons=({"code": "external_tarball_source"},),
    )
    callbacks = []
    completed_handoffs = []
    original_write = framing._write_encoded_line

    class HostileDict(dict):
        def items(self):
            callbacks.append("late_package_items")
            raise AssertionError("completed package handoff must retain its sent projection")

    def forward(**kwargs):
        # Route a real authorized tool call through the verified package
        # replacement and production record/write boundary, using an inert
        # echo child. No archive is executed and no scanner result is implied.
        bound = runtime_mcp._bound_external_archive_mcp_request(
            kwargs["message"], kwargs["params"], evaluation=evaluation
        )
        assert bound is not None
        bound_message, bound_params = bound
        return proxy._record_package_forward(
            message=bound_message,
            child_stdin=kwargs["child_stdin"],
            child_stdout=kwargs["child_stdout"],
            client_input=kwargs["client_input"],
            server_output=kwargs["server_output"],
            artifact=kwargs["artifact"],
            artifact_hash=kwargs["artifact_hash"],
            tool_name=bound_params["name"],
            params=bound_params,
            package_evaluation=evaluation,
            policy_action="warn",
            scanner_evidence=(),
            event_decision="package-warn",
            remember=False,
            policy_workspace=None,
            decision_source="policy-warn",
            expected_catalog_generation=kwargs["expected_catalog_generation"],
            expected_catalog_state=kwargs["expected_catalog_state"],
            expected_catalog_fingerprint=kwargs["expected_catalog_fingerprint"],
            authority_check=kwargs["authority_check"],
        )

    def write(stream, data, **kwargs):
        result = original_write(stream, data, **kwargs)
        if json.loads(data).get("method") == "tools/call":
            binding = current_tool_call_binding()
            assert binding is not None and binding.parent is not None
            binding.owned_message["params"]["arguments"] = HostileDict(text="late replacement")
            completed_handoffs.append(True)
        return result

    monkeypatch.setattr(proxy, "_allow_and_forward", forward)
    monkeypatch.setattr(framing, "_write_encoded_line", write)

    result = proxy.run_session(messages)

    assert callbacks == []
    assert completed_handoffs == [True]
    received = json.loads(marker.read_text())
    assert received["params"]["arguments"]["text"] == str(archive_path)
    assert messages[-1]["params"]["arguments"]["text"] == source_url
    assert result["responses"][-1]["result"]["content"][0]["text"] == "forwarded"
    assert result["events"][-1]["redacted_params"] == received["params"]
    assert len(proxy.store.list_receipts(limit=10)) == 1


def test_unsupported_type_metadata_cannot_invoke_custom_equality():
    callbacks = []

    class HostileType(type):
        def __eq__(cls, other):
            callbacks.append("type_equality")
            return False

    class Unsupported(metaclass=HostileType):
        pass

    message = {"id": 1, "method": "tools/call", "params": {"name": "echo", "arguments": Unsupported()}}

    assert bind_tool_call(message) is None
    assert callbacks == []

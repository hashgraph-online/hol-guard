"""Inactive E helper predicates and current-runtime ownership rejection."""

from __future__ import annotations

import importlib
import io
import json
import sys
from argparse import Namespace
from contextlib import nullcontext
from copy import deepcopy
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.proxy import CodexMcpGuardProxy, framing, runtime_mcp
from codex_plugin_scanner.guard.store import GuardStore


@pytest.fixture(autouse=True)
def no_historical_measurement_workers(monkeypatch):
    """Finite source predicates must never start an E/F measurement worker."""
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))

    def forbidden(*_args, **_kwargs):
        pytest.fail("historical profile/campaign execution is outside current-runtime test scope")

    for name in ("profile_guard_mcp_session", "profile_guard_mcp_streaming_session"):
        worker = importlib.import_module(name)
        for entrypoint in ("run_case", "run_remote_case", "run_matrix", "main"):
            monkeypatch.setattr(worker, entrypoint, forbidden)


@pytest.fixture
def module(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    return importlib.import_module("guard_mcp_owned_preparation_pilot")


@pytest.fixture
def pilot(module):
    candidate = module.OwnedPreparationPilot()
    restore = module.install_adapter(runtime_mcp, candidate)
    try:
        yield candidate
    finally:
        restore()


def _session(tmp_path, *, action="warn"):
    marker = tmp_path / "received.json"
    code = "\n".join(
        [
            "import json,sys",
            "from pathlib import Path",
            f"marker=Path({str(marker)!r})",
            "for line in sys.stdin:",
            " message=json.loads(line)",
            " method=message.get('method')",
            " result={}",
            " if method=='tools/list': result={'tools':[{'name':'safe_echo','inputSchema':{'type':'object'}}]}",
            " if method=='tools/call':",
            "  marker.write_text(json.dumps(message))",
            "  result={'content':[{'type':'text','text':'forwarded'}]}",
            " if 'id' in message: print(json.dumps({'jsonrpc':'2.0','id':message['id'],'result':result}),flush=True)",
        ]
    )
    context = HarnessContext(home_dir=tmp_path, workspace_dir=tmp_path, guard_home=tmp_path / "guard")
    proxy = CodexMcpGuardProxy(
        server_name="synthetic",
        command=[sys.executable, "-u", "-c", code],
        context=context,
        store=GuardStore(context.guard_home),
        config=GuardConfig(guard_home=context.guard_home, workspace=tmp_path, default_action=action),
        source_scope="project",
        config_path=".mcp.json",
    )
    message = {
        "jsonrpc": "2.0",
        "id": "exact-id",
        "method": "tools/call",
        "params": {"name": "safe_echo", "arguments": {"nested": [False, 7, -0.0, None], "text": "ordinary"}},
    }
    messages = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"capabilities": {"elicitation": {}}}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        message,
    ]
    return proxy, messages, marker


@pytest.mark.parametrize(
    ("first", "second"),
    [
        (True, 1),
        (1, 1.0),
        (0.0, -0.0),
        ([], ()),
        ({"a": 1, "b": 2}, {"b": 2, "a": 1}),
        ([[1], 2], [[1, 2]]),
        ("1", 1),
        ({"a": [1, 2]}, {"a": [2, 1]}),
    ],
)
def test_exact_binding_distinguishes_json_material(module, first, second):
    assert module._exact_binding(first) != module._exact_binding(second)


def test_binding_is_alias_independent_private_and_bounded(module, monkeypatch):
    child = {"text": "immutable-private-marker"}
    assert module._exact_binding([child, child]) == module._exact_binding([child, deepcopy(child)])
    request = module.OwnedPreparationPilot().own_request({"params": {"arguments": child}})
    assert request is not None
    assert request.owned_message["params"]["arguments"] is not child
    assert "immutable-private-marker" not in repr(request)
    cycle = []
    cycle.append(cycle)
    with pytest.raises((ValueError, RecursionError)):
        module._exact_binding(cycle)
    monkeypatch.setattr(module, "MAX_BINDING_BYTES", 64)
    with pytest.raises(ValueError, match="binding_limit"):
        module._exact_binding("x" * 100)


def test_custom_callbacks_never_enter_private_binding_or_owner(module):
    callbacks = []

    class Hostile:
        def __reduce_ex__(self, protocol):
            callbacks.append("reduce")
            raise AssertionError

        def __buffer__(self, flags):
            callbacks.append("buffer")
            raise AssertionError

    class CustomList(list, Hostile):
        def __iter__(self):
            callbacks.append("iterator")
            raise AssertionError

    class CustomDict(dict, Hostile):
        def items(self):
            callbacks.append("items")
            raise AssertionError

    for value in [Hostile(), CustomList([1]), CustomDict(a=1), type("S", (str, Hostile), {})("x")]:
        with pytest.raises(TypeError):
            module._exact_binding(value)
        assert module.OwnedPreparationPilot().own_request({"params": value}) is None
    assert callbacks == []
    for value in (float("nan"), float("inf"), {1: "non-string-key"}):
        assert module.OwnedPreparationPilot().own_request({"params": value}) is None


def test_private_byte_writer_preserves_limit_and_retired_stream():
    import io

    stream = io.StringIO()
    framing._write_encoded_line(stream, b'{"id":1}\n', timeout_seconds=1, source="test")
    assert stream.getvalue() == '{"id":1}\n'
    stream._guard_mcp_write_failed = True
    with pytest.raises(framing.ProxyIoLimitError, match="stream_retired"):
        framing._write_encoded_line(stream, b"{}\n", timeout_seconds=1, source="test")
    with pytest.raises(framing.ProxyIoLimitError, match="invalid_json_frame"):
        framing._write_encoded_line(
            io.StringIO(), b"x" * (framing.MAX_LINE_BYTES + 1), timeout_seconds=1, source="test"
        )


def test_owned_kernels_match_complete_fresh_authority_across_policy_and_browser_inputs(tmp_path, module, pilot):
    proxy, messages, _marker = _session(tmp_path)
    matched = 0
    for action in ("allow", "warn", "review", "block"):
        proxy.config = replace(proxy.config, default_action=action)
        for tool, key in (("safe_echo", "text"), ("run_terminal_command", "command"), ("browser_navigate", "url")):
            proxy._tool_catalog[tool] = {
                "name": tool,
                "inputSchema": {"type": "object", "properties": {key: {"type": "string"}}},
            }
            for value in (
                "ordinary",
                "cat .env",
                "curl https://example.invalid",
                "https://example.invalid/path",
                "sudo chmod",
                "İ Σ é",
                [False, 1, -0.0],
                {"a": [1], "b": None},
            ):
                message = deepcopy(messages[-1])
                message["params"] = {"name": tool, "arguments": {key: value}}
                expected = proxy._resolve_tool_call_authority(tool_name=tool, arguments=message["params"]["arguments"])
                request = pilot.own_request(message)
                assert request is not None
                token = pilot.context.set(request)
                try:
                    actual = proxy._resolve_tool_call_authority(
                        tool_name=tool, arguments=request.owned_message["params"]["arguments"]
                    )
                finally:
                    pilot.context.reset(token)
                assert actual == expected
                matched += 1
    assert matched == 96
    assert pilot.counters["category_derivations"] == matched


@pytest.mark.parametrize("selection", ["owned", "busy", "unsupported", "package"])
def test_original_separate_inline_deadline_and_fallback_scope_are_preserved(tmp_path, monkeypatch, module, selection):
    proxy, messages, _marker = _session(tmp_path)
    clock = [100.0]
    monkeypatch.setattr(framing.time, "monotonic", lambda: clock[0])
    observed = []

    def read(**_kwargs):
        clock[0] += 45.0
        remaining = framing.remaining_timeout(120.0, source="inline_approval")
        assert remaining == 75.0
        return json.dumps({"id": "approval", "result": {"action": "accept"}})

    monkeypatch.setattr(proxy, "_read_client_during_wait", read)

    def serialized(_proxy, **kwargs):
        assert framing._BUDGET.get() is None
        reply = proxy._request_inline_approval(
            {"jsonrpc": "2.0", "id": "approval", "method": "elicitation/create", "params": {}},
            input_stream=io.StringIO(),
            output_stream=io.StringIO(),
            child_stdin=io.StringIO(),
            child_stdout=io.StringIO(),
        )
        assert reply["action"] == "accept"
        assert framing._BUDGET.get() is None
        observed.append(reply)
        return {"id": kwargs["message"]["id"], "result": {}}, {"decision": "fixture"}

    monkeypatch.setattr(runtime_mcp.RuntimeMcpGuardProxy, "_handle_message_serialized", serialized)
    candidate = module.OwnedPreparationPilot()
    restore = module.install_adapter(runtime_mcp, candidate)
    if selection == "busy":
        candidate.admission.acquire()
    elif selection == "unsupported":
        messages[-1]["params"]["arguments"]["text"] = float("nan")
    elif selection == "package":
        monkeypatch.setattr(proxy, "_package_request_artifact", lambda **_kwargs: object())
    try:
        proxy._handle_message_checked(
            message=messages[-1],
            child_stdin=io.StringIO(),
            child_stdout=io.StringIO(),
            client_input=None,
            server_output=None,
            approval_callback=None,
        )
    finally:
        restore()
        if selection == "busy":
            candidate.admission.release()
    assert len(observed) == 1
    assert clock[0] == 145.0


def test_legacy_custom_routing_fallback_adds_no_callback_invocations(tmp_path, monkeypatch, module):
    proxy, messages, _marker = _session(tmp_path)
    callbacks = []

    class Message(dict):
        def get(self, *args):
            callbacks.append("get")
            return super().get(*args)

    class Method(str):
        def __eq__(self, value):
            callbacks.append("equality")
            return super().__eq__(value)

    monkeypatch.setattr(
        runtime_mcp.RuntimeMcpGuardProxy, "_handle_message_serialized", lambda _self, **_kwargs: (None, {})
    )
    for message in (Message(messages[-1]), {**messages[-1], "method": Method("tools/call")}):
        kwargs = dict(
            message=message,
            child_stdin=io.StringIO(),
            child_stdout=io.StringIO(),
            client_input=None,
            server_output=None,
            approval_callback=None,
        )
        callbacks.clear()
        proxy._handle_message_checked(**kwargs)
        expected = list(callbacks)
        callbacks.clear()
        candidate = module.OwnedPreparationPilot()
        restore = module.install_adapter(runtime_mcp, candidate)
        try:
            proxy._handle_message_checked(**kwargs)
        finally:
            restore()
        assert callbacks == expected
        assert candidate.counters["requests_admitted"] == 0


@pytest.mark.parametrize("stage", ["during_case", "after_completed_case"])
def test_comparison_preserves_failed_attempts_and_completed_invalid_results(tmp_path, monkeypatch, module, stage):
    comparison = importlib.import_module("compare_guard_mcp_owned_preparation")
    identity = {"mcp_tool_calls.py": "frozen"}
    monkeypatch.setattr(comparison, "source_identity", lambda _root: identity)
    monkeypatch.setattr(comparison, "oracle_identity", lambda: identity)
    monkeypatch.setattr(comparison, "harness_identity", lambda: {"harness": "frozen"})
    monkeypatch.setattr(comparison, "performance_lock", lambda _path: nullcontext())
    monkeypatch.setattr(comparison, "verify_facts", lambda _root: {"cases": 3008})

    def case(**_kwargs):
        if stage == "during_case":
            raise comparison.BenchmarkCaseError(
                {"attempted_tool_requests": 3, "observed_tool_responses": 2, "observed_child_forwarded_count": 2}
            )
        return {"loaded_runtime_sha256": {"mcp_tool_calls.py": "wrong"}, "correctness": {"accepted": 4, "errors": 0}}

    monkeypatch.setattr(comparison, "run_case", case)
    args = Namespace(
        json=tmp_path / "attempts.json",
        baseline_src=tmp_path / "B",
        candidate_src=tmp_path / "E",
        lock_file=tmp_path / "lock",
        samples=3,
    )
    with pytest.raises((comparison.BenchmarkCaseError, RuntimeError)):
        comparison.run_comparison(args)
    report = json.loads(args.json.read_text())
    assert report["cases"] == []
    failed = report["failed_case"]
    if stage == "during_case":
        assert failed["attempted_tool_requests"] == 3
        assert failed["observed_tool_responses"] == 2
        assert failed["observed_child_forwarded_count"] == 2
    else:
        assert failed["completed_case_result"]["correctness"]["accepted"] == 4
        assert failed["measurement_valid"] is False
    with pytest.raises(ValueError, match="refuses_to_overwrite"):
        comparison.run_comparison(args)


def test_comparison_rejects_wrong_parent_oracle_before_credit_or_sampling(tmp_path, monkeypatch, module):
    comparison = importlib.import_module("compare_guard_mcp_owned_preparation")
    monkeypatch.setattr(comparison, "source_identity", lambda _root: {"mcp_tool_calls.py": "expected"})
    monkeypatch.setattr(comparison, "oracle_identity", lambda: {"mcp_tool_calls.py": "wrong-installed-copy"})
    monkeypatch.setattr(comparison, "performance_lock", lambda _path: nullcontext())
    monkeypatch.setattr(comparison, "verify_facts", lambda _root: pytest.fail("wrong oracle must never execute"))
    monkeypatch.setattr(comparison, "run_case", lambda **_kwargs: pytest.fail("wrong oracle must prevent timing"))
    args = Namespace(
        json=tmp_path / "wrong-oracle.json",
        baseline_src=tmp_path,
        candidate_src=tmp_path,
        lock_file=tmp_path / "lock",
        samples=3,
    )
    with pytest.raises(RuntimeError, match="wrong_candidate_source"):
        comparison.run_comparison(args)
    report = json.loads(args.json.read_text())
    assert report["cases"] == []
    assert "public_api_facts_parity" not in report
    assert report["public_oracle_loaded_sources_sha256"] == {"mcp_tool_calls.py": "wrong-installed-copy"}


@pytest.mark.parametrize("policy_state", ["ordinary", "inline", "saved_once"])
def test_current_runtime_rejects_historical_owner_before_tool_write(tmp_path, monkeypatch, pilot, policy_state):
    """Old adapters cannot replace the current production admission owner."""
    from codex_plugin_scanner.guard.proxy.tool_call_binding import current_tool_call_binding

    proxy, messages, marker = _session(tmp_path, action="warn" if policy_state == "ordinary" else "review")
    preparations = []
    claims = []
    approvals = []
    quiet_fences = []
    saved = {}
    original_prepare = pilot.prepare
    original_capture = proxy._capture_tools_catalog
    original_drain = proxy._drain_and_validate_catalog_authority

    def prepare(current_proxy, **kwargs):
        historical = pilot.context.get()
        current = current_tool_call_binding()
        assert historical is not None and current is not None
        assert current.live_message is historical.owned_message
        assert current.owned_message is not historical.owned_message
        assert kwargs["arguments"] is current.owned_message["params"]["arguments"]
        current.check()
        preparations.append(True)
        return original_prepare(current_proxy, **kwargs)

    def capture(*args, **kwargs):
        response = original_capture(*args, **kwargs)
        if policy_state == "saved_once":
            assert pilot.context.get() is None
            authority = proxy._resolve_tool_call_authority(
                tool_name="safe_echo", arguments=messages[-1]["params"]["arguments"]
            )
            saved.update(
                harness="codex",
                artifact_id=authority.artifact.artifact_id,
                artifact_hash=authority.artifact_hash,
                workspace=str(tmp_path),
                publisher=authority.artifact.publisher,
            )
            approval_id = proxy.store.record_local_once_approval(
                **saved,
                request_id="historical-owner-rejection",
                action="allow",
                created_at="2026-07-17T00:00:00+00:00",
                expires_at="2027-07-17T00:00:00+00:00",
            )
            assert approval_id is not None
        return response

    def claim(*args, **kwargs):
        claims.append(True)
        pytest.fail("incompatible ownership must fail before claiming saved approval")

    def approve(_request):
        approvals.append(True)
        pytest.fail("incompatible ownership must fail before inline approval")

    def drain(**kwargs):
        if kwargs.get("quiet_seconds") == 0.005:
            quiet_fences.append(True)
        return original_drain(**kwargs)

    monkeypatch.setattr(pilot, "prepare", prepare)
    monkeypatch.setattr(proxy, "_capture_tools_catalog", capture)
    monkeypatch.setattr(proxy, "_drain_and_validate_catalog_authority", drain)
    monkeypatch.setattr(proxy.store, "claim_approval_reuse_decisions", claim)
    result = proxy.run_session(messages, inline_approval_callback=approve)

    assert preparations == [True]
    assert claims == approvals == quiet_fences == []
    assert not marker.exists()
    assert result["events"][-1]["reason_code"] == "owned_request_generation_changed"
    assert result["events"][-1]["session_terminal"] is True
    assert "result" not in result["responses"][-1]
    assert pilot.counters["requests_admitted"] == pilot.counters["selected_failures"] == 1
    assert pilot.counters["category_derivations"] == pilot.counters["preparations_completed"] == 0
    assert pilot.counters["bound_forwards"] == 0
    assert pilot.context.get() is None and current_tool_call_binding() is None
    assert not pilot.admission.locked()
    assert proxy.store.list_receipts(limit=10) == []
    if policy_state == "saved_once":
        assert proxy.store.peek_local_once_approval(**saved, now="2026-09-18T00:00:00+00:00") is not None


@pytest.mark.parametrize("owner", ["live", "historical", "current", "hostile_live_method"])
def test_current_runtime_mutations_cannot_make_historical_owner_executable(tmp_path, monkeypatch, pilot, owner):
    from codex_plugin_scanner.guard.proxy.tool_call_binding import current_tool_call_binding

    proxy, messages, marker = _session(tmp_path)
    callbacks = []
    mutations = []
    original_prepare = pilot.prepare

    class HostileMethod(str):
        def __str__(self):
            callbacks.append("string")
            raise AssertionError

        def __eq__(self, _other):
            callbacks.append("equality")
            raise AssertionError

        def __reduce_ex__(self, _protocol):
            callbacks.append("reduction")
            raise AssertionError

    def prepare(current_proxy, **kwargs):
        historical = pilot.context.get()
        current = current_tool_call_binding()
        assert historical is not None and current is not None
        if owner == "hostile_live_method":
            messages[-1]["method"] = HostileMethod("ping")
        else:
            target = {
                "live": messages[-1],
                "historical": historical.owned_message,
                "current": current.owned_message,
            }[owner]
            target["params"]["arguments"]["text"] = "changed at ownership rejection"
        mutations.append(True)
        return original_prepare(current_proxy, **kwargs)

    monkeypatch.setattr(pilot, "prepare", prepare)
    result = proxy.run_session(messages)

    assert mutations == [True] and callbacks == []
    assert not marker.exists()
    assert result["events"][-1]["reason_code"] == "owned_request_generation_changed"
    assert result["events"][-1]["session_terminal"] is True
    assert pilot.counters["category_derivations"] == pilot.counters["bound_forwards"] == 0
    assert pilot.context.get() is None and current_tool_call_binding() is None
    assert not pilot.admission.locked()


@pytest.mark.parametrize("mutate_nested", [False, True])
def test_nested_current_runtime_keeps_its_binding_and_rejects_historical_outer(
    tmp_path, monkeypatch, pilot, mutate_nested
):
    from codex_plugin_scanner.guard.proxy.tool_call_binding import current_tool_call_binding

    proxy, messages, marker = _session(tmp_path)
    nested = deepcopy(messages[-1])
    nested["id"] = "nested-current-b"
    nested_results = []
    inner_fences = []
    original_prepare = pilot.prepare
    original_drain = proxy._drain_and_validate_catalog_authority

    def drain(**kwargs):
        response = original_drain(**kwargs)
        current = current_tool_call_binding()
        if kwargs.get("quiet_seconds") == 0.005 and current is not None and current.owned_message["id"] == nested["id"]:
            assert pilot.context.get() is None
            inner_fences.append(True)
            if mutate_nested:
                nested["params"]["arguments"]["text"] = "changed nested request"
        return response

    def prepare(current_proxy, **kwargs):
        historical = pilot.context.get()
        current = current_tool_call_binding()
        assert historical is not None and current is not None
        assert pilot.admission.locked()
        process = proxy._active_process
        assert process is not None and process.stdin is not None and process.stdout is not None
        response, event = proxy._handle_message(
            message=nested,
            child_stdin=process.stdin,
            child_stdout=process.stdout,
            client_input=None,
            server_output=None,
            approval_callback=None,
        )
        nested_results.append((response, event))
        assert pilot.context.get() is historical
        assert current_tool_call_binding() is current
        assert pilot.admission.locked()
        return original_prepare(current_proxy, **kwargs)

    monkeypatch.setattr(pilot, "prepare", prepare)
    monkeypatch.setattr(proxy, "_drain_and_validate_catalog_authority", drain)
    result = proxy.run_session(messages)

    assert len(nested_results) == 1 and inner_fences == [True]
    response, event = nested_results[0]
    assert response["id"] == "nested-current-b"
    if mutate_nested:
        assert not marker.exists()
        assert event["reason_code"] == "tool_call_request_changed"
        assert event["session_terminal"] is True
        assert "result" not in response
    else:
        assert json.loads(marker.read_text()) == nested
        assert response["result"]["content"][0]["text"] == "forwarded"
    assert result["events"][-1]["reason_code"] == "owned_request_generation_changed"
    assert "result" not in result["responses"][-1]
    assert pilot.counters["requests_admitted"] == pilot.counters["busy_fallback"] == 1
    assert pilot.counters["category_derivations"] == pilot.counters["bound_forwards"] == 0
    assert pilot.context.get() is None and current_tool_call_binding() is None
    assert not pilot.admission.locked()

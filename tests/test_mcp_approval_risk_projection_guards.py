"""Unexecuted source-change refusal controls for approval risk projection."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard import mcp_tool_calls as calls
from codex_plugin_scanner.guard.mcp_authority_binding import proxy_authority_scope
from codex_plugin_scanner.guard.proxy import runtime_mcp
from codex_plugin_scanner.guard.proxy.tool_call_binding import bind_tool_call, use_tool_call_binding

from .test_mcp_approval_risk_projection import _bound_queue, _queue_hooks, _supported
from .test_mcp_invocation_risk_pair import _observed
from .test_mcp_owned_preparation_pilot import _session


@pytest.mark.parametrize("changed", ["concrete_path", "context_descriptor", "config_dispatch"])
def test_observation_refuses_changed_dispatch_before_invoking_it(tmp_path, monkeypatch, changed):
    _supported()
    proxy, messages, _marker = _session(tmp_path, action="review")
    binding = bind_tool_call(messages[-1])
    params = binding.owned_message["params"]
    calls_seen = []

    def forbidden(*_args, **_kwargs):
        calls_seen.append(changed)
        raise AssertionError("changed dispatch must not run merely to enable reuse")

    with proxy_authority_scope(), use_tool_call_binding(binding):
        authority = proxy._resolve_tool_call_authority(tool_name=params["name"], arguments=params["arguments"])
        analysis = authority.risk_analysis
        assert analysis is not None
        expected = calls.tool_call_risk_summary(authority.artifact, params["arguments"])
        if changed == "concrete_path":
            monkeypatch.setattr(type(proxy.context.workspace_dir), "resolve", forbidden)
        elif changed == "context_descriptor":
            monkeypatch.setattr(type(proxy.context), "workspace_dir", property(forbidden))
        else:
            monkeypatch.setattr(type(proxy.config), "__getattribute__", forbidden)
        with _observed() as counts:
            result = runtime_mcp._approval_risk_summary(analysis, authority.artifact, params["arguments"])
    assert result == expected
    assert counts["categories"] == counts["signals"] == 1
    assert calls_seen == []
    assert analysis._phase == "closed"


@pytest.mark.parametrize(
    "interface",
    [
        "runtime_digest",
        "authority_digest",
        "authority_check",
        "request_check",
        "request_matcher",
        "request_parts",
        "request_json_alias",
        "runtime_object_shadow",
    ],
)
def test_changed_authority_interfaces_are_not_invoked_by_optional_probe(tmp_path, monkeypatch, interface):
    from types import SimpleNamespace

    from codex_plugin_scanner.guard import mcp_authority_binding as authority_binding
    from codex_plugin_scanner.guard.proxy import tool_call_binding as request_binding

    _supported()
    proxy, messages, _marker = _session(tmp_path, action="review")
    invoked = []
    locations = {
        "runtime_digest": (runtime_mcp, "exact_authority_digest"),
        "runtime_object_shadow": (runtime_mcp, "object"),
        "authority_digest": (authority_binding, "exact_authority_digest"),
        "authority_check": (authority_binding.ExactAuthorityBinding, "check"),
        "request_check": (request_binding.ToolCallBinding, "check"),
        "request_matcher": (request_binding, "_matches_frame"),
        "request_parts": (request_binding, "_json_parts"),
        "request_json_alias": (request_binding, "json"),
    }

    def forbidden(*_args, **_kwargs):
        invoked.append(interface)
        raise AssertionError("changed authority callback is not an optional observation")

    def mutate(name):
        if name == "daemon":
            owner, member = locations[interface]
            if interface == "request_json_alias":
                replacement = SimpleNamespace(dumps=forbidden)
            elif interface == "runtime_object_shadow":
                replacement = SimpleNamespace(__getattribute__=forbidden)
            else:
                replacement = forbidden
            monkeypatch.setattr(owner, member, replacement, raising=False)

    _trace, payloads, receipts = _queue_hooks(monkeypatch, proxy, mutate=mutate)
    with _observed() as counts:
        _bound_queue(proxy, messages[-1])
    assert invoked == []
    assert counts == {"categories": 3, "signals": 2, "policy": 2}
    assert payloads and receipts


def test_reexported_default_method_does_not_hide_inherited_custom_dispatch(tmp_path):
    _supported()
    proxy, messages, _marker = _session(tmp_path, action="review")
    binding = bind_tool_call(messages[-1])
    params = binding.owned_message["params"]
    invoked = []

    class CustomDispatch(runtime_mcp.RuntimeMcpGuardProxy):
        def __getattribute__(self, name):
            invoked.append(name)
            return super().__getattribute__(name)

    class Reexported(CustomDispatch):
        _capture_tool_call_authority = runtime_mcp.RuntimeMcpGuardProxy._capture_tool_call_authority
        _bind_tool_call_artifact = staticmethod(runtime_mcp.RuntimeMcpGuardProxy._bind_tool_call_artifact)
        _evaluate_tool_call_authority = runtime_mcp.RuntimeMcpGuardProxy._evaluate_tool_call_authority
        _resolve_tool_call_authority = runtime_mcp.RuntimeMcpGuardProxy._resolve_tool_call_authority

    with proxy_authority_scope(), use_tool_call_binding(binding):
        authority = proxy._resolve_tool_call_authority(tool_name=params["name"], arguments=params["arguments"])
        analysis = authority.risk_analysis
        assert analysis is not None
        original_type = type(proxy)
        try:
            object.__setattr__(proxy, "__class__", Reexported)
            assert not runtime_mcp._approval_observation_supported(proxy)
            with _observed() as counts:
                summary = runtime_mcp._approval_risk_summary(analysis, authority.artifact, params["arguments"])
        finally:
            object.__setattr__(proxy, "__class__", original_type)
    assert summary == "No high-risk signal was detected in this tool call."
    assert counts["categories"] == counts["signals"] == 1
    assert invoked == []
    assert analysis._phase == "closed"


def test_path_constructor_namespace_is_available_from_exact_class_dictionary():
    from pathlib import Path

    from codex_plugin_scanner.guard.mcp_approval_risk import function_namespace

    member = Path.__dict__.get("__new__")
    assert type(member) is staticmethod
    assert function_namespace(member) is function_namespace(Path.__new__)
    assert function_namespace(member) is not None


def test_exact_staticmethod_namespace_observation_does_not_call_the_function():
    from codex_plugin_scanner.guard.mcp_approval_risk import function_namespace

    def forbidden():
        raise AssertionError("optional observation must not execute the constructor")

    assert function_namespace(staticmethod(forbidden)) is forbidden.__globals__


def test_unknown_staticmethod_and_callable_descriptors_are_not_invoked():
    from codex_plugin_scanner.guard.mcp_approval_risk import function_namespace

    class CallableDescriptor:
        def __get__(self, instance, owner):
            raise AssertionError("descriptor must not be invoked")

        def __call__(self):
            raise AssertionError("callable must not be invoked")

    class CustomStaticmethod(staticmethod):
        def __getattribute__(self, name):
            raise AssertionError("custom dispatch must not be invoked")

    callback = CallableDescriptor()
    assert function_namespace(callback) is None
    assert function_namespace(staticmethod(callback)) is None
    assert function_namespace(CustomStaticmethod(lambda: None)) is None


@pytest.mark.parametrize("change", ["descriptor_identity", "wrapped_code"])
def test_path_constructor_changes_refuse_reuse_without_invoking_constructor(change):
    import sys
    from pathlib import Path

    from codex_plugin_scanner.guard.mcp_risk_dependencies import _HelperBinding

    member = Path.__dict__["__new__"]
    function = object.__getattribute__(member, "__func__")
    original_code = function.__code__
    changed_code = original_code.replace(co_filename="<changed-risk-constructor>")
    binding = _HelperBinding.capture({"Path": Path}, "Path")
    assert binding.unchanged()
    calls_seen = []

    def observe(frame, event, _arg):
        if event == "call" and (frame.f_code is original_code or frame.f_code is changed_code):
            calls_seen.append(event)

    previous_profile = sys.getprofile()
    try:
        if change == "descriptor_identity":
            type.__setattr__(Path, "__new__", staticmethod(function))
        else:
            function.__code__ = changed_code
        sys.setprofile(observe)
        unchanged = binding.unchanged()
    finally:
        sys.setprofile(previous_profile)
        function.__code__ = original_code
        type.__setattr__(Path, "__new__", member)
    assert unchanged is False
    assert calls_seen == []
    assert Path.__dict__["__new__"] is member
    assert function.__code__ is original_code

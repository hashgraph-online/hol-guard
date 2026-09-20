"""Exact stream comparison and retained authority witnesses for inactive F."""

from __future__ import annotations

import importlib
import io
import json
from copy import deepcopy
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.proxy import runtime_mcp
from tests import test_mcp_owned_preparation_pilot as retained

_session = retained._session
no_historical_measurement_workers = retained.no_historical_measurement_workers
test_alias_binding = retained.test_binding_is_alias_independent_private_and_bounded
test_custom_callbacks = retained.test_custom_callbacks_never_enter_private_binding_or_owner
test_type_identity = retained.test_exact_binding_distinguishes_json_material
test_custom_routing = retained.test_legacy_custom_routing_fallback_adds_no_callback_invocations
test_original_deadlines = retained.test_original_separate_inline_deadline_and_fallback_scope_are_preserved
test_authority_browser_parity = (
    retained.test_owned_kernels_match_complete_fresh_authority_across_policy_and_browser_inputs
)
test_current_runtime_rejects_historical_owner = retained.test_current_runtime_rejects_historical_owner_before_tool_write
test_current_runtime_mutations_reject_historical_owner = (
    retained.test_current_runtime_mutations_cannot_make_historical_owner_executable
)
test_nested_current_runtime_rejects_historical_outer = (
    retained.test_nested_current_runtime_keeps_its_binding_and_rejects_historical_outer
)


# Retain compatible finite predicates and exercise current-runtime rejection.
# Complete prior source/receipts remain frozen in the test-scope evidence; no
# profile or campaign worker is executed by these tests.
@pytest.fixture
def module(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    return importlib.import_module("guard_mcp_streaming_preparation_pilot")


@pytest.fixture
def pilot(module):
    candidate = module.OwnedPreparationPilot()
    restore = module.install_adapter(runtime_mcp, candidate)
    try:
        yield candidate
    finally:
        restore()


@pytest.mark.parametrize("width", [1, 2, 3, 7, 16, 64])
def test_comparison_does_not_depend_on_chunk_boundaries(module, width):
    reference = b"finite exact comparison, including \x00 and \xff"
    for candidate in (reference, reference[:-1], reference + b"x", b"x" + reference[1:]):
        output = module._BindingComparator(reference)
        for offset in range(0, len(candidate), width):
            assert output.write(candidate[offset : offset + width]) == len(candidate[offset : offset + width])
            assert output.write(b"") == 0
        assert output.matches() is (candidate == reference)
        assert output.position == len(candidate)
        assert output.reference is reference
        assert not hasattr(output, "__dict__")


def test_streamed_bindings_match_frozen_e_for_strict_values_without_a_new_buffer(module, monkeypatch):
    original = importlib.import_module("guard_mcp_owned_preparation_pilot")
    shared = {"text": "shared"}
    values = [
        None,
        False,
        True,
        0,
        1,
        1.0,
        -0.0,
        0.0,
        "",
        "İ Σ é €",
        "x" * 131072,
        [0] * 65536,
        [shared, shared],
        [shared, deepcopy(shared)],
        {"a": [1], "b": None},
        {"b": None, "a": [1]},
    ]
    references = [original._exact_binding(value) for value in values]

    def forbidden_buffer():
        pytest.fail("freshness comparison must not allocate a complete binding buffer")

    monkeypatch.setattr(module, "_BindingBuffer", forbidden_buffer)
    for value, reference in zip(values, references, strict=True):
        assert module._binding_matches(value, reference)
        assert not module._binding_matches(value, reference[:-1])
        assert not module._binding_matches(value, reference + b"\x00")
    for left, right in ((False, 0), (True, 1), (1, 1.0), (0.0, -0.0), ({"a": 1, "b": 2}, {"b": 2, "a": 1})):
        assert not module._binding_matches(left, original._exact_binding(right))


def test_streamed_comparison_keeps_limits_cycles_and_custom_rejection(module, monkeypatch):
    callbacks = []

    class Hostile:
        def __reduce_ex__(self, _protocol):
            callbacks.append("reduce")
            raise AssertionError

        def __buffer__(self, _flags):
            callbacks.append("buffer")
            raise AssertionError

    class CustomBytes(bytes):
        def __len__(self):
            callbacks.append("length")
            raise AssertionError

    # A prior byte mismatch must not skip rejection of later custom material.
    with pytest.raises(TypeError, match="custom_input"):
        module._binding_matches(["x" * 131072, Hostile()], b"mismatch")
    for target in (
        lambda: module._BindingComparator(CustomBytes(b"x")),
        lambda: module._BindingComparator(b"x").write(CustomBytes(b"x")),
    ):
        with pytest.raises(TypeError, match="custom_binding"):
            target()
    cycle = []
    cycle.append(cycle)
    with pytest.raises((ValueError, RecursionError)):
        module._binding_matches(cycle, b"not a cycle")
    assert callbacks == []
    monkeypatch.setattr(module, "MAX_BINDING_BYTES", 64)
    with pytest.raises(ValueError, match="binding_limit"):
        module._BindingComparator(b"x" * 65)
    output = module._BindingComparator(b"x" * 64)
    assert output.write(b"x" * 64) == 64
    assert output.matches()
    with pytest.raises(ValueError, match="binding_limit"):
        output.write(b"x")
    with pytest.raises(ValueError, match="binding_limit"):
        module._binding_matches("x" * 100, b"mismatch")


def test_unrelated_child_replies_and_notifications_preserve_their_existing_writer(tmp_path, pilot):
    proxy, messages, _marker = _session(tmp_path)
    request = pilot.own_request(messages[-1])
    assert request is not None and request.generation is None
    stream = io.StringIO()
    forwarded = [
        {"jsonrpc": "2.0", "id": "nested-response", "result": {"method": "tools/call"}},
        {"jsonrpc": "2.0", "method": "notifications/progress", "params": {"progress": 1}},
    ]
    token = pilot.context.set(request)
    try:
        for message in forwarded:
            proxy._forward_notification(message, stream)
            assert pilot.context.get() is request
    finally:
        pilot.context.reset(token)
    assert [json.loads(line) for line in stream.getvalue().splitlines()] == forwarded
    assert pilot.counters["bound_forwards"] == 0

"""Unexecuted proposal controls for the bounded RSP-100 authority pair.

These tests use fresh source paths only. They do not install historical adapters,
run benchmark workers, alter campaign plans, or claim full RSP-100 acceptance.
"""

from __future__ import annotations

import contextvars
import json
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import replace

import pytest

from codex_plugin_scanner.guard import mcp_request_risk as sharing
from codex_plugin_scanner.guard import mcp_tool_calls as calls
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.mcp_authority_binding import proxy_authority_scope
from codex_plugin_scanner.guard.proxy import runtime_mcp
from codex_plugin_scanner.guard.proxy.tool_call_binding import bind_tool_call, use_tool_call_binding
from codex_plugin_scanner.guard.runtime import browser_mcp_intent as browser

from .test_mcp_owned_preparation_pilot import _session


@contextmanager
def _observed(hook=None):
    # A profile observer leaves the helper implementation identities unchanged.
    codes = {
        calls.tool_call_risk_categories.__code__: "categories",
        calls._tool_call_risk_signals_for_categories.__code__: "signals",
        GuardConfig.resolve_action_override.__code__: "policy",
    }
    seen = Counter()
    previous = sys.getprofile()

    def observe(frame, event, value):
        if event == "call" and frame.f_code in codes:
            seen[codes[frame.f_code]] += 1
        if hook is not None:
            hook(frame, event, value, seen)

    sys.setprofile(observe)
    try:
        yield seen
    finally:
        sys.setprofile(previous)


def _resolve(proxy, message):
    binding = bind_tool_call(message)
    assert binding is not None
    params = binding.owned_message["params"]
    with proxy_authority_scope(), use_tool_call_binding(binding):
        return proxy._resolve_tool_call_authority(tool_name=params["name"], arguments=params.get("arguments"))


def _assert_uncached_parity(proxy, authority, arguments):
    # Compare the same captured authority inputs. A fresh executable resolution
    # may intentionally issue a different nonce before a session starts.
    original_artifact = deepcopy(authority.artifact)
    with proxy_authority_scope(), use_tool_call_binding(None), _observed() as counts:
        artifact, artifact_hash, decision = proxy._evaluate_tool_call_authority(
            artifact=authority.artifact, arguments=arguments, config=proxy.config
        )
    assert counts == {"categories": 2, "signals": 1, "policy": 2}
    assert artifact is authority.artifact
    assert authority.artifact == original_artifact
    assert artifact_hash == authority.artifact_hash
    assert decision == authority.decision


def test_admitted_pair_derives_once_and_each_later_invocation_is_fresh(tmp_path):
    proxy, messages, _marker = _session(tmp_path)
    message = messages[-1]
    with _observed() as direct_counts:
        direct = proxy._resolve_tool_call_authority(
            tool_name=message["params"]["name"], arguments=message["params"]["arguments"]
        )
    assert direct_counts == {"categories": 2, "signals": 1, "policy": 2}
    with _observed() as counts:
        first = _resolve(proxy, message)
        second = _resolve(proxy, message)
    assert counts == {"categories": 2, "signals": 2, "policy": 4}
    assert first.artifact is not second.artifact
    for authority in (direct, first, second):
        _assert_uncached_parity(proxy, authority, message["params"]["arguments"])
    assert sharing._OWNER.get() is None
    assert not hasattr(first, "risk_facts")


def test_real_stdio_keeps_child_bytes_and_once_only_pair(tmp_path):
    proxy, messages, marker = _session(tmp_path)
    with _observed() as counts:
        result = proxy.run_session(messages)
    assert counts["categories"] == counts["signals"] == 1
    assert counts["policy"] == 2
    assert json.loads(marker.read_text()) == messages[-1]
    assert result["responses"][-1]["result"]["content"][0]["text"] == "forwarded"


@pytest.mark.parametrize("name", ["build_tool_call_hash", "evaluate_tool_call"])
def test_replaced_public_alias_receives_original_kwargs_and_runs_uncached(tmp_path, monkeypatch, name):
    proxy, messages, _marker = _session(tmp_path)
    original = getattr(runtime_mcp, name)
    reached = []

    def callback(*args, **kwargs):
        assert "risk_facts" not in kwargs
        reached.append(name)
        return original(*args, **kwargs)

    monkeypatch.setattr(runtime_mcp, name, callback)
    with _observed() as counts:
        _resolve(proxy, messages[-1])
    assert reached == [name]
    assert counts["categories"] == 2


@pytest.mark.parametrize("name", ["_tool_call_risk_category_set", "_schema_risk_categories"])
def test_changed_helper_between_consumers_recomputes_without_public_alias_bypass(tmp_path, monkeypatch, name):
    proxy, messages, _marker = _session(tmp_path)
    original_check = proxy._check_tool_call_preparation
    original = getattr(calls, name)
    preparations = []

    def prepare():
        preparations.append(True)
        if len(preparations) == 2:

            def changed(*args, **kwargs):
                return original(*args, **kwargs) | {"secret_access"}

            monkeypatch.setattr(calls, name, changed)
        return original_check()

    monkeypatch.setattr(proxy, "_check_tool_call_preparation", prepare)
    with _observed() as counts:
        result = _resolve(proxy, messages[-1])
    assert len(preparations) == 3
    assert counts["categories"] == 2
    assert "secret_access" in result.decision.risk_categories


def test_helper_change_after_second_policy_callback_recomputes(tmp_path, monkeypatch):
    proxy, messages, _marker = _session(tmp_path)
    original = calls._tool_call_risk_category_set
    policy_code = GuardConfig.resolve_action_override.__code__
    changed = []

    def observe(frame, event, _value, counts):
        if event == "return" and frame.f_code is policy_code and counts["policy"] == 2 and not changed:
            changed.append(True)
            monkeypatch.setattr(
                calls,
                "_tool_call_risk_category_set",
                lambda artifact, arguments: original(artifact, arguments) | {"secret_access"},
            )

    with _observed(observe) as counts:
        result = _resolve(proxy, messages[-1])
    assert changed == [True]
    assert counts["categories"] == 2
    assert "secret_access" in result.decision.risk_categories


@pytest.mark.parametrize("mutation", ["arguments", "catalog", "policy", "artifact"])
def test_bound_input_or_authority_change_never_reuses_prior_facts(tmp_path, mutation):
    proxy, messages, _marker = _session(tmp_path)
    proxy.config = replace(proxy.config, artifact_actions={})
    category_code = calls.tool_call_risk_categories.__code__
    changed = []

    def observe(frame, event, _value, _counts):
        if event != "return" or frame.f_code is not category_code or changed:
            return
        changed.append(True)
        if mutation == "arguments":
            frame.f_locals["arguments"]["text"] = "changed"
        elif mutation == "catalog":
            proxy._tool_catalog_generation += 1
        elif mutation == "policy":
            proxy.config.artifact_actions["changed"] = "block"
        else:
            frame.f_locals["artifact"].runtime_private_metadata["changed"] = True

    with _observed(observe), pytest.raises(runtime_mcp.framing.ProxyIoLimitError):
        _resolve(proxy, messages[-1])
    assert changed == [True]
    assert sharing._OWNER.get() is None


def test_exception_expires_token_and_does_not_poison_next_invocation(tmp_path):
    proxy, messages, _marker = _session(tmp_path)
    target = calls._tool_call_policy_context.__code__
    captured = []

    def observe(frame, event, _value, _counts):
        if event == "call" and frame.f_code is target:
            captured.append(sharing._OWNER.get())
            raise RuntimeError("injected after category derivation")

    with _observed(observe), pytest.raises(RuntimeError, match="injected"):
        _resolve(proxy, messages[-1])
    assert len(captured) == 1 and captured[0] is not None
    assert captured[0]._closed is True
    assert captured[0]._categories is None
    assert sharing._OWNER.get() is None
    with _observed() as counts:
        _resolve(proxy, messages[-1])
    assert counts["categories"] == 1


def test_nested_resolution_disables_parent_and_nested_sharing(tmp_path):
    proxy, messages, _marker = _session(tmp_path)
    target = calls.tool_call_risk_categories.__code__
    nested = []

    def observe(frame, event, _value, _counts):
        if event == "call" and frame.f_code is target and not nested:
            # Profiling callbacks do not recursively profile their own calls.
            nested.append(_resolve(proxy, messages[-1]))

    with _observed(observe) as counts:
        outer = _resolve(proxy, messages[-1])
    assert len(nested) == 1
    assert counts["categories"] == 2
    assert sharing._OWNER.get() is None
    for authority in (outer, nested[0]):
        _assert_uncached_parity(proxy, authority, messages[-1]["params"]["arguments"])


def test_copied_context_in_another_thread_cannot_consume_the_token(tmp_path):
    proxy, messages, _marker = _session(tmp_path)
    target = calls._tool_call_policy_context.__code__
    observed = []

    def observe(frame, event, _value, _counts):
        if event == "call" and frame.f_code is target and not observed:
            facts = sharing._OWNER.get()
            assert facts is not None
            context = contextvars.copy_context()
            with ThreadPoolExecutor(max_workers=1) as executor:
                observed.append(executor.submit(context.run, facts.supported).result())
            assert facts._closed is True

    with _observed(observe) as counts:
        _resolve(proxy, messages[-1])
    assert observed == [False]
    assert counts["categories"] == 2
    assert sharing._OWNER.get() is None


@pytest.mark.parametrize("shape", ["plain", "secret", "schema", "description", "browser"])
def test_production_graph_admits_each_supported_risk_shape(tmp_path, shape):
    assert calls._RISK_PAIR_HELPERS.available, calls._RISK_PAIR_HELPERS.refusal_reason
    proxy, messages, _marker = _session(tmp_path)
    message = messages[-1]
    definition = {"name": "safe_echo", "inputSchema": {"type": "object"}}
    if shape == "secret":
        message["params"]["arguments"] = {"path": "/tmp/.env"}
    elif shape == "schema":
        definition["inputSchema"] = {"type": "object", "properties": {"command": {"type": "string"}}}
    elif shape == "description":
        definition["description"] = "Execute shell commands and read secrets."
    elif shape == "browser":
        proxy.server_name = "playwright"
        message["params"]["name"] = "browser_navigate"
        message["params"]["arguments"] = {"url": "https://example.test/path"}
        definition["name"] = "browser_navigate"
    proxy._tool_catalog[definition["name"]] = definition
    proxy._tool_catalog_state = "complete"
    with _observed() as counts:
        actual = _resolve(proxy, message)
    assert counts == {"categories": 1, "signals": 1, "policy": 2}
    _assert_uncached_parity(proxy, actual, message["params"]["arguments"])


def test_module_member_change_between_consumers_refuses_sharing(tmp_path, monkeypatch):
    proxy, messages, _marker = _session(tmp_path)
    original_check = proxy._check_tool_call_preparation
    original_dumps = calls.json.dumps
    preparations = []
    reached = []

    def changed(*args, **kwargs):
        reached.append(True)
        return original_dumps(*args, **kwargs)

    def prepare():
        preparations.append(True)
        if len(preparations) == 2:
            monkeypatch.setattr(calls.json, "dumps", changed)
        original_check()

    monkeypatch.setattr(proxy, "_check_tool_call_preparation", prepare)
    with _observed() as counts:
        _resolve(proxy, messages[-1])
    assert len(preparations) == 3
    assert reached
    assert counts["categories"] == 2


@pytest.mark.parametrize("owner_name", ["literal", "browser"])
def test_existing_class_constructor_change_refuses_sharing(tmp_path, monkeypatch, owner_name):
    proxy, messages, _marker = _session(tmp_path)
    if owner_name == "browser":
        proxy.server_name = "playwright"
        messages[-1]["params"] = {"name": "browser_navigate", "arguments": {"url": "https://example.test/path"}}
        owner = browser.GuardBrowserAutomationIntentV1
    else:
        owner = calls._LiteralRiskPattern
    original_init = owner.__init__
    original_check = proxy._check_tool_call_preparation
    preparations = []

    def changed(self, *args, **kwargs):
        return original_init(self, *args, **kwargs)

    def prepare():
        preparations.append(True)
        if len(preparations) == 2:
            monkeypatch.setattr(owner, "__init__", changed)
        original_check()

    monkeypatch.setattr(proxy, "_check_tool_call_preparation", prepare)
    with _observed() as counts:
        _resolve(proxy, messages[-1])
    assert counts["categories"] == 2


def test_helper_change_on_final_authority_return_refuses_cached_categories(tmp_path, monkeypatch):
    proxy, messages, _marker = _session(tmp_path)
    original = calls._tool_call_risk_category_set
    changed = []

    def observe(frame, event, _value, _counts):
        facts = sharing._OWNER.get()
        if (
            event == "return"
            and facts is not None
            and facts._phase == "current"
            and facts.authority_check is not None
            and frame.f_code is facts.authority_check.__code__
            and frame.f_back is not None
            and frame.f_back.f_code is sharing.InvocationRiskFacts.categories.__code__
            and not changed
        ):
            changed.append(True)
            monkeypatch.setattr(
                calls,
                "_tool_call_risk_category_set",
                lambda artifact, arguments: original(artifact, arguments) | {"secret_access"},
            )

    with _observed(observe) as counts:
        actual = _resolve(proxy, messages[-1])
    assert changed == [True]
    assert counts["categories"] == 2
    assert "secret_access" in actual.decision.risk_categories


def test_replaced_private_hash_kernel_keeps_original_signature(tmp_path, monkeypatch):
    proxy, messages, _marker = _session(tmp_path)
    original = calls._build_tool_call_hash_for_categories
    reached = []

    def kernel(artifact, arguments, *, workspace, config, risk_categories):
        reached.append(True)
        return original(artifact, arguments, workspace=workspace, config=config, risk_categories=risk_categories)

    monkeypatch.setattr(calls, "_build_tool_call_hash_for_categories", kernel)
    with _observed() as counts:
        _resolve(proxy, messages[-1])
    assert reached == [True]
    assert counts["categories"] == 2


def test_existing_explicit_snapshot_facts_keep_original_public_behavior(tmp_path):
    from .test_mcp_request_risk_facts import _artifact

    proxy, _messages, _marker = _session(tmp_path)
    artifact = _artifact("run_terminal_command")
    arguments = {"command": "cat .env"}
    options = {"workspace": tmp_path, "config": proxy.config}
    expected_hash = calls.build_tool_call_hash(artifact, arguments, **options)
    expected = calls.evaluate_tool_call(
        store=proxy.store,
        config=proxy.config,
        artifact=artifact,
        artifact_hash=expected_hash,
        arguments=arguments,
        claim_saved_approval=False,
    )
    facts = calls.prepare_tool_call_risk_facts(artifact, arguments)
    assert facts is not None
    with _observed() as counts:
        actual_hash = calls.build_tool_call_hash(artifact, arguments, **options, risk_facts=facts)
        actual = calls.evaluate_tool_call(
            store=proxy.store,
            config=proxy.config,
            artifact=artifact,
            artifact_hash=actual_hash,
            arguments=arguments,
            claim_saved_approval=False,
            risk_facts=facts,
        )
    assert actual_hash == expected_hash
    assert actual == expected
    assert counts["categories"] == 0
    assert counts["signals"] == 1
    assert counts["policy"] == 2
    assert sharing._OWNER.get() is None


def test_python_only_string_arguments_keep_the_uncached_path(tmp_path):
    proxy, messages, _marker = _session(tmp_path)
    messages[-1]["params"]["arguments"] = '{"url": "https://example.test"}'
    with _observed() as counts:
        _resolve(proxy, messages[-1])
    assert counts["categories"] == 2
    assert counts["signals"] == 1


def test_browser_local_import_mutation_between_consumers_recomputes(tmp_path, monkeypatch):
    import urllib.parse

    proxy, messages, _marker = _session(tmp_path)
    proxy.server_name = "playwright"
    message = messages[-1]
    message["params"] = {
        "name": "browser_navigate",
        "arguments": {"url": "https://example.test/path?token=secret#token=secret"},
    }
    original_parse = urllib.parse.parse_qsl
    original_check = proxy._check_tool_call_preparation
    preparations = []
    reached = []

    def changed(*args, **kwargs):
        reached.append(True)
        return original_parse(*args, **kwargs)

    def prepare():
        preparations.append(True)
        if len(preparations) == 2:
            monkeypatch.setattr(urllib.parse, "parse_qsl", changed)
        original_check()

    monkeypatch.setattr(proxy, "_check_tool_call_preparation", prepare)
    with _observed() as counts:
        _resolve(proxy, message)
    assert len(preparations) == 3
    assert counts["categories"] == 2
    assert reached


def test_config_dispatch_change_between_consumers_keeps_callbacks(tmp_path, monkeypatch):
    proxy, messages, _marker = _session(tmp_path)
    original_check = proxy._check_tool_call_preparation
    preparations = []
    reached = []

    def changed(self, name):
        if name == "resolve_action_override":
            reached.append(name)
        return object.__getattribute__(self, name)

    def prepare():
        preparations.append(True)
        if len(preparations) == 2:
            monkeypatch.setattr(type(proxy.config), "__getattribute__", changed)
        original_check()

    monkeypatch.setattr(proxy, "_check_tool_call_preparation", prepare)
    with _observed() as counts:
        _resolve(proxy, messages[-1])
    assert len(preparations) == 3
    assert counts["categories"] == 2
    assert counts["policy"] == 2
    assert reached

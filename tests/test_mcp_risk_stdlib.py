"""Bound only the actual CPython helper forms used by supported interpreters."""

from __future__ import annotations

import re
from operator import attrgetter
from pathlib import PurePath

import pytest

from codex_plugin_scanner.guard import mcp_risk_stdlib as leaves
from codex_plugin_scanner.guard.mcp_risk_dependencies import _HelperBinding

from .test_mcp_risk_dependencies import _capture, _config, _namespace


def _global_capture(value):
    namespace = _namespace("def risk(): return dependency\n")
    namespace["dependency"] = value
    helpers = _capture(namespace)
    return namespace, helpers


def _sentinel():
    value = re.__dict__.get("_zero_sentinel")
    if value is None:
        pytest.skip("re._zero_sentinel is introduced by Python 3.13")
    assert leaves.is_re_zero_sentinel(value)
    return value


def test_live_stdlib_producers_have_bound_state():
    getter = attrgetter("_drv")
    namespace, helpers = _global_capture(getter)
    assert helpers.available and helpers.unchanged(_config(), namespace)
    with pytest.raises(AttributeError):
        getter.extra_state = True
    path = _HelperBinding.capture({"PurePath": PurePath}, "PurePath")
    assert path.unchanged()
    regex = _HelperBinding.capture({"sub": re.sub}, "sub")
    assert regex.unchanged()
    if "_zero_sentinel" in re.__dict__:
        sentinel = re.__dict__["_zero_sentinel"]
        assert leaves.is_re_zero_sentinel(sentinel)
        namespace, helpers = _global_capture(sentinel)
        assert helpers.available and helpers.unchanged(_config(), namespace)


def test_equal_attrgetter_replacement_invalidates_identity():
    namespace, helpers = _global_capture(attrgetter("_drv"))
    assert helpers.available and helpers.unchanged(_config(), namespace)
    namespace["dependency"] = attrgetter("_drv")
    assert helpers.unchanged(_config(), namespace) is False


def test_path_property_getter_replacement_invalidates(monkeypatch):
    namespace, helpers = _global_capture(PurePath)
    assert helpers.available and helpers.unchanged(_config(), namespace)
    with monkeypatch.context() as scoped:
        scoped.setattr(PurePath, "drive", property(attrgetter("_root")))
        unchanged = helpers.unchanged(_config(), namespace)
    assert unchanged is False
    assert helpers.unchanged(_config(), namespace)


@pytest.mark.parametrize("kind", ["callable", "int-subclass", "opaque"])
def test_unrelated_callable_and_integer_objects_remain_unsupported(kind):
    calls = []

    class CallableObject:
        def __call__(self):
            calls.append("call")

    class IntegerObject(int):
        def __int__(self):
            calls.append("int")
            return 0

    value = {"callable": CallableObject(), "int-subclass": IntegerObject(0), "opaque": object()}[kind]
    namespace, helpers = _global_capture(value)
    assert helpers.available is False
    assert helpers.unchanged(_config(), namespace) is False
    assert calls == []


@pytest.mark.parametrize("name", ["_zero_sentinel", "_ZeroSentinel"])
def test_re_sentinel_current_module_links_are_required(monkeypatch, name):
    sentinel = _sentinel()
    namespace, helpers = _global_capture(sentinel)
    assert helpers.available and helpers.unchanged(_config(), namespace)
    with monkeypatch.context() as scoped:
        scoped.setitem(re.__dict__, name, object())
        unchanged = helpers.unchanged(_config(), namespace)
    assert unchanged is False
    assert helpers.unchanged(_config(), namespace)


def test_another_zero_instance_is_not_the_retained_sentinel():
    sentinel = _sentinel()
    value = type(sentinel)(0)
    assert value is not sentinel
    namespace, helpers = _global_capture(value)
    assert helpers.available is False
    assert helpers.unchanged(_config(), namespace) is False


@pytest.mark.parametrize("name", ["__repr__", "__int__", "__getattribute__"])
def test_sentinel_class_dispatch_changes_refuse_without_invocation(monkeypatch, name):
    sentinel = _sentinel()
    namespace, helpers = _global_capture(sentinel)
    assert helpers.available and helpers.unchanged(_config(), namespace)
    calls = []

    def changed(*args):
        calls.append(args)
        raise AssertionError("the dependency observer invoked changed dispatch")

    with monkeypatch.context() as scoped:
        scoped.setattr(type(sentinel), name, changed, raising=False)
        unchanged = helpers.unchanged(_config(), namespace)
    assert unchanged is False
    assert calls == []
    assert helpers.unchanged(_config(), namespace)


def test_sentinel_native_dictionary_descriptor_cannot_be_replaced():
    sentinel = _sentinel()
    original = type.__getattribute__(type(sentinel), "__dict__")["__dict__"]
    calls = []

    def changed(_value):
        calls.append("descriptor")
        return {}

    with pytest.raises((AttributeError, TypeError)):
        type(sentinel).__dict__ = property(changed)
    assert type.__getattribute__(type(sentinel), "__dict__")["__dict__"] is original
    assert calls == []


def test_sentinel_instance_mutation_is_bound_and_restored():
    sentinel = _sentinel()
    data = leaves.GetSetDescriptorType.__get__(leaves._ZERO_DICT, sentinel, type(sentinel))
    key = "_rsp100_mutation_control"
    assert key not in data
    data[key] = {"nested": [1]}
    try:
        namespace, helpers = _global_capture(sentinel)
        assert helpers.available and helpers.unchanged(_config(), namespace)
        data[key]["nested"].append(2)
        assert helpers.unchanged(_config(), namespace) is False
    finally:
        del data[key]


def test_sentinel_opaque_instance_state_declines_without_calling_it():
    sentinel = _sentinel()
    data = leaves.GetSetDescriptorType.__get__(leaves._ZERO_DICT, sentinel, type(sentinel))
    key = "_rsp100_opaque_control"
    assert key not in data
    data[key] = object()
    try:
        namespace, helpers = _global_capture(sentinel)
        assert helpers.available is False
        assert helpers.unchanged(_config(), namespace) is False
    finally:
        del data[key]


def test_sentinel_default_replacement_invalidates(monkeypatch):
    sentinel = _sentinel()
    namespace = _namespace("def risk(): return regex.sub('a', 'b', 'a')\n")
    namespace["regex"] = re
    helpers = _capture(namespace)
    assert helpers.available and helpers.unchanged(_config(), namespace)
    defaults = dict(re.sub.__kwdefaults__)
    assert any(value is sentinel for value in defaults.values())
    with monkeypatch.context() as scoped:
        scoped.setattr(re.sub, "__kwdefaults__", {name: object() for name in defaults})
        unchanged = helpers.unchanged(_config(), namespace)
    assert unchanged is False
    assert helpers.unchanged(_config(), namespace)


def test_forged_re_named_zero_producer_remains_unsupported(monkeypatch):
    calls = []

    class ForgedZero(int):
        def __int__(self):
            calls.append("int")
            raise AssertionError("a forged sentinel conversion was invoked")

    ForgedZero.__name__ = "_ZeroSentinel"
    ForgedZero.__qualname__ = "_ZeroSentinel"
    ForgedZero.__module__ = "re"
    forged = int.__new__(ForgedZero, 0)
    with monkeypatch.context() as scoped:
        scoped.setattr(re, "_zero_sentinel", forged, raising=False)
        scoped.setattr(re, "_ZeroSentinel", ForgedZero, raising=False)
        namespace, helpers = _global_capture(forged)
        available = helpers.available
        unchanged = helpers.unchanged(_config(), namespace)
    assert available is False
    assert unchanged is False
    assert calls == []

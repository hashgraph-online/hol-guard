"""Unexecuted dependency-capture controls for the RSP-100 proposal."""

from __future__ import annotations

import builtins
import sys
from types import FunctionType, ModuleType

import pytest

from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.mcp_risk_dependencies import ReviewedRiskHelpers, _plain_digest


def _namespace(body, *, future_annotations=True):
    # Real dataclasses resolve generated-method globals through sys.modules.
    # Use an actual scoped module and restore the previous entry exactly.
    name = "codex_plugin_scanner.guard._risk_dependency_control"
    module = ModuleType(name)
    missing = object()
    previous = sys.modules.get(name, missing)
    namespace = module.__dict__
    # Match the explicit compiler mode of the production dataclass modules.
    prefix = "from __future__ import annotations\n" if future_annotations else ""
    source = prefix + "def build_tool_call_hash(): pass\ndef evaluate_tool_call(): pass\n" + body
    sys.modules[name] = module
    try:
        exec(compile(source, "<risk_dependency_control>", "exec", dont_inherit=True), namespace)
    finally:
        if previous is missing:
            del sys.modules[name]
        else:
            sys.modules[name] = previous
    return namespace


def _config():
    # Dependency guards inspect type/dispatch only; the authority layer owns data.
    return object.__new__(GuardConfig)


def _capture(namespace):
    return ReviewedRiskHelpers(
        namespace=namespace,
        pure_roots=("risk",),
        consumers=("build_tool_call_hash", "evaluate_tool_call"),
        policy_type=GuardConfig,
        policy_methods=("resolve_action_override", "resolve_artifact_or_publisher_action_override"),
    )


@pytest.mark.parametrize("kind", ["cycle", "opaque", "oversize"])
def test_unsupported_capture_refuses_sharing_without_breaking_import(kind):
    namespace = _namespace("def risk(value=None): return value\n")
    if kind == "cycle":
        value = []
        value.append(value)
    elif kind == "oversize":
        value = list(range(5000))
    else:
        value = object()
    namespace["risk"].__defaults__ = (value,)
    helpers = _capture(namespace)
    assert helpers.available is False
    assert helpers.refusal_reason == "unsupported_helper_dependency"
    assert helpers.unchanged(_config(), namespace) is False


def test_nested_code_global_changes_are_bound():
    namespace = _namespace(
        "def transform(value): return value\ndef risk(): return tuple(transform(value) for value in range(2))\n"
    )
    helpers = _capture(namespace)
    assert helpers.available
    assert helpers.unchanged(_config(), namespace)
    namespace["transform"] = lambda value: value + 1
    assert helpers.unchanged(_config(), namespace) is False


def test_attribute_name_is_not_mistaken_for_unrelated_global():
    namespace = _namespace("def risk(value): return value.get('key')\n")
    namespace["get"] = object()
    helpers = _capture(namespace)
    assert helpers.available
    assert helpers.unchanged(_config(), namespace)
    namespace["get"] = object()
    assert helpers.unchanged(_config(), namespace)


def test_executed_module_attribute_changes_are_bound():
    namespace = _namespace("def risk(): return helper.value()\n")
    helper = ModuleType("risk_control")
    helper.value = lambda: 1
    namespace["helper"] = helper
    helpers = _capture(namespace)
    assert helpers.available
    assert helpers.unchanged(_config(), namespace)
    helper.value = lambda: 2
    assert helpers.unchanged(_config(), namespace) is False


def test_existing_constructor_code_change_is_bound(monkeypatch):
    namespace = _namespace(
        "class Value:\n    def __init__(self, value): self.value = value\ndef risk(): return Value(1).value\n"
    )
    helpers = _capture(namespace)
    assert helpers.available
    constructor = namespace["Value"].__init__

    def changed(self, value):
        self.value = value + 1

    monkeypatch.setattr(constructor, "__code__", changed.__code__)
    assert helpers.unchanged(_config(), namespace) is False


def test_mutable_set_inside_default_is_bound():
    namespace = _namespace("def risk(value={'tags': {'first'}}): return value\n")
    helpers = _capture(namespace)
    assert helpers.available
    namespace["risk"].__defaults__[0]["tags"].add("second")
    assert helpers.unchanged(_config(), namespace) is False


def test_set_and_tuple_encodings_cannot_alias():
    assert _plain_digest({"value": {"first"}}) != _plain_digest({"value": ("set", ("first",))})


def test_new_global_shadow_of_builtin_is_bound():
    namespace = _namespace("def risk(value): return len(value)\n")
    helpers = _capture(namespace)
    assert helpers.available
    namespace["len"] = lambda value: 0
    assert helpers.unchanged(_config(), namespace) is False


def test_frozen_dataclass_constructor_closure_is_supported():
    namespace = _namespace(
        "from dataclasses import dataclass\n"
        "@dataclass(frozen=True, slots=True)\n"
        "class Value:\n"
        "    number: int\n"
        "def risk(): return Value(1).number\n"
    )
    helpers = _capture(namespace)
    assert helpers.available, helpers.refusal_reason
    assert helpers.unchanged(_config(), namespace)


def test_nonfuture_dataclass_annotation_producer_is_observed_without_evaluation():
    namespace = _namespace(
        "from dataclasses import dataclass\n"
        "@dataclass(frozen=True, slots=True)\n"
        "class Value:\n"
        "    number: int\n"
        "def risk(): return Value(1).number\n",
        future_annotations=False,
    )
    value_type = namespace["Value"]
    annotations = tuple(
        member
        for member in vars(value_type).values()
        if type(member) is FunctionType and member.__name__ == "__annotate__"
    )
    calls = []

    def observe(frame, event, _arg):
        if event == "call" and any(frame.f_code is function.__code__ for function in annotations):
            calls.append(frame.f_code)

    previous = sys.getprofile()
    sys.setprofile(observe)
    try:
        helpers = _capture(namespace)
        unchanged = helpers.unchanged(_config(), namespace)
    finally:
        sys.setprofile(previous)
    assert calls == []
    assert value_type(1).number == 1
    if annotations:
        # Python 3.14 produces deferred annotation closures containing callable
        # dictionaries. These remain outside the supported plain-data graph.
        assert helpers.available is False
        assert helpers.refusal_reason == "unsupported_helper_dependency"
        assert unchanged is False
    else:
        # Earlier interpreters produce ordinary evaluated annotations here.
        assert helpers.available, helpers.refusal_reason
        assert unchanged


def test_cached_local_from_import_member_changes_are_bound(monkeypatch):
    import urllib.parse

    namespace = _namespace(
        "def risk(value):\n    from urllib.parse import parse_qsl, urlencode\n    return urlencode(parse_qsl(value))\n"
    )
    helpers = _capture(namespace)
    assert helpers.available, helpers.refusal_reason
    assert helpers.unchanged(_config(), namespace)
    monkeypatch.setattr(urllib.parse, "parse_qsl", lambda value: [])
    assert helpers.unchanged(_config(), namespace) is False


def test_cached_local_import_module_replacement_is_bound(monkeypatch):
    import sys
    import urllib.parse

    namespace = _namespace("def risk(value):\n    from urllib.parse import parse_qsl\n    return parse_qsl(value)\n")
    helpers = _capture(namespace)
    assert helpers.available, helpers.refusal_reason
    replacement = ModuleType("urllib.parse")
    replacement.parse_qsl = urllib.parse.parse_qsl
    monkeypatch.setitem(sys.modules, "urllib.parse", replacement)
    assert helpers.unchanged(_config(), namespace) is False


@pytest.mark.parametrize(
    "statement",
    [
        "import urllib.parse",
        "from .unknown import value",
        "from ..unknown import value",
        "from _rsp100_uncached_dependency import value",
    ],
)
def test_unreviewed_local_import_shape_declines_without_import(statement):
    assert "_rsp100_uncached_dependency" not in sys.modules
    namespace = _namespace("def risk():\n    " + statement + "\n    return None\n")
    observed_imports = []
    original_import = builtins.__import__
    previous_profile = sys.getprofile()

    def observe(_frame, event, argument):
        if event == "c_call" and argument is original_import:
            observed_imports.append("import")

    sys.setprofile(observe)
    try:
        helpers = _capture(namespace)
    finally:
        sys.setprofile(previous_profile)
    assert helpers.available is False
    assert helpers.refusal_reason == "unsupported_helper_dependency"
    assert observed_imports == []


def test_existing_class_method_global_change_is_bound():
    namespace = _namespace(
        "value = 1\nclass Value:\n    def __init__(self): self.number = value\ndef risk(): return Value().number\n"
    )
    helpers = _capture(namespace)
    assert helpers.available, helpers.refusal_reason
    namespace["value"] = 2
    assert helpers.unchanged(_config(), namespace) is False


def test_owned_closure_helper_global_change_is_bound():
    namespace = _namespace(
        "value = 1\n"
        "def helper(): return value\n"
        "def make(helper):\n"
        "    def risk(): return helper()\n"
        "    return risk\n"
        "risk = make(helper)\n"
    )
    helpers = _capture(namespace)
    assert helpers.available, helpers.refusal_reason
    namespace["value"] = 2
    assert helpers.unchanged(_config(), namespace) is False


def test_unknown_closure_function_declines():
    namespace = _namespace(
        "def make(helper):\n    def risk(): return helper()\n    return risk\nrisk = make(lambda: 1)\n"
    )
    namespace["risk"].__closure__[0].cell_contents.__module__ = "unknown_plugin"
    helpers = _capture(namespace)
    assert helpers.available is False


def test_policy_instance_dispatch_mutation_is_bound(monkeypatch):
    namespace = _namespace("def risk(value): return value\n")
    helpers = _capture(namespace)
    assert helpers.available, helpers.refusal_reason
    assert helpers.unchanged(_config(), namespace)

    def changed(self, name):
        return object.__getattribute__(self, name)

    monkeypatch.setattr(GuardConfig, "__getattribute__", changed)
    assert helpers.unchanged(_config(), namespace) is False


def test_source_class_with_opaque_existing_descriptor_declines():
    namespace = _namespace("class Value: pass\ndef risk(): return Value().number\n")

    class Descriptor:
        def __get__(self, _instance, _owner):
            return 1

    namespace["Value"].number = Descriptor()
    helpers = _capture(namespace)
    assert helpers.available is False


@pytest.mark.parametrize("name", ["__getstate__", "__setstate__", "__replace__"])
def test_generated_copy_or_serialization_hook_state_remains_bound(monkeypatch, name):
    namespace = _namespace(
        "from dataclasses import dataclass\n"
        "@dataclass(frozen=True, slots=True)\n"
        "class Value:\n"
        "    number: int\n"
        "def risk(): return Value(1).number\n"
    )
    helpers = _capture(namespace)
    assert helpers.available, helpers.refusal_reason
    hook = getattr(namespace["Value"], name, None)
    if hook is None:
        pytest.skip("__replace__ is introduced by Python 3.13")

    def changed(self):
        return []

    monkeypatch.setattr(hook, "__code__", changed.__code__)
    assert helpers.unchanged(_config(), namespace) is False


@pytest.mark.parametrize("replacement", ["global_shadow", "builtin"])
def test_not_implemented_singleton_is_bound_and_replacement_invalidates(monkeypatch, replacement):
    import builtins

    namespace = _namespace("def risk(): return NotImplemented\n")
    helpers = _capture(namespace)
    assert helpers.available, helpers.refusal_reason
    assert helpers.unchanged(_config(), namespace)
    assert namespace["risk"]() is NotImplemented
    with monkeypatch.context() as change:
        if replacement == "global_shadow":
            change.setitem(namespace, "NotImplemented", object())
        else:
            change.setattr(builtins, "NotImplemented", object())
        unchanged = helpers.unchanged(_config(), namespace)
    assert unchanged is False


def test_dataclass_comparison_code_change_invalidates_supported_singleton(monkeypatch):
    namespace = _namespace(
        "from dataclasses import dataclass\n"
        "@dataclass(frozen=True, slots=True)\n"
        "class Value:\n"
        "    number: int\n"
        "def risk(): return Value(1).number\n"
    )
    helpers = _capture(namespace)
    assert helpers.available, helpers.refusal_reason
    comparison = namespace["Value"].__eq__
    assert comparison(namespace["Value"](1), object()) is NotImplemented

    def changed(self, other):
        return True

    monkeypatch.setattr(comparison, "__code__", changed.__code__)
    assert helpers.unchanged(_config(), namespace) is False


def test_arbitrary_opaque_global_remains_unsupported():
    namespace = _namespace("def risk(): return opaque\n")
    namespace["opaque"] = object()
    helpers = _capture(namespace)
    assert helpers.available is False
    assert helpers.refusal_reason == "unsupported_helper_dependency"


def test_stdlib_callable_default_is_supported_without_invocation_during_capture():
    import urllib.parse

    namespace = _namespace("def risk(value):\n    from urllib.parse import urlencode\n    return urlencode(value)\n")
    helpers = _capture(namespace)
    assert helpers.available, helpers.refusal_reason
    assert helpers.unchanged(_config(), namespace)
    assert namespace["risk"]({"space": "a b"}) == urllib.parse.urlencode({"space": "a b"})


@pytest.mark.parametrize("kind", ["positional", "keyword"])
def test_callable_default_identity_change_invalidates(kind):
    signature = "formatter=helper" if kind == "positional" else "*, formatter=helper"
    namespace = _namespace(f"def helper(value): return value\ndef risk(value, {signature}): return formatter(value)\n")
    helpers = _capture(namespace)
    assert helpers.available, helpers.refusal_reason
    assert helpers.unchanged(_config(), namespace)
    if kind == "positional":
        namespace["risk"].__defaults__ = (lambda value: value + 1,)
    else:
        namespace["risk"].__kwdefaults__["formatter"] = lambda value: value + 1
    assert helpers.unchanged(_config(), namespace) is False


@pytest.mark.parametrize("changed", ["code", "defaults", "global"])
def test_source_callable_default_dependency_changes_invalidate(monkeypatch, changed):
    namespace = _namespace(
        "offset = 1\n"
        "def helper(value, extra=1): return value + extra + offset\n"
        "def risk(value, formatter=helper): return formatter(value)\n"
    )
    # The helper is reached exclusively through the retained default, so
    # ordinary risk bytecode traversal cannot bind its global dependencies.
    helper = namespace.pop("helper")
    helpers = _capture(namespace)
    assert helpers.available, helpers.refusal_reason
    assert helpers.unchanged(_config(), namespace)
    if changed == "code":

        def replacement(value, extra=1):
            return value + extra + 4

        monkeypatch.setattr(helper, "__code__", replacement.__code__)
    elif changed == "defaults":
        helper.__defaults__ = (3,)
    else:
        namespace["offset"] = 3
    assert helpers.unchanged(_config(), namespace) is False


def test_callable_default_capture_never_calls_the_default():
    namespace = _namespace(
        "def helper(value): raise AssertionError('must not execute')\n"
        "def risk(value, formatter=helper): return formatter(value)\n"
    )
    helpers = _capture(namespace)
    assert helpers.available, helpers.refusal_reason
    assert helpers.unchanged(_config(), namespace)


@pytest.mark.parametrize("kind", ["cycle", "opaque", "nested_callable", "external_closure", "budget"])
def test_unreviewed_callable_default_shapes_refuse(kind):
    namespace = _namespace(
        "def helper(value=None): return value\ndef risk(value, formatter=helper): return formatter(value)\n"
    )
    helper = namespace["helper"]
    if kind == "cycle":
        helper.__defaults__ = (helper,)
    elif kind == "opaque":
        helper.__defaults__ = (object(),)
    elif kind == "nested_callable":
        helper.__defaults__ = ([lambda: None],)
    elif kind == "external_closure":
        namespace.update(
            _namespace("def make(value):\n    def helper(): return value\n    return helper\nhelper = make(1)\n")
        )
        helper = namespace["helper"]
        helper.__module__ = "unknown_plugin"
        namespace["risk"] = _namespace("def risk(value=None): return value\n")["risk"]
        namespace["risk"].__defaults__ = (helper,)
    else:
        # Each child is individually bounded; their combined state is not.
        first = _namespace("def first(value=None): return value\n")["first"]
        second = _namespace("def second(value=None): return value\n")["second"]
        first.__defaults__ = (list(range(2500)),)
        second.__defaults__ = (list(range(2500)),)
        helper.__defaults__ = (first, second)
    helpers = _capture(namespace)
    assert helpers.available is False
    assert helpers.refusal_reason == "unsupported_helper_dependency"

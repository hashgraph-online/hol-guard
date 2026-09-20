"""Bounded source-default helper bindings for one MCP risk-fact invocation.

This observes reviewed Python helper interfaces, not arbitrary interpreter state.
Unsupported dependency shapes disable sharing and preserve original derivation.
"""

from __future__ import annotations

import dataclasses
import dis
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from functools import lru_cache
from re import RegexFlag
from types import (
    BuiltinFunctionType,
    BuiltinMethodType,
    CodeType,
    FunctionType,
    GetSetDescriptorType,
    MappingProxyType,
    MemberDescriptorType,
    MethodDescriptorType,
    ModuleType,
    NotImplementedType,
    WrapperDescriptorType,
)
from typing import cast

from .mcp_authority_binding import UnsupportedAuthorityValueError, exact_authority_digest
from .mcp_risk_stdlib import is_re_zero_sentinel, stdlib_leaf_state

_CACHED_FUNCTION_TYPE = type(lru_cache()(lambda: None))
_MISSING = object()
_MAX_BINDINGS = 512
_MAX_STATE_ITEMS = 4096
_MAX_STATE_DEPTH = 24
_CAPTURE_ERRORS = (UnsupportedAuthorityValueError, AttributeError, KeyError, TypeError, ValueError, RuntimeError)
_REFLECTION_FIELDS = frozenset({"__annotations__", "__dataclass_fields__", "__dataclass_params__", "__doc__"})
_GENERATED_SERIALIZATION_HOOKS = {
    "__getstate__": dataclasses.__dict__.get("_dataclass_getstate"),
    "__setstate__": dataclasses.__dict__.get("_dataclass_setstate"),
    "__replace__": dataclasses.__dict__.get("_replace"),
}


def _plain_digest(value: object, budget: list[int] | None = None) -> bytes:
    """Bound mutable defaults/tables, including sets and nested containers."""
    if budget is None:
        budget = [_MAX_STATE_ITEMS]

    def visit(item: object, parents: frozenset[int]) -> object:
        budget[0] -= 1
        if budget[0] < 0 or len(parents) > _MAX_STATE_DEPTH:
            raise UnsupportedAuthorityValueError
        kind = type(item)
        if item is None or kind in (bool, str, int, float, bytes):
            return item
        if kind not in (dict, list, tuple, set, frozenset) or id(item) in parents:
            raise UnsupportedAuthorityValueError
        nested = parents | {id(item)}
        if kind is dict:
            mapping = cast(dict[object, object], item)
            if any(type(key) is not str for key in mapping):
                raise UnsupportedAuthorityValueError
            return ("dict", tuple((cast(str, key), visit(child, nested)) for key, child in mapping.items()))
        values = [visit(child, nested) for child in cast(list[object], item)]
        if kind is list:
            return ("list", tuple(values))
        if kind is tuple:
            return ("tuple", tuple(values))
        # Unordered containers bind exact elements without calling their equality.
        return ("set" if kind is set else "frozenset", tuple(sorted(exact_authority_digest(x) for x in values)))

    return exact_authority_digest(visit(value, frozenset()))


def _default_state(defaults: object, parents: frozenset[int], budget: list[int]) -> tuple[object, ...]:
    """Bind direct callable defaults without admitting arbitrary object graphs."""
    budget[0] -= 1
    if budget[0] < 0:
        raise UnsupportedAuthorityValueError
    if defaults is None:
        return ("none",)
    values: tuple[tuple[int | str, object], ...]
    if type(defaults) is tuple:
        if len(cast(tuple[object, ...], defaults)) > budget[0]:
            raise UnsupportedAuthorityValueError
        values = tuple(enumerate(cast(tuple[object, ...], defaults)))
        tag = "positional"
    elif type(defaults) is dict:
        mapping = cast(dict[str, object], defaults)
        if len(mapping) > budget[0]:
            raise UnsupportedAuthorityValueError
        if any(type(key) is not str for key in mapping):
            raise UnsupportedAuthorityValueError
        values = tuple(mapping.items())
        tag = "keyword"
    else:
        raise UnsupportedAuthorityValueError
    if len(values) > budget[0]:
        raise UnsupportedAuthorityValueError
    result = []
    for key, value in values:
        if type(value) is FunctionType:
            function = cast(FunctionType, value)
            if id(function) in parents or (
                function.__closure__ and not function.__module__.startswith("codex_plugin_scanner.")
            ):
                raise UnsupportedAuthorityValueError
            detail = ("callable", id(function), _state(function, parents, budget))
        elif is_re_zero_sentinel(value):
            detail = ("stdlib_sentinel", _state(value, parents, budget))
        else:
            # Containers may hold ordinary data, but nested callable/opaque
            # values still decline. This is the existing plain-data boundary.
            detail = ("data", _plain_digest(value, budget))
        result.append((key, detail))
    return (tag, tuple(result))


def _state(value: object, parents: frozenset[int] = frozenset(), budget: list[int] | None = None) -> tuple[object, ...]:
    """Inspect only exact known types; never invoke an injected descriptor."""
    if budget is None:
        budget = [_MAX_STATE_ITEMS]
    budget[0] -= 1
    if budget[0] < 0 or len(parents) > _MAX_STATE_DEPTH:
        raise UnsupportedAuthorityValueError
    if id(value) in parents:
        return ("reference", id(value))
    nested = parents | {id(value)}
    kind = type(value)
    leaf = stdlib_leaf_state(value, nested, budget, inspect_class=_state, plain_digest=_plain_digest)
    if leaf is not None:
        return leaf
    if kind is NotImplementedType:
        # Generated dataclass comparisons return this immutable singleton.
        # Bind identity; replacement of the executed builtin still invalidates.
        return ("not_implemented", id(value))
    if kind is RegexFlag:
        # re exposes immutable integer flag values through enum instances.
        # Bind the exact stored value without invoking user conversions.
        stored = object.__getattribute__(value, "_value_")
        if type(stored) is not int:
            raise UnsupportedAuthorityValueError
        return ("regex_flag", id(kind), int.__int__(cast(RegexFlag, value)), stored)
    if kind is FunctionType:
        function = cast(FunctionType, value)
        closure = function.__closure__ or ()
        cells = tuple((id(cell), _state(cell.cell_contents, nested, budget)) for cell in closure)
        return (
            "function",
            id(function.__code__),
            id(function.__defaults__),
            _default_state(function.__defaults__, nested, budget),
            _default_state(function.__kwdefaults__, nested, budget),
            cells,
        )
    if kind is _CACHED_FUNCTION_TYPE:
        wrapped = object.__getattribute__(value, "__wrapped__")
        if type(wrapped) is not FunctionType:
            raise UnsupportedAuthorityValueError
        return ("cached", id(wrapped), _state(wrapped, nested, budget))
    if kind is property:
        descriptor = cast(property, value)
        return (
            "property",
            tuple(
                (id(fn), _state(fn, nested, budget)) if fn is not None else None
                for fn in (descriptor.fget, descriptor.fset, descriptor.fdel)
            ),
        )
    if kind is staticmethod or kind is classmethod:
        function = object.__getattribute__(value, "__func__")
        return (kind.__name__, id(function), _state(function, nested, budget))
    if isinstance(value, type):
        # Class identity alone misses replacement/in-place edits to constructors
        # and properties on the already bound browser/literal pattern types.
        members = []
        for base in type.__getattribute__(value, "__mro__"):
            namespace = type.__getattribute__(base, "__dict__")
            budget[0] -= len(namespace)
            if budget[0] < 0:
                raise UnsupportedAuthorityValueError
            for name, child in namespace.items():
                detail = None
                if type(child) in (FunctionType, property, staticmethod, classmethod):
                    detail = _state(child, nested, budget)
                elif name not in _REFLECTION_FIELDS and type(child) in (dict, list, tuple, set, frozenset):
                    detail = ("value", _plain_digest(child, budget))
                elif (
                    type.__getattribute__(base, "__module__").startswith("codex_plugin_scanner.")
                    and name not in _REFLECTION_FIELDS
                    and child is not None
                    and type(child)
                    not in (
                        bool,
                        str,
                        int,
                        float,
                        bytes,
                        ModuleType,
                        BuiltinFunctionType,
                        BuiltinMethodType,
                        MethodDescriptorType,
                        WrapperDescriptorType,
                        GetSetDescriptorType,
                        MemberDescriptorType,
                    )
                ):
                    # An existing arbitrary descriptor may mutate in place.
                    # Its identity is not enough to admit a source-owned class.
                    raise UnsupportedAuthorityValueError
                members.append((id(base), name, id(child), detail))
        return ("class", tuple(members))
    if kind in (dict, list, tuple, set, frozenset) or value is None or kind in (bool, str, int, float, bytes):
        return ("value", _plain_digest(value, budget))
    # Modules and native descriptors/callables retain their object identity.
    # Executed module attributes are captured separately from bytecode below.
    if kind in (
        ModuleType,
        BuiltinFunctionType,
        BuiltinMethodType,
        MethodDescriptorType,
        WrapperDescriptorType,
        GetSetDescriptorType,
        MemberDescriptorType,
    ):
        return ("native", id(value))
    raise UnsupportedAuthorityValueError


@dataclass(frozen=True, slots=True, repr=False)
class _HelperBinding:
    namespace: Mapping[str, object]
    name: str
    value: object
    state: tuple[object, ...]

    @classmethod
    def capture(cls, namespace: Mapping[str, object], name: str) -> _HelperBinding:
        value = namespace.get(name, _MISSING)
        return cls(namespace, name, value, ("absent",) if value is _MISSING else _state(value))

    def unchanged(self) -> bool:
        value = self.namespace.get(self.name, _MISSING)
        if value is not self.value:
            return False
        return value is _MISSING or _state(value) == self.state


def _function(value: object) -> FunctionType | None:
    if type(value) is FunctionType:
        return cast(FunctionType, value)
    if type(value) is _CACHED_FUNCTION_TYPE:
        value = object.__getattribute__(value, "__wrapped__")
        return cast(FunctionType, value) if type(value) is FunctionType else None
    return None


def _codes(code: CodeType) -> tuple[CodeType, ...]:
    result = [code]
    for value in code.co_consts:
        if type(value) is CodeType:
            result.extend(_codes(cast(CodeType, value)))
    if len(result) > _MAX_BINDINGS:
        raise UnsupportedAuthorityValueError
    return tuple(result)


class ReviewedRiskHelpers:
    """Capture a finite reviewed graph; unsupported capture never breaks import."""

    def __init__(
        self,
        *,
        namespace: Mapping[str, object],
        pure_roots: tuple[str, ...],
        consumers: tuple[str, ...],
        policy_type: type,
        policy_methods: tuple[str, ...],
    ) -> None:
        self._bindings: tuple[_HelperBinding, ...] = ()
        self._original_consumers: dict[str, object] = {}
        self._policy_methods = policy_methods
        self._policy_type = policy_type
        self._policy_mro = type.__getattribute__(policy_type, "__mro__")
        self.available = False
        self.refusal_reason: str | None = None
        bindings: dict[tuple[int, str], _HelperBinding] = {}
        visited: set[int] = set()
        self._import_modules = sys.modules

        def capture_import(function: FunctionType, instructions: tuple[dis.Instruction, ...], index: int) -> None:
            # Only the cached absolute from-import form present in the reviewed
            # browser graph is admitted. Observation never executes an import.
            instruction = instructions[index]
            if index < 2 or type(instruction.argval) is not str:
                raise UnsupportedAuthorityValueError
            level, fromlist = instructions[index - 2 : index]
            if (
                level.opname not in ("LOAD_CONST", "LOAD_SMALL_INT")
                or type(level.argval) is not int
                or level.argval != 0
                or fromlist.opname != "LOAD_CONST"
                or type(fromlist.argval) is not tuple
                or not fromlist.argval
                or any(type(name) is not str or name == "*" for name in fromlist.argval)
            ):
                raise UnsupportedAuthorityValueError
            builtins = function.__builtins__
            if type(builtins) is not dict:
                raise UnsupportedAuthorityValueError
            capture(builtins, "__import__", recursive=False)
            module = capture(sys.modules, instruction.argval, recursive=False)
            if type(module) is not ModuleType:
                raise UnsupportedAuthorityValueError
            namespace = object.__getattribute__(module, "__dict__")
            for name in fromlist.argval:
                member = capture(namespace, name, recursive=True)
                if member is _MISSING:
                    raise UnsupportedAuthorityValueError

        def walk(value: object, *, closure: bool = False) -> None:
            function = _function(value)
            if closure and function is not None and not function.__module__.startswith("codex_plugin_scanner."):
                raise UnsupportedAuthorityValueError
            if id(value) in visited:
                return
            if len(visited) >= _MAX_BINDINGS:
                raise UnsupportedAuthorityValueError
            visited.add(id(value))
            function = _function(value)
            if function is not None:
                # A callable default may be invoked without a LOAD_GLOBAL.
                # Its exact state is bound above; walk source-owned globals
                # under the same finite rules as other reviewed helpers.
                defaults = function.__defaults__ or ()
                keyword_defaults = tuple((function.__kwdefaults__ or {}).values())
                for default in (*defaults, *keyword_defaults):
                    if type(default) is FunctionType:
                        walk(default)
                if not function.__module__.startswith("codex_plugin_scanner."):
                    if closure:
                        raise UnsupportedAuthorityValueError
                    return
                for cell in function.__closure__ or ():
                    walk(cell.cell_contents, closure=True)
                for code in _codes(function.__code__):
                    instructions = tuple(dis.get_instructions(code))
                    for index, instruction in enumerate(instructions):
                        if instruction.opname == "IMPORT_NAME":
                            capture_import(function, instructions, index)
                            continue
                        if instruction.opname not in ("LOAD_GLOBAL", "LOAD_NAME"):
                            continue
                        name = instruction.argval
                        if type(name) is not str:
                            raise UnsupportedAuthorityValueError
                        dependency = capture(function.__globals__, name, recursive=True)
                        if dependency is _MISSING:
                            builtins = function.__builtins__
                            if type(builtins) is not dict:
                                raise UnsupportedAuthorityValueError
                            dependency = capture(builtins, name, recursive=False)
                        position = index + 1
                        while position < len(instructions):
                            member = instructions[position]
                            if member.opname not in ("LOAD_ATTR", "LOAD_METHOD"):
                                break
                            if type(dependency) is not ModuleType or type(member.argval) is not str:
                                break
                            module_namespace = object.__getattribute__(dependency, "__dict__")
                            dependency = capture(module_namespace, member.argval, recursive=True)
                            position += 1
                return
            if type(value) in (staticmethod, classmethod):
                walk(object.__getattribute__(value, "__func__"), closure=closure)
            elif type(value) is property:
                for function in (value.fget, value.fset, value.fdel):
                    if function is not None:
                        walk(function, closure=closure)
            elif isinstance(value, type) and type.__getattribute__(value, "__module__").startswith(
                "codex_plugin_scanner."
            ):
                for base in type.__getattribute__(value, "__mro__"):
                    for name, member in type.__getattribute__(base, "__dict__").items():
                        # CPython injects these exact dataclasses functions for
                        # frozen slots classes, plus __replace__ on Python 3.13.
                        # Classification never copies or serializes
                        # its intent/pattern instances. Their code/default/state
                        # remains bound by _state; their serialization-only
                        # transitive globals do not enter this helper graph.
                        if member is _GENERATED_SERIALIZATION_HOOKS.get(name, _MISSING):
                            continue
                        if type(member) in (FunctionType, property, staticmethod, classmethod):
                            walk(member, closure=True)

        def capture(owner: Mapping[str, object], name: str, *, recursive: bool) -> object:
            if type(owner) not in (dict, MappingProxyType):
                raise UnsupportedAuthorityValueError
            key = (id(owner), name)
            if key in bindings:
                return bindings[key].value
            if len(bindings) >= _MAX_BINDINGS:
                raise UnsupportedAuthorityValueError
            binding = _HelperBinding.capture(owner, name)
            bindings[key] = binding
            if recursive:
                walk(binding.value)
            return binding.value

        try:
            for name in pure_roots:
                capture(namespace, name, recursive=True)
            for name in consumers:
                capture(namespace, name, recursive=False)
            for base in self._policy_mro:
                policy_namespace = type.__getattribute__(base, "__dict__")
                for name in (*policy_methods, "__getattribute__", "__getattr__", "__dict__"):
                    capture(policy_namespace, name, recursive=False)
            self._original_consumers = {
                name: namespace[name] for name in ("build_tool_call_hash", "evaluate_tool_call")
            }
            self._bindings = tuple(bindings.values())
            self.available = True
        except _CAPTURE_ERRORS:
            # Refusal changes only optimization admission. Do not replace or
            # invoke a helper, swallow a later evaluation error, or break import.
            self.refusal_reason = "unsupported_helper_dependency"
            self._bindings = ()

    def unchanged(self, config: object, aliases: Mapping[str, object]) -> bool:
        if not self.available or type(config) is not self._policy_type:
            return False
        try:
            if sys.modules is not self._import_modules:
                return False
            if type.__getattribute__(self._policy_type, "__mro__") != self._policy_mro:
                return False
            try:
                instance = object.__getattribute__(config, "__dict__")
            except AttributeError:
                instance = {}
            if any(name in instance for name in self._policy_methods):
                return False
            if any(aliases.get(name) is not expected for name, expected in self._original_consumers.items()):
                return False
            return all(binding.unchanged() for binding in self._bindings)
        except _CAPTURE_ERRORS:
            return False

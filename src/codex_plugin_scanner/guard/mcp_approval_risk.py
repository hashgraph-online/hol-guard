"""Private pure-risk projection for the current owned MCP approval diagnostic.

This is not execution or approval authority. New internal observations can only
permit pure fact reuse; refusal preserves the original public derivation.
"""

from __future__ import annotations

import dis
from collections.abc import Callable, Mapping
from dataclasses import Field, dataclass, field
from threading import get_ident
from types import FunctionType, MethodType
from typing import cast

from .mcp_authority_binding import AuthorityCheck
from .mcp_risk_dependencies import _CAPTURE_ERRORS, _codes, _HelperBinding
from .models import GuardArtifact

_ISSUER = object()


@dataclass(frozen=True, slots=True, repr=False)
class BoundApprovalRiskAnalysis:
    artifact: GuardArtifact | None
    arguments: object
    categories: tuple[str, ...]
    signals: tuple[str, ...]
    authority_check: AuthorityCheck | None
    supported: Callable[[], bool] | None
    owner_check: Callable[[], bool] | None
    _issuer: object | None = field(default=None, repr=False)
    _thread: int = 0
    _phase: str = "summary"

    def observe(self, artifact: GuardArtifact, arguments: object, *, consumer: str) -> bool:
        """Refuse new optional observation failures without changing old calls.

        Existing daemon/browser/queue/public derivation calls run outside this
        method. Their exceptions are never caught or converted by this probe.
        """
        if (
            self._issuer is not _ISSUER
            or consumer != self._phase
            or artifact is not self.artifact
            or arguments is not self.arguments
            or get_ident() != self._thread
        ):
            self.close()
            return False
        supported, owner_check, authority_check = self.supported, self.owner_check, self.authority_check
        if supported is None or owner_check is None or authority_check is None:
            self.close()
            return False
        try:
            if not supported() or not owner_check():
                self.close()
                return False
            authority_check()
            # The current authority observer checks the complete input/catalog/
            # config/effective workspace. Only source-default implementations
            # may reach that internal observation, and checks repeat afterward.
            if not owner_check() or not supported():
                self.close()
                return False
        except (TypeError, ValueError, RuntimeError, OSError):
            self.close()
            return False
        object.__setattr__(self, "_phase", "receipt" if consumer == "summary" else "consumed")
        return True

    def close(self) -> None:
        object.__setattr__(self, "_phase", "closed")
        object.__setattr__(self, "_issuer", None)
        object.__setattr__(self, "artifact", None)
        object.__setattr__(self, "arguments", None)
        object.__setattr__(self, "authority_check", None)
        object.__setattr__(self, "supported", None)
        object.__setattr__(self, "owner_check", None)


def issue_approval_risk_analysis(
    owner: object,
    *,
    supported: Callable[[], bool],
    owner_check: Callable[[], bool],
) -> BoundApprovalRiskAnalysis | None:
    # Import only at the explicit export boundary after both modules exist.
    # A caller-created object or inactive token cannot supply arbitrary facts.
    from .mcp_request_risk import _OWNER, InvocationRiskFacts

    if type(owner) is not InvocationRiskFacts or _OWNER.get() is not owner:
        return None
    if object.__getattribute__(owner, "_closed") or object.__getattribute__(owner, "_phase") != "consumed":
        return None
    if object.__getattribute__(owner, "_thread") != get_ident():
        return None
    artifact = object.__getattribute__(owner, "artifact")
    arguments = object.__getattribute__(owner, "arguments")
    categories = object.__getattribute__(owner, "_categories")
    signals = object.__getattribute__(owner, "_signals")
    authority_check = object.__getattribute__(owner, "authority_check")
    if (
        artifact is None
        or authority_check is None
        or type(categories) is not tuple
        or type(signals) is not tuple
        or any(type(value) is not str for value in (*categories, *signals))
    ):
        return None
    return BoundApprovalRiskAnalysis(
        artifact,
        arguments,
        categories,
        signals,
        authority_check,
        supported,
        owner_check,
        _issuer=_ISSUER,
        _thread=get_ident(),
    )


def function_namespace(value: object) -> Mapping[str, object] | None:
    # Python stores a source-defined __new__ as an exact staticmethod in the
    # class dictionary. Observe that wrapper without invoking a descriptor.
    if type(value) is staticmethod:
        value = object.__getattribute__(value, "__func__")
    if type(value) is FunctionType:
        return cast(FunctionType, value).__globals__
    return None


class ApprovalRiskSourceDefaults:
    """Bind exact default aliases/methods used by the two optional observations."""

    def __init__(
        self,
        *,
        aliases: tuple[tuple[Mapping[str, object] | None, str], ...],
        owner_type: type,
        methods: tuple[str, ...],
        identities: tuple[tuple[Mapping[str, object], str], ...] = (),
        type_collections: tuple[tuple[Mapping[str, object], str], ...] = (),
        record_types: tuple[type, ...] = (),
        authority_functions: tuple[FunctionType, ...] = (),
    ) -> None:
        self.available = False
        self._bindings: tuple[_HelperBinding, ...] = ()
        self._methods: dict[str, object] = {}
        self._owner_type = owner_type
        self._identities: tuple[tuple[Mapping[str, object], str, object], ...] = ()
        self._collections: tuple[tuple[Mapping[str, object], str, object, tuple[type, ...]], ...] = ()
        self._records: tuple[tuple[type, object], ...] = ()
        try:
            if any(namespace is None for namespace, _name in aliases):
                return
            bindings = [_HelperBinding.capture(namespace, name) for namespace, name in aliases if namespace is not None]
            self._identities = tuple((ns, name, ns.get(name)) for ns, name in identities)
            collections = []
            for ns, name in type_collections:
                value = ns.get(name)
                if type(value) is not tuple or any(type(item) is not type for item in value):
                    return
                collections.append((ns, name, value, tuple(value)))
            self._collections = tuple(collections)
            self._records = tuple((record, _record_state(record)) for record in record_types)
            # Bind actual global loads in the finite authority/request observer
            # roots and their nested code. This includes absent module shadows
            # and builtin interfaces; it does not execute or recursively expand
            # arbitrary callbacks or interpreter implementation internals.
            identities_list = list(self._identities)
            identity_keys = {(id(ns), name) for ns, name, _value in identities_list}
            collection_keys = {(id(ns), name) for ns, name, _value, _items in self._collections}
            seen = {(id(binding.namespace), binding.name) for binding in bindings}

            def capture_global(ns: Mapping[str, object], name: str) -> None:
                key = (id(ns), name)
                if key in seen or key in identity_keys or key in collection_keys:
                    return
                seen.add(key)
                value = ns.get(name)
                if any(value is record for record in record_types):
                    identities_list.append((ns, name, value))
                else:
                    bindings.append(_HelperBinding.capture(ns, name))

            for function in authority_functions:
                if type(function) is not FunctionType or type(function.__builtins__) is not dict:
                    return
                for code in _codes(function.__code__):
                    for instruction in dis.get_instructions(code):
                        if instruction.opname not in ("LOAD_GLOBAL", "LOAD_NAME"):
                            continue
                        name = instruction.argval
                        if type(name) is not str:
                            return
                        capture_global(function.__globals__, name)
                        if name not in function.__globals__:
                            capture_global(function.__builtins__, name)
            self._identities = tuple(identities_list)
            for record in record_types:
                names = tuple(type.__getattribute__(record, "__dict__")["__dataclass_fields__"])
                for base in type.__getattribute__(record, "__mro__"):
                    members = type.__getattribute__(base, "__dict__")
                    for name in (*names, "__getattribute__", "__getattr__"):
                        bindings.append(_HelperBinding.capture(members, name))
            for name in ("name", "_field_type", "__getattribute__", "__getattr__"):
                bindings.append(_HelperBinding.capture(Field.__dict__, name))
            namespace = type.__getattribute__(owner_type, "__dict__")
            for name in methods:
                binding = _HelperBinding.capture(namespace, name)
                bindings.append(binding)
                self._methods[name] = binding.value
            self._bindings = tuple(bindings)
            self.available = True
        except _CAPTURE_ERRORS:
            self._bindings = ()

    def unchanged(self) -> bool:
        if not self.available:
            return False
        try:
            if any(ns.get(name) is not value for ns, name, value in self._identities):
                return False
            for ns, name, value, items in self._collections:
                current = cast(tuple[type, ...], ns.get(name))
                if current is not value or len(current) != len(items):
                    return False
                if any(item is not expected for item, expected in zip(current, items, strict=True)):
                    return False
            if not all(binding.unchanged() for binding in self._bindings):
                return False
            return all(_record_state(record) == state for record, state in self._records)
        except _CAPTURE_ERRORS:
            return False

    def method_supported(self, owner: object, name: str, resolved: object) -> bool:
        """Only the exact resolved default receives a new private keyword."""
        if not self.method_owned(owner, name) or type(resolved) is not MethodType:
            return False
        method = cast(MethodType, resolved)
        return method.__self__ is owner and method.__func__ is self._methods.get(name)

    def method_owned(self, owner: object, name: str) -> bool:
        """Do not invoke custom descriptors just to decide optimization support."""
        if not self.unchanged():
            return False
        expected = self._methods.get(name)
        if expected is None:
            return False
        try:
            namespace = object.__getattribute__(owner, "__dict__")
            if type(namespace) is not dict or name in namespace:
                return False
            # A proxy subclass may inherit the supported implementation; a
            # custom attribute-dispatch implementation disables sharing.
            selected = None
            found = False
            for base in type.__getattribute__(type(owner), "__mro__"):
                members = type.__getattribute__(base, "__dict__")
                if "__getattr__" in members:
                    return False
                getter = members.get("__getattribute__")
                if getter is not None and getter is not object.__getattribute__:
                    return False
                if not found and name in members:
                    selected = members[name]
                    found = True
            return found and selected is expected
        except (AttributeError, TypeError):
            return False
        return False


def _record_state(record: type) -> object:
    """Bind fields consumed by the existing exact-authority record traversal."""
    if type(record) is not type:
        raise TypeError("unsupported authority record")
    namespace = type.__getattribute__(record, "__dict__")
    metadata = namespace.get("__dataclass_fields__")
    if type(metadata) is not dict:
        raise TypeError("unsupported authority record fields")
    fields = []
    for key, value in metadata.items():
        if type(key) is not str or type(value) is not Field:
            raise TypeError("unsupported authority record field")
        name = object.__getattribute__(value, "name")
        if type(name) is not str:
            raise TypeError("unsupported authority record name")
        fields.append((key, id(value), name, id(object.__getattribute__(value, "_field_type"))))
    return (
        tuple(id(base) for base in type.__getattribute__(record, "__mro__")),
        id(metadata),
        tuple(fields),
    )

"""Typed GuardPolicy v1alpha1 documents and canonical JSON hashing."""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields, is_dataclass
from types import UnionType
from typing import Any, Literal, TypeAlias, TypeVar, cast, get_args, get_origin, get_type_hints

from .native_policy_document import NativePolicyDocumentError, policy_query
from .runtime.command_expression import CommandCondition, CommandExpression

POLICY_API_VERSION = "guard.hashgraphonline.com/v1alpha1"
POLICY_KIND = "GuardPolicy"
NETWORK_POLICY_SPEC_FIELD = "networkPolicy"
POLICY_MATCH_FIELDS = (
    "operations",
    "actors",
    "agents",
    "artifacts",
    "commands",
    "devices",
    "domains",
    "ecosystems",
    "environments",
    "harnesses",
    "locations",
    "mcps",
    "packages",
    "paths",
    "publishers",
    "repositories",
    "secretTypes",
    "skills",
    "tools",
    "workspaces",
    "browserIntents",
    "browserOperations",
    "browserProfiles",
    "origins",
    "pathPrefixes",
    "sensitiveSurfaces",
)

JsonValue: TypeAlias = None | bool | int | float | str | list["JsonValue"] | dict[str, "JsonValue"]
EncodedExtensions: TypeAlias = tuple[tuple[str, str], ...]
_DTO = TypeVar("_DTO")


class _NativeDocumentDTO:
    __slots__ = ()

    @classmethod
    def from_mapping(cls: type[_DTO], value: dict[str, object]) -> _DTO:
        return _decode_dto(cls, policy_query("from_mapping_dto", {"class_name": cls.__name__, "value": value}))

    def to_mapping(self) -> dict[str, JsonValue]:
        result = _ordered_mapping(
            policy_query("to_mapping_ordered", {"class_name": type(self).__name__, "dto": asdict(cast(Any, self))})
        )
        if not isinstance(result, dict):
            raise NativePolicyDocumentError("native_policy_document_dto_invalid")
        return cast(dict[str, JsonValue], result)


def _ordered_mapping(value: Any) -> Any:
    if isinstance(value, dict) and set(value) == {"object"} and isinstance(value["object"], list):
        pairs = value["object"]
        if any(not isinstance(pair, list) or len(pair) != 2 or not isinstance(pair[0], str) for pair in pairs):
            raise NativePolicyDocumentError("native_policy_document_dto_invalid")
        result = {key: _ordered_mapping(item) for key, item in pairs}
        if len(result) == len(pairs):
            return result
    elif isinstance(value, dict) and set(value) == {"array"} and isinstance(value["array"], list):
        return [_ordered_mapping(item) for item in value["array"]]
    elif value is None or type(value) in (str, int, bool):
        return value
    raise NativePolicyDocumentError("native_policy_document_dto_invalid")


def _decode_dto(cls: type[_DTO], value: Any) -> _DTO:
    if not isinstance(value, dict) or set(value) != {field.name for field in fields(cast(Any, cls))}:
        raise NativePolicyDocumentError("native_policy_document_dto_invalid")
    annotations = get_type_hints(cls)
    values = value.copy()
    for key, item in values.items():
        annotation = annotations[key]
        nested = get_args(annotation)[0] if get_origin(annotation) is UnionType else annotation
        primitive = type(get_args(annotation)[0]) if get_origin(annotation) is Literal else annotation
        if isinstance(nested, type) and is_dataclass(nested) and item is not None:
            values[key] = _decode_dto(nested, item)
        elif key in {"rules", "conditions"}:
            if not isinstance(item, list):
                raise NativePolicyDocumentError("native_policy_document_dto_invalid")
            target = PolicyRule if key == "rules" else CommandCondition
            values[key] = tuple(_decode_dto(target, part) for part in item)
        elif key in {"extensions", "spec_extensions", "labels", "values", "fields"}:
            if not isinstance(item, list) or any(
                not isinstance(pair, list) or len(pair) != 2 or not isinstance(pair[0], str) for pair in item
            ):
                raise NativePolicyDocumentError("native_policy_document_dto_invalid")
            if key == "fields":
                if any(
                    not isinstance(pair[1], list) or not all(isinstance(part, str) for part in pair[1]) for pair in item
                ):
                    raise NativePolicyDocumentError("native_policy_document_dto_invalid")
                values[key] = tuple((pair[0], tuple(pair[1])) for pair in item)
            else:
                values[key] = tuple(tuple(pair) for pair in item)
        elif key == "receipt_ids":
            if not isinstance(item, list) or not all(isinstance(part, str) for part in item):
                raise NativePolicyDocumentError("native_policy_document_dto_invalid")
            values[key] = tuple(item)
        elif primitive in (str, int, bool) and type(item) is not primitive:
            raise NativePolicyDocumentError("native_policy_document_dto_invalid")
    # The native parser validated command DTOs; construction cannot rerun their
    # Python pattern normalization or evaluate a second command expression.
    result = object.__new__(cls)
    for key, item in values.items():
        object.__setattr__(result, key, item)
    return result


@dataclass(frozen=True, slots=True)
class PolicyMetadata(_NativeDocumentDTO):
    id: str
    name: str
    revision: int
    labels: tuple[tuple[str, str], ...] = ()
    extensions: EncodedExtensions = ()


@dataclass(frozen=True, slots=True)
class PolicyDefaults(_NativeDocumentDTO):
    mode: str
    values: tuple[tuple[str, JsonValue], ...] = ()
    extensions: EncodedExtensions = ()


@dataclass(frozen=True, slots=True)
class PolicyMatch(_NativeDocumentDTO):
    fields: tuple[tuple[str, tuple[str, ...]], ...] = ()
    command_expression: CommandExpression | None = None
    extensions: EncodedExtensions = ()


@dataclass(frozen=True, slots=True)
class PolicyLifetime(_NativeDocumentDTO):
    mode: str
    expires_at: str | None = None
    extensions: EncodedExtensions = ()


@dataclass(frozen=True, slots=True)
class PolicyProvenance(_NativeDocumentDTO):
    source: str
    created_at: str
    receipt_ids: tuple[str, ...] = ()
    suggestion_id: str | None = None
    created_by: str | None = None
    updated_at: str | None = None
    updated_by: str | None = None
    import_source_digest: str | None = None
    previous_rule_revision: int | None = None
    extensions: EncodedExtensions = ()


@dataclass(frozen=True, slots=True)
class PolicyRule(_NativeDocumentDTO):
    id: str
    enabled: bool
    effect: str
    match: PolicyMatch
    lifetime: PolicyLifetime
    provenance: PolicyProvenance
    description: str | None = None
    extensions: EncodedExtensions = ()


@dataclass(frozen=True, slots=True)
class GuardPolicyDocument(_NativeDocumentDTO):
    metadata: PolicyMetadata
    defaults: PolicyDefaults
    rules: tuple[PolicyRule, ...]
    rollout_state: str | None = None
    api_version: str = POLICY_API_VERSION
    kind: str = POLICY_KIND
    spec_extensions: EncodedExtensions = ()
    extensions: EncodedExtensions = ()


def canonical_json_bytes(value: JsonValue) -> bytes:
    """Return canonical JSON bytes for the contract's integer-only number subset."""

    result = policy_query("canonical", {"value": value})
    if not isinstance(result, str):
        raise NativePolicyDocumentError("native_policy_document_dto_invalid")
    return result.encode("utf-8")


def canonical_policy_document_bytes(document: GuardPolicyDocument) -> bytes:
    """Return RFC 8785-compatible JSON for the contract's integer-only number subset."""

    return canonical_json_bytes(document.to_mapping())


def policy_document_digest(document: GuardPolicyDocument) -> str:
    result = policy_query("digest", {"value": document.to_mapping()})
    if not isinstance(result, str) or len(result) != 64 or any(ch not in "0123456789abcdef" for ch in result):
        raise NativePolicyDocumentError("native_policy_document_dto_invalid")
    return result

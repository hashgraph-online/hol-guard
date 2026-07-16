"""Typed GuardPolicy v1alpha1 documents and canonical JSON hashing."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import TypeAlias, cast

POLICY_API_VERSION = "guard.hashgraphonline.com/v1alpha1"
POLICY_KIND = "GuardPolicy"
POLICY_RULE_EFFECTS = ("allow", "block", "review", "ignore")
POLICY_MODES = ("observe", "prompt", "enforce")
POLICY_LIFETIME_MODES = ("once", "session", "project", "machine", "workspace", "team", "permanent", "until")
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

def _mapping(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise TypeError("validated_policy_document_shape")
    return cast(dict[str, object], value)


def _sequence(value: object) -> list[object]:
    if not isinstance(value, list):
        raise TypeError("validated_policy_document_shape")
    return cast(list[object], value)


def _json_value(value: object) -> JsonValue:
    return cast(JsonValue, value)

def _canonical_json_text(value: JsonValue | object) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, list):
        return "[" + ",".join(_canonical_json_text(item) for item in value) + "]"
    if isinstance(value, dict):
        items = cast(dict[str, object], value).items()
        ordered = sorted(items, key=lambda item: item[0].encode("utf-16-be"))
        return (
            "{"
            + ",".join(
                f"{_canonical_json_text(key)}:{_canonical_json_text(item)}"
                for key, item in ordered
            )
            + "}"
        )
    raise TypeError("unsupported_canonical_json_value")


def _encode_extensions(value: dict[str, object], known_fields: frozenset[str]) -> EncodedExtensions:
    return tuple(
        (key, _canonical_json_text(item))
        for key, item in sorted(value.items())
        if key not in known_fields
    )


def _decode_extensions(value: EncodedExtensions) -> dict[str, JsonValue]:
    return {key: json.loads(encoded) for key, encoded in value}


def _with_extensions(core: dict[str, JsonValue], extensions: EncodedExtensions) -> dict[str, JsonValue]:
    core.update(_decode_extensions(extensions))
    return core


@dataclass(frozen=True, slots=True)
class PolicyMetadata:
    id: str
    name: str
    revision: int
    labels: tuple[tuple[str, str], ...] = ()
    extensions: EncodedExtensions = ()

    @classmethod
    def from_mapping(cls, value: dict[str, object]) -> PolicyMetadata:
        labels_value = value.get("labels")
        labels = _mapping(labels_value) if labels_value is not None else {}
        revision = value["revision"]
        if not isinstance(revision, int) or isinstance(revision, bool):
            raise TypeError("validated_policy_document_shape")
        return cls(
            id=str(value["id"]),
            name=str(value["name"]),
            revision=revision,
            labels=tuple(sorted((key, str(item)) for key, item in labels.items())),
            extensions=_encode_extensions(value, frozenset({"id", "name", "revision", "labels"})),
        )

    def to_mapping(self) -> dict[str, JsonValue]:
        result: dict[str, JsonValue] = {"id": self.id, "name": self.name, "revision": self.revision}
        if self.labels:
            result["labels"] = dict(self.labels)
        return _with_extensions(result, self.extensions)


@dataclass(frozen=True, slots=True)
class PolicyDefaults:
    mode: str
    values: tuple[tuple[str, JsonValue], ...] = ()
    extensions: EncodedExtensions = ()

    @classmethod
    def from_mapping(cls, value: dict[str, object]) -> PolicyDefaults:
        known = frozenset(
            {
                "mode",
                "defaultAction",
                "unknownPublisherAction",
                "changedHashAction",
                "newNetworkDomainAction",
                "subprocessAction",
                "telemetryEnabled",
                "syncEnabled",
            }
        )
        values = tuple(
            (key, _json_value(value[key]))
            for key in sorted(known - {"mode"})
            if key in value
        )
        return cls(mode=str(value["mode"]), values=values, extensions=_encode_extensions(value, known))

    def to_mapping(self) -> dict[str, JsonValue]:
        result: dict[str, JsonValue] = {"mode": self.mode}
        result.update(self.values)
        return _with_extensions(result, self.extensions)


@dataclass(frozen=True, slots=True)
class PolicyMatch:
    fields: tuple[tuple[str, tuple[str, ...]], ...] = ()
    extensions: EncodedExtensions = ()

    @classmethod
    def from_mapping(cls, value: dict[str, object]) -> PolicyMatch:
        fields = tuple(
            (key, tuple(str(item) for item in _sequence(value[key])))
            for key in POLICY_MATCH_FIELDS
            if isinstance(value.get(key), list)
        )
        return cls(fields=fields, extensions=_encode_extensions(value, frozenset(POLICY_MATCH_FIELDS)))

    def to_mapping(self) -> dict[str, JsonValue]:
        result: dict[str, JsonValue] = {key: list(values) for key, values in self.fields}
        return _with_extensions(result, self.extensions)


@dataclass(frozen=True, slots=True)
class PolicyLifetime:
    mode: str
    expires_at: str | None = None
    extensions: EncodedExtensions = ()

    @classmethod
    def from_mapping(cls, value: dict[str, object]) -> PolicyLifetime:
        expires_at = value.get("expiresAt")
        return cls(
            mode=str(value["mode"]),
            expires_at=expires_at if isinstance(expires_at, str) else None,
            extensions=_encode_extensions(value, frozenset({"mode", "expiresAt"})),
        )

    def to_mapping(self) -> dict[str, JsonValue]:
        result: dict[str, JsonValue] = {"mode": self.mode, "expiresAt": self.expires_at}
        return _with_extensions(result, self.extensions)


@dataclass(frozen=True, slots=True)
class PolicyProvenance:
    source: str
    created_at: str
    receipt_ids: tuple[str, ...] = ()
    suggestion_id: str | None = None
    created_by: str | None = None
    extensions: EncodedExtensions = ()

    @classmethod
    def from_mapping(cls, value: dict[str, object]) -> PolicyProvenance:
        receipt_ids = value.get("receiptIds")
        suggestion_id = value.get("suggestionId")
        created_by = value.get("createdBy")
        return cls(
            source=str(value["source"]),
            created_at=str(value["createdAt"]),
            receipt_ids=tuple(str(item) for item in _sequence(receipt_ids)) if isinstance(receipt_ids, list) else (),
            suggestion_id=suggestion_id if isinstance(suggestion_id, str) else None,
            created_by=created_by if isinstance(created_by, str) else None,
            extensions=_encode_extensions(
                value,
                frozenset({"source", "receiptIds", "suggestionId", "createdAt", "createdBy"}),
            ),
        )

    def to_mapping(self) -> dict[str, JsonValue]:
        result: dict[str, JsonValue] = {"source": self.source, "createdAt": self.created_at}
        if self.receipt_ids:
            result["receiptIds"] = list(self.receipt_ids)
        if self.suggestion_id is not None:
            result["suggestionId"] = self.suggestion_id
        if self.created_by is not None:
            result["createdBy"] = self.created_by
        return _with_extensions(result, self.extensions)


@dataclass(frozen=True, slots=True)
class PolicyRule:
    id: str
    enabled: bool
    effect: str
    match: PolicyMatch
    lifetime: PolicyLifetime
    provenance: PolicyProvenance
    description: str | None = None
    extensions: EncodedExtensions = ()

    @classmethod
    def from_mapping(cls, value: dict[str, object]) -> PolicyRule:
        description = value.get("description")
        return cls(
            id=str(value["id"]),
            description=description if isinstance(description, str) else None,
            enabled=bool(value["enabled"]),
            effect=str(value["effect"]),
            match=PolicyMatch.from_mapping(_mapping(value["match"])),
            lifetime=PolicyLifetime.from_mapping(_mapping(value["lifetime"])),
            provenance=PolicyProvenance.from_mapping(_mapping(value["provenance"])),
            extensions=_encode_extensions(
                value,
                frozenset({"id", "description", "enabled", "effect", "match", "lifetime", "provenance"}),
            ),
        )

    def to_mapping(self) -> dict[str, JsonValue]:
        result: dict[str, JsonValue] = {"id": self.id}
        if self.description is not None:
            result["description"] = self.description
        result.update(
            {
                "enabled": self.enabled,
                "effect": self.effect,
                "match": self.match.to_mapping(),
                "lifetime": self.lifetime.to_mapping(),
                "provenance": self.provenance.to_mapping(),
            }
        )
        return _with_extensions(result, self.extensions)


@dataclass(frozen=True, slots=True)
class GuardPolicyDocument:
    metadata: PolicyMetadata
    defaults: PolicyDefaults
    rules: tuple[PolicyRule, ...]
    rollout_state: str | None = None
    api_version: str = POLICY_API_VERSION
    kind: str = POLICY_KIND
    spec_extensions: EncodedExtensions = ()
    extensions: EncodedExtensions = ()

    @classmethod
    def from_mapping(cls, value: dict[str, object]) -> GuardPolicyDocument:
        metadata = _mapping(value["metadata"])
        spec = _mapping(value["spec"])
        defaults = _mapping(spec["defaults"])
        rules = _sequence(spec["rules"])
        rollout_state = spec.get("rolloutState")
        return cls(
            api_version=str(value["apiVersion"]),
            kind=str(value["kind"]),
            metadata=PolicyMetadata.from_mapping(metadata),
            defaults=PolicyDefaults.from_mapping(defaults),
            rules=tuple(PolicyRule.from_mapping(_mapping(rule)) for rule in rules),
            rollout_state=rollout_state if isinstance(rollout_state, str) else None,
            spec_extensions=_encode_extensions(spec, frozenset({"defaults", "rolloutState", "rules"})),
            extensions=_encode_extensions(value, frozenset({"apiVersion", "kind", "metadata", "spec"})),
        )

    def to_mapping(self) -> dict[str, JsonValue]:
        spec: dict[str, JsonValue] = {
            "defaults": self.defaults.to_mapping(),
            "rules": [rule.to_mapping() for rule in self.rules],
        }
        if self.rollout_state is not None:
            spec["rolloutState"] = self.rollout_state
        spec = _with_extensions(spec, self.spec_extensions)
        result: dict[str, JsonValue] = {
            "apiVersion": self.api_version,
            "kind": self.kind,
            "metadata": self.metadata.to_mapping(),
            "spec": spec,
        }
        return _with_extensions(result, self.extensions)


def canonical_policy_document_bytes(document: GuardPolicyDocument) -> bytes:
    """Return RFC 8785-compatible JSON for the contract's integer-only number subset."""

    return _canonical_json_text(document.to_mapping()).encode("utf-8")


def policy_document_digest(document: GuardPolicyDocument) -> str:
    return hashlib.sha256(canonical_policy_document_bytes(document)).hexdigest()


def validate_effective_rule_ids(documents: tuple[GuardPolicyDocument, ...]) -> None:
    """Reject duplicate rule IDs across an explicitly assembled effective set."""

    seen: set[str] = set()
    for document in documents:
        for rule in document.rules:
            if rule.id in seen:
                raise ValueError("duplicate_effective_rule_id")
            seen.add(rule.id)

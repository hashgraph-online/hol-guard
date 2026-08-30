"""Strict, package-safe contracts for fleet Extension configuration."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from copy import deepcopy
from importlib.resources import files as resource_files
from typing import Final, Literal, TypeAlias, cast

from jsonschema import FormatChecker, ValidationError
from jsonschema.validators import Draft202012Validator, extend

ContractKind: TypeAlias = Literal[
    "fleetExtensionConfiguration",
    "assignment",
    "customExtensionDefinition",
    "customExtensionConfiguration",
    "catalogSemantics",
]

CONTRACT_SCHEMAS: Final[dict[ContractKind, str]] = {
    "fleetExtensionConfiguration": "guard.fleet-extension-configuration.v1",
    "assignment": "guard.managed-control-assignment.v1",
    "customExtensionDefinition": "guard.custom-extension-definition.v2",
    "customExtensionConfiguration": "guard.custom-extension-configuration.v2",
    "catalogSemantics": "guard.catalog-semantic-fingerprint.v2",
}
CONTRACT_DOMAINS: Final[dict[ContractKind, bytes]] = {
    kind: f"hol.guard.{schema.removeprefix('guard.')}\0".encode() for kind, schema in CONTRACT_SCHEMAS.items()
}
REQUIRED_FLEET_CAPABILITIES: Final[frozenset[str]] = frozenset(
    {
        *CONTRACT_SCHEMAS.values(),
        "guard.managed-controls-composite-apply.v2",
        "guard.managed-controls-signed-delivery.v2",
    }
)
_SCHEMA_FILES: Final[dict[ContractKind, str]] = {
    "fleetExtensionConfiguration": "fleet-extension-configuration.schema.json",
    "assignment": "managed-control-assignment.schema.json",
    "customExtensionDefinition": "custom-extension-definition.schema.json",
    "customExtensionConfiguration": "custom-extension-configuration.schema.json",
    "catalogSemantics": "catalog-semantic-fingerprint.schema.json",
}
_CONTRACT_PACKAGE: Final = resource_files("codex_plugin_scanner.guard.managed_controls.contracts.v2")
_CAPABILITY = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
_MAX_PAYLOAD_BYTES = 524_288
_SELECTOR_FIELDS: Final[frozenset[str]] = frozenset(
    {"memberIds", "deviceIds", "agentIds", "directoryQueryId", "deviceTags"}
)
_TIMESTAMP_FIELDS: Final[frozenset[str]] = frozenset(
    {"createdAt", "effectiveFrom", "expiresAt", "retiredAt", "reviewedAt"}
)


class FleetContractError(ValueError):
    """Stable, bounded rejection that never contains private payload values."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message[:512])
        self.code = code


_MESSAGES: Final[dict[str, str]] = {
    "fec_invalid_json": "The fleet configuration payload is not valid JSON.",
    "fec_unknown_field": "The fleet configuration contains an unsupported field.",
    "fec_missing_field": "The fleet configuration is missing a required field.",
    "fec_limit_exceeded": "The fleet configuration exceeds a supported limit.",
    "fec_invalid_identifier": "A fleet configuration identifier is invalid.",
    "fec_invalid_timestamp": "A fleet configuration timestamp is not canonical UTC.",
    "fec_duplicate_entry": "The fleet configuration contains a duplicate logical entry.",
    "fec_conflicting_entry": "The fleet configuration contains conflicting authority.",
    "fec_managed_weaken_forbidden": "Managed restrictive authority cannot weaken protection.",
    "fec_unsupported_capability": "The device does not support required fleet configuration semantics.",
    "fec_catalog_mismatch": "The device catalog does not match the signed configuration projection.",
    "fec_semantic_mismatch": "The Extension meaning changed and requires a new simulation.",
    "fec_identity_unbound": "The portable Custom Extension is not bound to an approved local identity.",
    "fec_assignment_empty": "The managed assignment selector has no eligible targets.",
}


def _fail(code: str) -> None:
    raise FleetContractError(code, _MESSAGES.get(code, "The fleet configuration is invalid."))


def _read_resource_bytes(name: str) -> bytes:
    return _CONTRACT_PACKAGE.joinpath(name).read_bytes()


def _read_resource_json(name: str) -> object:
    try:
        return json.loads(_read_resource_bytes(name))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        _fail("fec_invalid_json")


def _load_schema(kind: ContractKind) -> dict[str, object]:
    value = _read_resource_json(_SCHEMA_FILES[kind])
    if not isinstance(value, dict):
        _fail("fec_invalid_json")
    return cast(dict[str, object], value)


def _validate_utf8_bytes(
    validator: object,
    maximum: object,
    instance: object,
    schema: object,
) -> Iterable[ValidationError]:
    del validator, schema
    if isinstance(instance, str) and isinstance(maximum, int) and len(instance.encode("utf-8")) > maximum:
        yield ValidationError("UTF-8 byte limit exceeded", validator="x-hol-maxUtf8Bytes")


FleetDraft202012Validator = extend(
    Draft202012Validator,
    {"x-hol-maxUtf8Bytes": _validate_utf8_bytes},
)


def _flatten_errors(error: ValidationError) -> tuple[ValidationError, ...]:
    flattened: list[ValidationError] = [error]
    for nested in error.context:
        flattened.extend(_flatten_errors(nested))
    return tuple(flattened)


def _path_key(error: ValidationError) -> object:
    path = list(error.absolute_path)
    return path[-1] if path else None


def _schema_error(errors: Sequence[ValidationError]) -> str:
    flattened = tuple(item for error in errors for item in _flatten_errors(error))
    if any(error.validator == "additionalProperties" for error in flattened):
        return "fec_unknown_field"
    if any(error.validator == "required" for error in flattened):
        return "fec_missing_field"
    if any(error.validator == "const" and list(error.absolute_path) == ["schemaVersion"] for error in flattened):
        return "fec_unsupported_capability"
    if any(
        error.validator == "const" and _path_key(error) in {"continuousEnrollment", "bindingMode", "fingerprintVersion"}
        for error in flattened
    ):
        return "fec_conflicting_entry"
    if any(
        error.validator in {"format", "pattern", "maxLength", "minLength", "x-hol-maxUtf8Bytes"}
        and _path_key(error) in _TIMESTAMP_FIELDS
        for error in flattened
    ):
        return "fec_invalid_timestamp"
    if any(
        error.validator
        in {
            "x-hol-maxUtf8Bytes",
            "maxItems",
            "minItems",
            "maxLength",
            "minLength",
            "maximum",
            "minimum",
        }
        for error in flattened
    ):
        return "fec_limit_exceeded"
    if any(error.validator in {"pattern", "format"} for error in flattened):
        return "fec_invalid_identifier"
    return "fec_invalid_json"


def _target_key(target: Mapping[str, object]) -> tuple[str, str, str]:
    return (
        cast(str, target["kind"]),
        cast(str, target.get("extensionId") or target.get("definitionId") or ""),
        cast(str, target.get("permissionId") or target.get("commandId") or ""),
    )


def _unique(values: Sequence[object]) -> None:
    encoded = [json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) for value in values]
    if len(encoded) != len(set(encoded)):
        _fail("fec_duplicate_entry")


def _preclassify(kind: ContractKind, value: object) -> None:
    if not isinstance(value, Mapping):
        return
    schema_version = value.get("schemaVersion")
    if schema_version is not None and schema_version != CONTRACT_SCHEMAS[kind]:
        _fail("fec_unsupported_capability")
    if kind == "fleetExtensionConfiguration":
        entries = value.get("entries")
        if isinstance(entries, Sequence) and not isinstance(entries, (str, bytes)):
            for raw_entry in entries:
                if not isinstance(raw_entry, Mapping):
                    continue
                if raw_entry.get("authorityMode") != "managed-restrictive":
                    continue
                target = raw_entry.get("target")
                target_kind = target.get("kind") if isinstance(target, Mapping) else None
                if (
                    target_kind not in {"extension", "permission"}
                    or raw_entry.get("availability") == "enabled"
                    or raw_entry.get("contextualOutcome") in {"permit", "review", "observe"}
                ):
                    _fail("fec_managed_weaken_forbidden")
    elif kind == "assignment":
        if value.get("continuousEnrollment") is False:
            _fail("fec_conflicting_entry")
        selector = value.get("selector")
        if isinstance(selector, Mapping):
            mode = selector.get("mode")
            expected_by_mode: dict[object, str | None] = {
                "all-active-devices": None,
                "selected-members": "memberIds",
                "selected-devices": "deviceIds",
                "supported-agents": "agentIds",
                "directory-query": "directoryQueryId",
                "device-tags": "deviceTags",
            }
            expected = expected_by_mode.get(mode)
            present = {key for key in selector if key in _SELECTOR_FIELDS}
            if expected is None:
                if mode == "all-active-devices" and present:
                    _fail("fec_conflicting_entry")
            elif present != {expected}:
                _fail("fec_conflicting_entry")
            elif selector.get(expected) in (None, "", []):
                _fail("fec_assignment_empty")
    elif kind == "customExtensionConfiguration":
        binding_mode = value.get("bindingMode")
        if binding_mode is not None and binding_mode != "exact-approved-variant":
            _fail("fec_conflicting_entry")


def _validate_fleet(value: dict[str, object]) -> None:
    entries = cast(list[dict[str, object]], value["entries"])
    _unique([entry["entryId"] for entry in entries])
    entries_by_target: dict[tuple[str, str, str], list[dict[str, object]]] = {}
    for entry in entries:
        target_key = _target_key(cast(dict[str, object], entry["target"]))
        entries_by_target.setdefault(target_key, []).append(entry)
    for grouped_entries in entries_by_target.values():
        if len(grouped_entries) < 2:
            continue
        authority_values = {
            (
                entry["authorityMode"],
                entry["availability"],
                entry["contextualOutcome"],
                entry["source"],
            )
            for entry in grouped_entries
        }
        if len(authority_values) == 1:
            _fail("fec_duplicate_entry")
        _fail("fec_conflicting_entry")
    for entry in entries:
        if entry["authorityMode"] != "managed-restrictive":
            continue
        target = cast(dict[str, object], entry["target"])
        if target.get("kind") not in {"extension", "permission"}:
            _fail("fec_managed_weaken_forbidden")
        if entry["availability"] == "enabled" or entry["contextualOutcome"] in {
            "permit",
            "review",
            "observe",
        }:
            _fail("fec_managed_weaken_forbidden")


def _validate_assignment(value: dict[str, object]) -> None:
    selector = cast(dict[str, object], value["selector"])
    expected_by_mode: dict[str, str | None] = {
        "all-active-devices": None,
        "selected-members": "memberIds",
        "selected-devices": "deviceIds",
        "supported-agents": "agentIds",
        "directory-query": "directoryQueryId",
        "device-tags": "deviceTags",
    }
    expected = expected_by_mode[cast(str, selector["mode"])]
    populated = [key for key in selector if key in _SELECTOR_FIELDS]
    if expected is None and populated:
        _fail("fec_conflicting_entry")
    if expected is not None and populated != [expected]:
        _fail("fec_conflicting_entry")
    if expected is not None:
        selected = selector[expected]
        if selected in (None, "", []):
            _fail("fec_assignment_empty")
        if isinstance(selected, list) and len(selected) != len(set(selected)):
            _fail("fec_duplicate_entry")
    if value["continuousEnrollment"] is not True:
        _fail("fec_conflicting_entry")
    exclusions = cast(list[dict[str, object]], value["exclusions"])
    _unique([(item["kind"], item["targetId"]) for item in exclusions])


def _validate_custom_definition(value: dict[str, object]) -> None:
    commands = cast(list[dict[str, object]], value["commands"])
    variants = cast(list[dict[str, object]], value["variants"])
    _unique([item["commandId"] for item in commands])
    _unique([item["variantId"] for item in variants])
    for item in variants:
        platforms = cast(list[str], item["platforms"])
        _unique(platforms)
        if item["reviewState"] == "trusted" and (not item.get("reviewedAt") or not item.get("reviewedBy")):
            _fail("fec_missing_field")


def _validate_custom_configuration(value: dict[str, object]) -> None:
    commands = cast(list[dict[str, object]], value["commands"])
    _unique([item["commandId"] for item in commands])
    _unique(cast(list[object], value["allowedVariantIds"]))


def validate_custom_extension_binding(
    definition_value: object,
    configuration_value: object,
) -> tuple[dict[str, object], dict[str, object]]:
    """Validate a configuration against the exact portable definition it binds."""

    definition = validate_fleet_contract("customExtensionDefinition", definition_value)
    configuration = validate_fleet_contract("customExtensionConfiguration", configuration_value)
    if (
        definition["workspaceId"] != configuration["workspaceId"]
        or definition["definitionId"] != configuration["definitionId"]
    ):
        _fail("fec_identity_unbound")
    trusted_variants = {
        variant["variantId"]
        for variant in cast(list[dict[str, object]], definition["variants"])
        if variant["reviewState"] == "trusted"
    }
    allowed_variants = set(cast(list[str], configuration["allowedVariantIds"]))
    definition_commands = {command["commandId"] for command in cast(list[dict[str, object]], definition["commands"])}
    configured_commands = {command["commandId"] for command in cast(list[dict[str, object]], configuration["commands"])}
    if not allowed_variants or not allowed_variants <= trusted_variants:
        _fail("fec_identity_unbound")
    if not configured_commands <= definition_commands:
        _fail("fec_identity_unbound")
    return definition, configuration


def validate_fleet_contract_collection(
    document: Mapping[str, object],
) -> dict[ContractKind, dict[str, object]]:
    """Validate every exact Fleet object embedded in a signed policy payload."""

    parsed: dict[ContractKind, dict[str, object]] = {}
    for kind in CONTRACT_SCHEMAS:
        if kind in document:
            parsed[kind] = validate_fleet_contract(kind, document[kind])
    definition = parsed.get("customExtensionDefinition")
    configuration = parsed.get("customExtensionConfiguration")
    if (definition is None) != (configuration is None):
        _fail("fec_identity_unbound")
    if definition is not None and configuration is not None:
        validated_definition, validated_configuration = validate_custom_extension_binding(definition, configuration)
        parsed["customExtensionDefinition"] = validated_definition
        parsed["customExtensionConfiguration"] = validated_configuration
    return parsed


def _validate_catalog(value: dict[str, object]) -> None:
    extensions = cast(list[dict[str, object]], value["extensions"])
    _unique([item["extensionId"] for item in extensions])
    _unique(cast(list[object], value["capabilities"]))
    for extension in extensions:
        permissions = cast(list[dict[str, object]], extension["permissions"])
        _unique([item["permissionId"] for item in permissions])


_SEMANTIC_VALIDATORS = {
    "fleetExtensionConfiguration": _validate_fleet,
    "assignment": _validate_assignment,
    "customExtensionDefinition": _validate_custom_definition,
    "customExtensionConfiguration": _validate_custom_configuration,
    "catalogSemantics": _validate_catalog,
}


def validate_fleet_contract(kind: ContractKind, value: object) -> dict[str, object]:
    """Validate and normalize one bounded shared contract."""

    _preclassify(kind, value)
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError):
        _fail("fec_invalid_json")
    if len(encoded) > _MAX_PAYLOAD_BYTES:
        _fail("fec_limit_exceeded")
    validator = FleetDraft202012Validator(
        _load_schema(kind),
        format_checker=FormatChecker(),
    )
    errors = tuple(validator.iter_errors(value))
    if errors:
        _fail(_schema_error(errors))
    normalized = deepcopy(cast(dict[str, object], value))
    if kind == "fleetExtensionConfiguration":
        for entry in cast(list[dict[str, object]], normalized["entries"]):
            entry.setdefault("source", "explicit")
        normalized.setdefault("previousVersionDigest", None)
    elif kind == "customExtensionConfiguration":
        normalized.setdefault("bindingMode", "exact-approved-variant")
    _SEMANTIC_VALIDATORS[kind](normalized)
    return normalized


def _sort_contract(kind: ContractKind, value: dict[str, object]) -> dict[str, object]:
    normalized = deepcopy(value)
    if kind == "fleetExtensionConfiguration":
        entries = cast(list[dict[str, object]], normalized["entries"])
        entries.sort(
            key=lambda item: (
                _target_key(cast(dict[str, object], item["target"])),
                cast(str, item["entryId"]),
            )
        )
    elif kind == "assignment":
        selector = cast(dict[str, object], normalized["selector"])
        for key in ("memberIds", "deviceIds", "agentIds", "deviceTags"):
            if isinstance(selector.get(key), list):
                selector[key] = sorted(cast(list[str], selector[key]))
        exclusions = cast(list[dict[str, object]], normalized["exclusions"])
        exclusions.sort(key=lambda item: (item["kind"], item["targetId"]))
    elif kind == "customExtensionDefinition":
        cast(list[dict[str, object]], normalized["commands"]).sort(key=lambda item: cast(str, item["commandId"]))
        variants = cast(list[dict[str, object]], normalized["variants"])
        for variant in variants:
            variant["platforms"] = sorted(cast(list[str], variant["platforms"]))
        variants.sort(key=lambda item: cast(str, item["variantId"]))
    elif kind == "customExtensionConfiguration":
        cast(list[dict[str, object]], normalized["commands"]).sort(key=lambda item: cast(str, item["commandId"]))
        normalized["allowedVariantIds"] = sorted(cast(list[str], normalized["allowedVariantIds"]))
    else:
        extensions = cast(list[dict[str, object]], normalized["extensions"])
        for extension in extensions:
            cast(list[dict[str, object]], extension["permissions"]).sort(
                key=lambda item: cast(str, item["permissionId"])
            )
        extensions.sort(key=lambda item: cast(str, item["extensionId"]))
        normalized["capabilities"] = sorted(cast(list[str], normalized["capabilities"]))
    return normalized


def canonical_fleet_contract_bytes(kind: ContractKind, value: object) -> bytes:
    """Return deterministic canonical bytes for signing and digesting."""

    normalized = _sort_contract(kind, validate_fleet_contract(kind, value))
    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def fleet_contract_digest(kind: ContractKind, value: object) -> str:
    digest = hashlib.sha256(CONTRACT_DOMAINS[kind] + canonical_fleet_contract_bytes(kind, value)).hexdigest()
    return f"sha256:{digest}"


def negotiate_fleet_capabilities(advertised: object) -> tuple[bool, tuple[str, ...]]:
    if isinstance(advertised, (str, bytes)) or not isinstance(advertised, Sequence):
        _fail("fec_invalid_identifier")
    values: set[str] = set()
    for candidate in advertised:
        if not isinstance(candidate, str) or _CAPABILITY.fullmatch(candidate) is None:
            _fail("fec_invalid_identifier")
        values.add(candidate)
    missing = tuple(sorted(REQUIRED_FLEET_CAPABILITIES - values))
    return not missing, missing


def load_shared_fleet_fixtures() -> dict[str, object]:
    value = _read_resource_json("fixtures.json")
    if not isinstance(value, dict):
        _fail("fec_invalid_json")
    return cast(dict[str, object], value)


def load_adversarial_fleet_fixtures() -> dict[str, object]:
    value = _read_resource_json("adversarial-fixtures.json")
    if not isinstance(value, dict):
        _fail("fec_invalid_json")
    return cast(dict[str, object], value)


def verify_packaged_contract_manifest() -> tuple[str, ...]:
    value = _read_resource_json("manifest.json")
    if not isinstance(value, Mapping) or not isinstance(value.get("files"), list):
        _fail("fec_invalid_json")
    verified: list[str] = []
    for raw in cast(list[object], value["files"]):
        if not isinstance(raw, Mapping):
            _fail("fec_invalid_json")
        path = raw.get("path")
        size = raw.get("bytes")
        digest = raw.get("sha256")
        if not isinstance(path, str) or not isinstance(size, int) or not isinstance(digest, str):
            _fail("fec_invalid_json")
        payload = _read_resource_bytes(path)
        if len(payload) != size or hashlib.sha256(payload).hexdigest() != digest:
            _fail("fec_semantic_mismatch")
        verified.append(path)
    if len(verified) != len(set(verified)):
        _fail("fec_duplicate_entry")
    return tuple(verified)


def _mutation_parent(value: object, path: Sequence[object]) -> tuple[object, object]:
    if not path:
        _fail("fec_invalid_json")
    current = value
    for segment in path[:-1]:
        if isinstance(segment, str) and isinstance(current, dict):  # noqa: SIM114
            current = current[segment]
        elif isinstance(segment, int) and isinstance(current, list):
            current = current[segment]
        else:
            _fail("fec_invalid_json")
    return current, path[-1]


def apply_adversarial_fixture(base: object, case: Mapping[str, object]) -> object:
    value = deepcopy(base)
    if not isinstance(value, dict):
        return value
    patch = case.get("patch")
    if isinstance(patch, Mapping):
        value.update(patch)
    replacement = case.get("replace")
    if isinstance(replacement, Mapping):
        value.update(replacement)
    remove_path = case.get("removePath")
    if isinstance(remove_path, Sequence) and not isinstance(remove_path, (str, bytes)):
        parent, key = _mutation_parent(value, remove_path)
        if isinstance(parent, dict) and isinstance(key, str):
            parent.pop(key, None)
        elif isinstance(parent, list) and isinstance(key, int):
            parent.pop(key)
        else:
            _fail("fec_invalid_json")
    mutation = case.get("mutation")
    if isinstance(mutation, Mapping):
        path = mutation.get("path")
        mutation_type = mutation.get("type")
        if not isinstance(path, Sequence) or isinstance(path, (str, bytes)):
            _fail("fec_invalid_json")
        parent, key = _mutation_parent(value, path)
        if mutation_type == "nested-add":
            if not isinstance(parent, dict) or not isinstance(key, str):
                _fail("fec_invalid_json")
            target = parent.get(key)
            nested_key = mutation.get("key")
            if not isinstance(target, dict) or not isinstance(nested_key, str):
                _fail("fec_invalid_json")
            target[nested_key] = deepcopy(mutation.get("value"))
        elif mutation_type == "nested-replace":
            if isinstance(parent, dict) and isinstance(key, str):  # noqa: SIM114
                parent[key] = deepcopy(mutation.get("value"))
            elif isinstance(parent, list) and isinstance(key, int):
                parent[key] = deepcopy(mutation.get("value"))
            else:
                _fail("fec_invalid_json")
        else:
            _fail("fec_invalid_json")
    duplicate_path = case.get("duplicatePath")
    if duplicate_path == "entries[0]":
        cast(list[object], value["entries"]).append(deepcopy(cast(list[object], value["entries"])[0]))
    elif duplicate_path == "extensions[0]":
        cast(list[object], value["extensions"]).append(deepcopy(cast(list[object], value["extensions"])[0]))
    return value

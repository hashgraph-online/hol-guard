"""Contract-only adapter for shared Guard Cloud Review artifacts."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Final, Protocol, cast
from urllib.parse import unquote_to_bytes

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

CONTRACT_VERSION: Final = "guard-cloud-review-v2"
_SOURCE_ROOT: Final = Path(__file__).resolve().parents[4]
_PACKAGE_DATA_ROOT: Final = Path(__file__).resolve().parent / "data" / "guard-cloud-review"
_SOURCE_ARTIFACTS: Final = {
    "v2/contract.json": _SOURCE_ROOT / "contracts" / "guard-cloud-review" / "v2" / "contract.json",
    "v2/fixtures.json": _SOURCE_ROOT / "contracts" / "guard-cloud-review" / "v2" / "fixtures.json",
    "guard-cloud-review.md": _SOURCE_ROOT / "docs" / "guard" / "contracts" / "guard-cloud-review.md",
}


def _artifact_path(name: str) -> Path:
    packaged = _PACKAGE_DATA_ROOT / name
    if packaged.is_file():
        return packaged
    source = _SOURCE_ARTIFACTS[name]
    if source.is_file():
        return source
    raise FileNotFoundError(f"Guard Cloud Review artifact is unavailable: {name}")


CONTRACT_PATH: Final = _artifact_path("v2/contract.json")
FIXTURES_PATH: Final = _artifact_path("v2/fixtures.json")
PUBLIC_DOCUMENTATION_PATH: Final = _artifact_path("guard-cloud-review.md")
_GENERATED_ARTIFACTS: Final = {
    "fixtures": (FIXTURES_PATH, "contracts/guard-cloud-review/v2/fixtures.json"),
    "publicDocumentation": (PUBLIC_DOCUMENTATION_PATH, "docs/guard/contracts/guard-cloud-review.md"),
}
_MISSING: Final = object()
_RFC3339_DATE_TIME: Final = re.compile(
    r"^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])T([01]\d|2[0-3]):[0-5]\d:[0-5]\d"
    + r"(?P<fraction>\.\d+)?(?:Z|[+-](?:0\d|1\d|2[0-3]):[0-5]\d)$"
)
_JSON_POINTER_ARRAY_INDEX: Final = re.compile(r"^(?:0|[1-9]\d*)$")
_INVALID_JSON_POINTER_PERCENT_ESCAPE: Final = re.compile(r"%(?![0-9A-Fa-f]{2})")


class _Validator(Protocol):
    def validate(self, instance: object) -> None: ...


class _UnresolvedJsonPointerError(ValueError):
    """A syntactically valid JSON pointer did not resolve in the document."""


def _read_mapping(path: Path) -> dict[str, object]:
    parsed = cast(object, json.loads(path.read_text(encoding="utf-8")))
    if not isinstance(parsed, dict):
        raise ValueError(f"{path.name} must contain a JSON object")
    raw_mapping = cast(dict[object, object], parsed)
    if any(not isinstance(key, str) for key in raw_mapping):
        raise ValueError(f"{path.name} must use string object keys")
    return cast(dict[str, object], raw_mapping)


def _string_keyed_mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} must be an object")
    raw_mapping = cast(Mapping[object, object], value)
    if any(not isinstance(key, str) for key in raw_mapping):
        raise ValueError(f"{label} must use string object keys")
    return cast(Mapping[str, object], raw_mapping)


def _mapping_field(mapping: Mapping[str, object], name: str) -> Mapping[str, object]:
    return _string_keyed_mapping(mapping.get(name), name)


def _string_array(value: object, label: str, *, require_items: bool = True) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ValueError(f"{label} must be a string array")
    raw_values = cast(list[object], value)
    if (require_items and not raw_values) or any(not isinstance(item, str) for item in raw_values):
        raise ValueError(f"{label} must be a string array")
    return tuple(cast(str, item) for item in raw_values)


def _schema_validator(schema: Mapping[str, object]) -> _Validator:
    return cast(_Validator, Draft202012Validator(schema))


def _contract_metadata(contract: Mapping[str, object]) -> Mapping[str, object]:
    return _mapping_field(contract, "x-hol-contract")


def load_contract() -> dict[str, object]:
    """Load and sanity-check the language-neutral Cloud Review contract source."""

    contract = _read_mapping(CONTRACT_PATH)
    metadata = _contract_metadata(contract)
    if metadata.get("contractVersion") != CONTRACT_VERSION:
        raise ValueError("unsupported Guard Cloud Review contract version")
    Draft202012Validator.check_schema(contract)
    return contract


def load_fixtures() -> dict[str, object]:
    """Load the fixtures intended for both Python and TypeScript consumers."""

    fixtures = _read_mapping(FIXTURES_PATH)
    if fixtures.get("contractVersion") != CONTRACT_VERSION:
        raise ValueError("fixtures use an unsupported Guard Cloud Review contract version")
    return fixtures


def status_values(name: str) -> tuple[str, ...]:
    """Return an enum owned by the contract schema, not a local duplicate."""

    contract = load_contract()
    paths = _mapping_field(_contract_metadata(contract), "vocabularyPaths")
    pointer = paths.get(name)
    if not isinstance(pointer, str) or not pointer.startswith("#"):
        raise ValueError(f"unknown Guard Cloud Review vocabulary: {name}")
    try:
        definition = _string_keyed_mapping(resolve_json_pointer(contract, pointer), "vocabulary definition")
    except ValueError as error:
        raise ValueError(f"invalid Guard Cloud Review vocabulary: {name}") from error
    try:
        values = _string_array(definition.get("enum"), f"invalid Guard Cloud Review vocabulary: {name}")
    except ValueError as error:
        raise ValueError(f"invalid Guard Cloud Review vocabulary: {name}") from error
    if len(values) != len(set(values)):
        raise ValueError(f"duplicate Guard Cloud Review vocabulary value: {name}")
    return values


def _validate_schema(result: Mapping[str, object]) -> None:
    schema = load_contract()
    try:
        _schema_validator(schema).validate(dict(result))
    except ValidationError as error:
        raise ValueError(error.message) from error


def result_validation_schema() -> dict[str, object]:
    """Return the standalone Draft 2020-12 schema for result consumers."""

    return load_contract()


def _decode_json_pointer_token(token: str) -> str:
    decoded: list[str] = []
    index = 0
    while index < len(token):
        character = token[index]
        if character != "~":
            decoded.append(character)
            index += 1
            continue
        if index + 1 >= len(token) or token[index + 1] not in {"0", "1"}:
            raise ValueError("JSON pointer contains an invalid escape")
        decoded.append("~" if token[index + 1] == "0" else "/")
        index += 2
    return "".join(decoded)


def _json_pointer_tokens(pointer: str) -> tuple[str, ...]:
    value = pointer
    if value.startswith("#"):
        fragment = value.removeprefix("#")
        if _INVALID_JSON_POINTER_PERCENT_ESCAPE.search(fragment) is not None:
            raise ValueError("JSON pointer fragment contains an invalid percent escape")
        try:
            value = unquote_to_bytes(fragment).decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError("JSON pointer fragment is not valid UTF-8") from error
    if value and not value.startswith("/"):
        raise ValueError("JSON pointer must be absolute or a fragment pointer")
    if not value:
        return ()
    return tuple(_decode_json_pointer_token(token) for token in value.removeprefix("/").split("/"))


def resolve_json_pointer(document: object, pointer: str) -> object:
    """Resolve an RFC6901 absolute or fragment JSON pointer through objects and arrays."""

    value = document
    for token in _json_pointer_tokens(pointer):
        if isinstance(value, Mapping):
            mapping = _string_keyed_mapping(cast(Mapping[object, object], value), "JSON pointer value")
            if token not in mapping:
                raise _UnresolvedJsonPointerError(f"JSON pointer token does not resolve: {token}")
            value = mapping[token]
            continue
        if not isinstance(value, list):
            raise _UnresolvedJsonPointerError("JSON pointer does not resolve through an object or array")
        if _JSON_POINTER_ARRAY_INDEX.fullmatch(token) is None:
            raise ValueError("JSON pointer contains an invalid array index")
        values = cast(list[object], value)
        index = int(token)
        if index >= len(values):
            raise _UnresolvedJsonPointerError(f"JSON pointer array index is out of range: {token}")
        value = values[index]
    return value


def _value_at_path(payload: Mapping[str, object], path: object) -> object:
    if not isinstance(path, str) or not path.startswith("/"):
        raise ValueError("semantic rule path must be an absolute JSON pointer")
    try:
        return resolve_json_pointer(payload, path)
    except _UnresolvedJsonPointerError as error:
        raise ValueError(f"semantic rule path is missing: {path}") from error
    except ValueError as error:
        raise ValueError(f"semantic rule path is invalid: {path}") from error


def _optional_value_at_path(payload: Mapping[str, object], path: object) -> object:
    if not isinstance(path, str) or not path.startswith("/"):
        raise ValueError("semantic rule path must be an absolute JSON pointer")
    try:
        return resolve_json_pointer(payload, path)
    except _UnresolvedJsonPointerError:
        return _MISSING
    except ValueError as error:
        raise ValueError(f"semantic rule path is invalid: {path}") from error


def _is_rfc3339_date_time(value: object) -> bool:
    if not isinstance(value, str):
        return False
    match = _RFC3339_DATE_TIME.fullmatch(value)
    if match is None:
        return False
    fraction = match.group("fraction")
    parse_value = value
    if fraction is not None:
        parse_value = value[: match.start("fraction")] + value[match.end("fraction") :]
    try:
        _ = datetime.fromisoformat(parse_value[:-1] + "+00:00" if parse_value.endswith("Z") else parse_value)
    except ValueError:
        return False
    return True


def _string_values(rule: Mapping[str, object], name: str) -> tuple[str, ...]:
    return _string_array(rule.get(name), f"semantic rule {name}")


def _rule_id(rule: Mapping[str, object]) -> str:
    value = rule.get("id")
    if not isinstance(value, str) or not value:
        raise ValueError("semantic rule id must be a non-empty string")
    return value


def _validate_semantic_rule(payload: Mapping[str, object], rule: Mapping[str, object]) -> None:
    rule_id = _rule_id(rule)
    operator = rule.get("operator")
    if operator == "rfc3339_date_time":
        for path in _string_values(rule, "requiredPaths"):
            if not _is_rfc3339_date_time(_value_at_path(payload, path)):
                raise ValueError(f"{rule_id}: value must be an RFC3339 date-time")
        for path in _string_values(rule, "optionalPaths"):
            value = _optional_value_at_path(payload, path)
            if value is not _MISSING and not _is_rfc3339_date_time(value):
                raise ValueError(f"{rule_id}: value must be an RFC3339 date-time")
        return
    if operator == "all_equal":
        values = [_value_at_path(payload, path) for path in _string_values(rule, "paths")]
        if len({json.dumps(value, sort_keys=True) for value in values}) != 1:
            raise ValueError(f"{rule_id}: values must match")
        return
    if operator == "equals":
        if _value_at_path(payload, rule.get("path")) != rule.get("value"):
            raise ValueError(f"{rule_id}: value must match")
        return
    if operator == "if_equals_then_equals":
        if _value_at_path(payload, rule.get("ifPath")) == rule.get("ifValue") and _value_at_path(
            payload, rule.get("thenPath")
        ) != rule.get("thenValue"):
            raise ValueError(f"{rule_id}: conditional value must match")
        return
    if operator == "if_equals_then_in":
        if _value_at_path(payload, rule.get("ifPath")) == rule.get("ifValue") and _value_at_path(
            payload, rule.get("thenPath")
        ) not in _string_values(rule, "thenValues"):
            raise ValueError(f"{rule_id}: conditional value is not allowed")
        return
    if operator == "if_in_then_equals":
        if _value_at_path(payload, rule.get("ifPath")) in _string_values(rule, "ifValues") and _value_at_path(
            payload, rule.get("thenPath")
        ) != rule.get("thenValue"):
            raise ValueError(f"{rule_id}: conditional value must match")
        return
    if operator == "if_all_equals_then_in":
        conditions = rule.get("conditions")
        if not isinstance(conditions, list) or not conditions:
            raise ValueError("semantic rule conditions must be a non-empty array")
        raw_conditions = cast(list[object], conditions)
        matches = True
        for condition_value in raw_conditions:
            condition = _string_keyed_mapping(condition_value, "semantic rule condition")
            if _value_at_path(payload, condition.get("path")) != condition.get("value"):
                matches = False
                break
        if matches and _value_at_path(payload, rule.get("thenPath")) not in _string_values(rule, "thenValues"):
            raise ValueError(f"{rule_id}: conditional value is not allowed")
        return
    raise ValueError(f"unsupported semantic rule operator: {operator}")


def validate_semantic_rules(result: Mapping[str, object]) -> None:
    """Apply the language-neutral semantic rules published beside the schema."""

    rules = _contract_metadata(load_contract()).get("semanticRules")
    if not isinstance(rules, list):
        raise ValueError("semanticRules must be an array")
    raw_rules = cast(list[object], rules)
    for rule_value in raw_rules:
        _validate_semantic_rule(result, _string_keyed_mapping(rule_value, "semantic rule"))


def validate_review_result(result: Mapping[str, object]) -> None:
    """Validate the versioned result without submitting, queueing, or applying a decision."""

    _validate_schema(result)
    validate_semantic_rules(result)


def expected_artifact_digests() -> dict[str, str]:
    """Return the checked-in, non-self-referential generated artifact digests."""

    generation = _mapping_field(_contract_metadata(load_contract()), "generation")
    if generation.get("algorithm") != "sha256":
        raise ValueError("unsupported contract generation algorithm")
    artifacts = _mapping_field(generation, "artifacts")
    expected: dict[str, str] = {}
    for name, (_, expected_path) in _GENERATED_ARTIFACTS.items():
        entry = _mapping_field(artifacts, name)
        digest = entry.get("sha256")
        if (
            entry.get("path") != expected_path
            or not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise ValueError(f"invalid generated artifact declaration: {name}")
        expected[name] = digest
    return expected


def validate_generated_artifacts() -> dict[str, str]:
    """Verify generated fixture and public-documentation bytes against the contract."""

    expected = expected_artifact_digests()
    observed = {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, (path, _) in _GENERATED_ARTIFACTS.items()}
    for name, digest in expected.items():
        if observed[name] != digest:
            raise ValueError(f"generated artifact digest mismatch: {name}")
    if PUBLIC_DOCUMENTATION_PATH.read_text(encoding="utf-8") != render_public_documentation():
        raise ValueError("generated public documentation does not match the contract")
    return observed


def validate_reviewability_case(case: Mapping[str, object]) -> None:
    """Verify the immutable-block boundary represented by shared fixtures."""

    request_kind = case.get("requestKind")
    accepted = case.get("remoteDecisionAccepted")
    if request_kind not in {"reviewable_pause", "immutable_policy_block"}:
        raise ValueError("unknown review request kind")
    if not isinstance(accepted, bool):
        raise ValueError("remoteDecisionAccepted must be a boolean")
    if accepted != (request_kind == "reviewable_pause"):
        raise ValueError("immutable policy blocks cannot be remotely approved")


def render_public_documentation() -> str:
    """Render the checked-in public documentation from the contract source."""

    contract = load_contract()
    metadata = _contract_metadata(contract)
    glossary = _mapping_field(metadata, "glossary")
    invariants = metadata.get("invariants")
    operations = _mapping_field(metadata, "operations")
    correlation = _mapping_field(metadata, "correlation")
    semantic_rules = metadata.get("semanticRules")
    if not isinstance(invariants, list) or not isinstance(semantic_rules, list):
        raise ValueError("invariants and semanticRules must be arrays")
    raw_invariants = cast(list[object], invariants)
    raw_semantic_rules = cast(list[object], semantic_rules)
    lines = [
        "# Guard Cloud Review Contract",
        "",
        "Generated from `contracts/guard-cloud-review/v2/contract.json`; do not edit this file by hand.",
        "",
        (
            "This contract freezes the protocol 2 review vocabulary. "
            "It does not change existing Local Guard runtime behavior."
        ),
        "",
        "## Glossary",
        "",
    ]
    for name, description in glossary.items():
        lines.append(f"- **{name}:** {description}")
    lines.extend(["", "## Invariants", ""])
    for item in raw_invariants:
        definition = _string_keyed_mapping(item, "invariant")
        invariant_id = definition.get("id")
        statement = definition.get("statement")
        if not isinstance(invariant_id, str) or not isinstance(statement, str):
            raise ValueError("invalid invariant")
        lines.append(f"- `{invariant_id}`: {statement}")
    lines.extend(["", "## Operations", ""])
    for name, item in operations.items():
        operation = _mapping_field({"operation": item}, "operation")
        try:
            outcomes = _string_array(operation.get("outcomes"), "invalid operation outcomes", require_items=False)
        except ValueError as error:
            raise ValueError("invalid operation outcomes") from error
        outcome_text = ", ".join(f"`{value}`" for value in outcomes) or "none"
        lines.append(f"- `{name}`: outcomes {outcome_text}.")
    lines.extend(["", "## Portable Semantic Rules", ""])
    for item in raw_semantic_rules:
        rule = _string_keyed_mapping(item, "semantic rule")
        lines.append(f"- `{_rule_id(rule)}`: `{rule.get('operator')}`.")
    pattern = correlation.get("pattern")
    must_appear_on = correlation.get("mustAppearOn")
    if not isinstance(pattern, str):
        raise ValueError("invalid correlation contract")
    correlation_stages = _string_array(must_appear_on, "invalid correlation contract")
    lines.extend(
        [
            "",
            "## Correlation",
            "",
            f"`correlationId` format: `{pattern}`.",
            "It must be attached to " + ", ".join(f"`{value}`" for value in correlation_stages) + ".",
            "",
            "## Canonical Status Values",
            "",
        ]
    )
    for name in (
        "requestStatus",
        "visibilityStatus",
        "decisionStatus",
        "deliveryStatus",
        "applicationStatus",
        "continuationStatus",
        "continuationCapability",
    ):
        values = ", ".join(f"`{value}`" for value in status_values(name))
        lines.extend([f"### {name}", "", values, ""])
    lines.extend(
        [
            "## Result Shape",
            "",
            "Every exact remote-review result includes `request`, `decision`, `delivery`, `application`, and "
            + "`continuation` records. A recorded decision is not local application, and applied locally is not "
            + "agent continuation.",
            "",
        ]
    )
    return "\n".join(lines)

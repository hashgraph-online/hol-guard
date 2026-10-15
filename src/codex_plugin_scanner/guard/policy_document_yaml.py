"""Strict YAML 1.2 parsing and deterministic formatting for GuardPolicy documents."""

from __future__ import annotations

import base64
import copy
import difflib
import json
import re
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from itertools import islice
from pathlib import Path
from typing import TypeAlias, cast

import yaml
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError
from yaml.nodes import MappingNode, Node, SequenceNode

from .native_policy_document import NativePolicyDocumentError, bounds_claim, policy_query
from .policy_document import GuardPolicyDocument
from .policy_document_business_bounds import oversized_business_selector_path
from .runtime.command_expression import (
    CommandExpressionError,
    command_expression_from_mapping,
    validate_command_expression,
)

MAX_POLICY_BYTES = 1_048_576
MAX_POLICY_DEPTH = 32
MAX_POLICY_RULES = 1_000
MAX_COLLECTION_ITEMS = 256
MAX_STRING_LENGTH = 4_096
MAX_DIAGNOSTICS = 20
MAX_POLICY_TOKENS = 200_000

JsonPath: TypeAlias = tuple[str | int, ...]
JsonSchemaValue: TypeAlias = str | int | float | bool | None | list["JsonSchemaValue"] | dict[str, "JsonSchemaValue"]

_JSON_BOOL = re.compile(r"^(?:true|false)$")
_JSON_NULL = re.compile(r"^null$")
_JSON_INT = re.compile(r"^-?(?:0|[1-9][0-9]*)$")
_JSON_FLOAT = re.compile(r"^-?(?:(?:0|[1-9][0-9]*)\.[0-9]+|(?:0|[1-9][0-9]*)(?:\.[0-9]+)?[eE][+-]?[0-9]+)$")
_AMBIGUOUS_STRING = re.compile(
    r"^(?:null|true|false|yes|no|on|off|~|[-+]?\.(?:inf|nan)|[-+]?0[0-9]+|[-+]?[0-9]+(?::[0-9]+)+)$",
    re.IGNORECASE,
)
_TIMESTAMP_LIKE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}(?:[Tt ]|$)")


@dataclass(frozen=True, slots=True)
class PolicyDiagnostic:
    code: str
    path: JsonPath = ()
    line: int | None = None
    column: int | None = None
    expected: object | None = None
    suggestion: str | None = None


class PolicyDocumentError(ValueError):
    """Bounded policy diagnostics that never include policy values."""

    diagnostics: tuple[PolicyDiagnostic, ...]

    def __init__(self, diagnostics: tuple[PolicyDiagnostic, ...], *, limit: int | None = MAX_DIAGNOSTICS):
        # The cap bounds the exception text. Callers that print structured JSON pass ``limit=None``.
        self.diagnostics = diagnostics if limit is None else diagnostics[:limit]
        summary = "; ".join(
            f"{item.code}@{_format_path(item.path)}:{item.line or 0}:{item.column or 0}"
            for item in self.diagnostics[:MAX_DIAGNOSTICS]
        )
        super().__init__((summary or "invalid_policy_document")[:4_096])


def _format_path(path: JsonPath) -> str:
    if not path:
        return "$"
    return "$" + "".join(
        f"[{item}]" if isinstance(item, int) else f"[{json.dumps(item[:80], ensure_ascii=True)}]" for item in path
    )


class _PolicyLoader(yaml.SafeLoader):
    pass


_PolicyLoader.yaml_implicit_resolvers = copy.deepcopy(yaml.SafeLoader.yaml_implicit_resolvers)
for first_character, resolvers in tuple(_PolicyLoader.yaml_implicit_resolvers.items()):
    _PolicyLoader.yaml_implicit_resolvers[first_character] = [
        (tag, expression)
        for tag, expression in resolvers
        if tag
        not in {
            "tag:yaml.org,2002:bool",
            "tag:yaml.org,2002:float",
            "tag:yaml.org,2002:int",
            "tag:yaml.org,2002:merge",
            "tag:yaml.org,2002:null",
            "tag:yaml.org,2002:timestamp",
        }
    ]

_PolicyLoader.add_implicit_resolver("tag:yaml.org,2002:bool", _JSON_BOOL, list("tf"))
_PolicyLoader.add_implicit_resolver("tag:yaml.org,2002:null", _JSON_NULL, ["n"])
_PolicyLoader.add_implicit_resolver("tag:yaml.org,2002:int", _JSON_INT, list("-0123456789"))
_PolicyLoader.add_implicit_resolver("tag:yaml.org,2002:float", _JSON_FLOAT, list("-0123456789"))


def _construct_unique_mapping(loader: _PolicyLoader, node: MappingNode, deep: bool = False) -> dict[object, object]:
    result: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key == "<<":
            raise PolicyDocumentError(
                (
                    PolicyDiagnostic(
                        "yaml_merge_key",
                        line=key_node.start_mark.line + 1,
                        column=key_node.start_mark.column + 1,
                    ),
                )
            )
        try:
            duplicate = key in result
        except TypeError as error:
            raise PolicyDocumentError(
                (
                    PolicyDiagnostic(
                        "yaml_unhashable_key",
                        line=key_node.start_mark.line + 1,
                        column=key_node.start_mark.column + 1,
                    ),
                )
            ) from error
        if duplicate:
            raise PolicyDocumentError(
                (
                    PolicyDiagnostic(
                        "yaml_duplicate_key",
                        line=key_node.start_mark.line + 1,
                        column=key_node.start_mark.column + 1,
                    ),
                )
            )
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_PolicyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping)


class _PolicyDumper(yaml.SafeDumper):
    pass


def _represent_policy_string(dumper: _PolicyDumper, value: str) -> yaml.ScalarNode:
    style = None
    if (
        not value
        or value != value.strip()
        or _AMBIGUOUS_STRING.fullmatch(value)
        or _TIMESTAMP_LIKE.match(value)
        or "\n" in value
    ):
        style = "'"
    return dumper.represent_scalar("tag:yaml.org,2002:str", value, style=style)


_PolicyDumper.add_representer(str, _represent_policy_string)


@lru_cache(maxsize=1)
def _load_policy_document_schema() -> dict[str, object]:
    schema_path = (
        resources.files("codex_plugin_scanner.guard").joinpath("schemas").joinpath("guard-policy-v1alpha1.schema.json")
    )
    value = json.loads(schema_path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError("invalid_packaged_policy_schema")
    Draft202012Validator.check_schema(value)
    return value


def policy_document_schema() -> dict[str, object]:
    return copy.deepcopy(_load_policy_document_schema())


@lru_cache(maxsize=1)
def _policy_document_validator() -> Draft202012Validator:
    return Draft202012Validator(_load_policy_document_schema())


def _scan_restricted_tokens(text: str) -> None:
    tokens: list[list[object]] = []
    try:
        for token in islice(yaml.scan(text, Loader=_PolicyLoader), MAX_POLICY_TOKENS + 1):
            value = getattr(token, "value", None)
            tokens.append(
                [
                    type(token).__name__,
                    token.start_mark.line + 1,
                    token.start_mark.column + 1,
                    bounds_claim(value) if isinstance(value, str) else None,
                    getattr(token, "style", None),
                ]
            )
    except (RecursionError, ValueError):
        tokens.append(["scanner_resource", None, None, None, None])
    except yaml.YAMLError as error:
        mark = getattr(error, "problem_mark", None)
        tokens.append(
            [
                "scanner_syntax",
                mark.line + 1 if mark is not None else None,
                mark.column + 1 if mark is not None else None,
                None,
                None,
            ]
        )
    result = policy_query("validate_yaml_tokens", {"tokens": tokens})
    if result is not None:
        if (
            not isinstance(result, dict)
            or set(result) != {"code", "line", "column"}
            or result["code"]
            not in (
                "limit_tokens",
                "limit_depth",
                "limit_string",
                "limit_integer",
                "yaml_alias",
                "yaml_anchor",
                "yaml_tag",
                "yaml_syntax",
                "yaml_resource_limit",
            )
            or any(
                value is not None and (type(value) is not int or value < 1)
                for value in (result["line"], result["column"])
            )
        ):
            raise NativePolicyDocumentError("native_policy_document_tokens_malformed")
        raise PolicyDocumentError((PolicyDiagnostic(result["code"], line=result["line"], column=result["column"]),))


def _load_yaml(text: str) -> object:
    _scan_restricted_tokens(text)
    try:
        documents = list(yaml.load_all(text, Loader=_PolicyLoader))
    except PolicyDocumentError:
        raise
    except (RecursionError, ValueError) as error:
        raise PolicyDocumentError((PolicyDiagnostic("yaml_resource_limit"),)) from error
    except yaml.YAMLError as error:
        mark = getattr(error, "problem_mark", None)
        raise PolicyDocumentError(
            (
                PolicyDiagnostic(
                    "yaml_syntax",
                    line=mark.line + 1 if mark is not None else None,
                    column=mark.column + 1 if mark is not None else None,
                ),
            )
        ) from error
    if len(documents) != 1:
        raise PolicyDocumentError((PolicyDiagnostic("yaml_document_count"),))
    return documents[0]


def _validate_bounds(value: object) -> None:
    _validate_native_metadata(value, "validate_bounds")


def _node_for_path(node: Node | None, path: JsonPath) -> Node | None:
    current = node
    for part in path:
        if isinstance(part, int):
            if not isinstance(current, SequenceNode) or part >= len(current.value):
                return current
            current = current.value[part]
            continue
        if not isinstance(current, MappingNode):
            return current
        selected: Node | None = None
        for key_node, value_node in current.value:
            if key_node.value == part:
                selected = value_node
                break
        if selected is None:
            return current
        current = selected
    return current


def _schema_expectation(error: ValidationError) -> tuple[object | None, str | None]:
    """Describe what the schema wanted, using only schema-sourced values and key names."""

    validator = error.validator
    instance = error.instance
    schema = error.schema if isinstance(error.schema, dict) else {}
    if validator == "additionalProperties" and isinstance(instance, dict):
        allowed = sorted(schema.get("properties", {})) if isinstance(schema.get("properties"), dict) else []
        patterns = schema.get("patternProperties")
        extension_patterns = [str(pattern) for pattern in patterns] if isinstance(patterns, dict) else []
        unknown = sorted(
            str(key)
            for key in instance
            if key not in allowed and not any(re.search(pattern, str(key)) for pattern in extension_patterns)
        )
        hints = []
        for key in unknown[:3]:
            close = difflib.get_close_matches(key, allowed, n=1)
            hints.append(f'Rename "{key}" to "{close[0]}".' if close else f'Remove "{key}", or prefix it with "x-".')
        return allowed or None, " ".join(hints) or None
    if validator == "required" and isinstance(instance, dict) and isinstance(error.validator_value, list):
        missing = [name for name in error.validator_value if name not in instance]
        return missing or None, (f"Add the required field(s): {', '.join(missing)}." if missing else None)
    if validator == "enum" and isinstance(error.validator_value, list):
        return list(error.validator_value), None
    if validator in {
        "type",
        "const",
        "pattern",
        "minItems",
        "maxItems",
        "minLength",
        "maxLength",
        "minimum",
        "maximum",
    }:
        return error.validator_value, None
    return None, None


def _schema_diagnostics(text: str, value: object, limit: int | None = MAX_DIAGNOSTICS) -> tuple[PolicyDiagnostic, ...]:
    try:
        source_node = yaml.compose(text, Loader=_PolicyLoader)
    except yaml.YAMLError:
        source_node = None
    diagnostics: list[PolicyDiagnostic] = []
    errors = sorted(
        _policy_document_validator().iter_errors(cast(JsonSchemaValue, value)),
        key=lambda item: tuple(str(part) for part in item.path),
    )
    for error in errors if limit is None else errors[:limit]:
        path: JsonPath = tuple(error.absolute_path)
        node = _node_for_path(source_node, path)
        expected, suggestion = _schema_expectation(error)
        diagnostics.append(
            PolicyDiagnostic(
                f"schema_{error.validator}",
                path,
                line=node.start_mark.line + 1 if node is not None else None,
                column=node.start_mark.column + 1 if node is not None else None,
                expected=expected,
                suggestion=suggestion,
            )
        )
    return tuple(diagnostics)


def _validate_native_metadata(value: object, query: str) -> None:
    result = policy_query(query, {"claim": bounds_claim(value)} if query == "validate_bounds" else {"value": value})
    if query == "validate_bounds" and isinstance(result, dict):
        try:
            result = {
                "code": result["code"],
                "path": [
                    base64.b64decode(part[1], validate=True).decode("utf-32-le", "surrogatepass")
                    if isinstance(part, list) and len(part) == 2 and part[0] == "text"
                    else part
                    for part in result["path_claims"]
                ],
            }
        except (KeyError, TypeError, ValueError) as exc:
            raise NativePolicyDocumentError("native_policy_document_metadata_malformed") from exc
    if result is not None:
        if (
            not isinstance(result, dict)
            or set(result) != {"code", "path"}
            or result["code"]
            not in (
                "duplicate_rule_id",
                "invalid_timestamp",
                "limit_depth",
                "invalid_unicode",
                "limit_string",
                "non_finite_number",
                "unsupported_float",
                "limit_collection",
                "mapping_key_type",
                "limit_key",
                "forbidden_sensitive_field",
            )
            or not isinstance(result["path"], list)
            or not all(type(part) in (str, int) for part in result["path"])
        ):
            raise NativePolicyDocumentError("native_policy_document_metadata_malformed")
        raise PolicyDocumentError((PolicyDiagnostic(result["code"], cast(JsonPath, tuple(result["path"]))),))


def _validate_command_expressions(value: dict[str, object]) -> None:
    spec = value.get("spec")
    if not isinstance(spec, dict):
        return
    rules = spec.get("rules")
    if not isinstance(rules, list):
        return
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue
        match = rule.get("match")
        if not isinstance(match, dict) or not isinstance(match.get("commands"), dict):
            continue
        path: JsonPath = ("spec", "rules", index, "match", "commands")
        try:
            expression = command_expression_from_mapping(match["commands"])
            validate_command_expression(expression)
        except CommandExpressionError as error:
            raise PolicyDocumentError((PolicyDiagnostic(str(error), path),)) from error


def parse_policy_document_yaml(
    source: str | bytes,
    *,
    diagnostic_limit: int | None = MAX_DIAGNOSTICS,
) -> GuardPolicyDocument:
    """Parse and validate one strict GuardPolicy YAML document.

    ``diagnostic_limit`` caps schema diagnostics; ``None`` reports every one (structured JSON output).
    """

    try:
        encoded = source.encode("utf-8") if isinstance(source, str) else source
    except UnicodeEncodeError as error:
        raise PolicyDocumentError((PolicyDiagnostic("invalid_utf8"),)) from error
    if len(encoded) > MAX_POLICY_BYTES:
        raise PolicyDocumentError((PolicyDiagnostic("limit_bytes"),))
    try:
        text = encoded.decode("utf-8")
    except UnicodeDecodeError as error:
        raise PolicyDocumentError((PolicyDiagnostic("invalid_utf8"),)) from error
    value = _load_yaml(text)
    _validate_bounds(value)
    diagnostics = _schema_diagnostics(text, value, diagnostic_limit)
    if diagnostics:
        raise PolicyDocumentError(diagnostics, limit=diagnostic_limit)
    if not isinstance(value, dict):
        raise PolicyDocumentError((PolicyDiagnostic("schema_type"),))
    if path := oversized_business_selector_path(value):
        raise PolicyDocumentError((PolicyDiagnostic("business_selector_limit_bytes", path),))
    _validate_native_metadata(value, "validate_ids")
    _validate_native_metadata(value, "validate_timestamps")
    _validate_command_expressions(value)
    return GuardPolicyDocument.from_mapping(value)


def load_policy_document(path: Path) -> GuardPolicyDocument:
    return parse_policy_document_yaml(path.read_bytes())


def format_policy_document_yaml(document: GuardPolicyDocument) -> str:
    """Render stable, human-readable YAML that round-trips through the strict parser."""

    return yaml.dump(
        document.to_mapping(),
        Dumper=_PolicyDumper,
        allow_unicode=True,
        default_flow_style=False,
        explicit_end=False,
        explicit_start=False,
        sort_keys=False,
        width=100,
    )

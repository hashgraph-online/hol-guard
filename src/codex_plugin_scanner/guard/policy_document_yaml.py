"""Strict YAML 1.2 parsing and deterministic formatting for GuardPolicy documents."""

from __future__ import annotations

import copy
import json
import math
import re
from dataclasses import dataclass
from datetime import datetime
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import TypeAlias, cast

import yaml
from jsonschema import Draft202012Validator
from yaml.nodes import MappingNode, Node, SequenceNode
from yaml.tokens import (
    AliasToken,
    AnchorToken,
    BlockEndToken,
    BlockMappingStartToken,
    BlockSequenceStartToken,
    FlowMappingEndToken,
    FlowMappingStartToken,
    FlowSequenceEndToken,
    FlowSequenceStartToken,
    ScalarToken,
    TagToken,
)

from .policy_document import GuardPolicyDocument

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
_SENSITIVE_KEY_NAMES = frozenset(
    {
        "apikey",
        "authorization",
        "authheader",
        "credential",
        "credentials",
        "password",
        "privatekey",
        "rawcredential",
        "secretvalue",
        "token",
        "accesstoken",
        "refreshtoken",
    }
)


@dataclass(frozen=True, slots=True)
class PolicyDiagnostic:
    code: str
    path: JsonPath = ()
    line: int | None = None
    column: int | None = None


class PolicyDocumentError(ValueError):
    """Bounded policy diagnostics that never include policy values."""

    diagnostics: tuple[PolicyDiagnostic, ...]

    def __init__(self, diagnostics: tuple[PolicyDiagnostic, ...]):
        self.diagnostics = diagnostics[:MAX_DIAGNOSTICS]
        summary = "; ".join(
            f"{item.code}@{_format_path(item.path)}:{item.line or 0}:{item.column or 0}" for item in self.diagnostics
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
    depth = 0
    token_count = 0
    collection_starts = (
        BlockMappingStartToken,
        BlockSequenceStartToken,
        FlowMappingStartToken,
        FlowSequenceStartToken,
    )
    collection_ends = (BlockEndToken, FlowMappingEndToken, FlowSequenceEndToken)
    try:
        for token in yaml.scan(text, Loader=_PolicyLoader):
            token_count += 1
            if token_count > MAX_POLICY_TOKENS:
                raise PolicyDocumentError(
                    (
                        PolicyDiagnostic(
                            "limit_tokens",
                            line=token.start_mark.line + 1,
                            column=token.start_mark.column + 1,
                        ),
                    )
                )
            if isinstance(token, collection_starts):
                depth += 1
                if depth > MAX_POLICY_DEPTH + 1:
                    raise PolicyDocumentError(
                        (
                            PolicyDiagnostic(
                                "limit_depth",
                                line=token.start_mark.line + 1,
                                column=token.start_mark.column + 1,
                            ),
                        )
                    )
            elif isinstance(token, collection_ends):
                depth = max(0, depth - 1)
            elif isinstance(token, ScalarToken):
                if len(token.value) > MAX_STRING_LENGTH:
                    raise PolicyDocumentError(
                        (
                            PolicyDiagnostic(
                                "limit_string",
                                line=token.start_mark.line + 1,
                                column=token.start_mark.column + 1,
                            ),
                        )
                    )
                if token.style is None and _JSON_INT.fullmatch(token.value) and len(token.value.removeprefix("-")) > 16:
                    raise PolicyDocumentError(
                        (
                            PolicyDiagnostic(
                                "limit_integer",
                                line=token.start_mark.line + 1,
                                column=token.start_mark.column + 1,
                            ),
                        )
                    )
            if isinstance(token, AliasToken):
                code = "yaml_alias"
            elif isinstance(token, AnchorToken):
                code = "yaml_anchor"
            elif isinstance(token, TagToken):
                code = "yaml_tag"
            else:
                continue
            raise PolicyDocumentError(
                (PolicyDiagnostic(code, line=token.start_mark.line + 1, column=token.start_mark.column + 1),)
            )
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


def _contains_surrogate(value: str) -> bool:
    return any(0xD800 <= ord(character) <= 0xDFFF for character in value)


def _validate_bounds(value: object, path: JsonPath = (), depth: int = 0) -> None:
    if depth > MAX_POLICY_DEPTH:
        raise PolicyDocumentError((PolicyDiagnostic("limit_depth", path),))
    if isinstance(value, str):
        if _contains_surrogate(value):
            raise PolicyDocumentError((PolicyDiagnostic("invalid_unicode", path),))
        if len(value) > MAX_STRING_LENGTH:
            raise PolicyDocumentError((PolicyDiagnostic("limit_string", path),))
        return
    if isinstance(value, float):
        code = "non_finite_number" if not math.isfinite(value) else "unsupported_float"
        raise PolicyDocumentError((PolicyDiagnostic(code, path),))
    if isinstance(value, list):
        limit = MAX_POLICY_RULES if path == ("spec", "rules") else MAX_COLLECTION_ITEMS
        if len(value) > limit:
            raise PolicyDocumentError((PolicyDiagnostic("limit_collection", path),))
        for index, item in enumerate(value):
            _validate_bounds(item, (*path, index), depth + 1)
        return
    if isinstance(value, dict):
        if len(value) > MAX_COLLECTION_ITEMS:
            raise PolicyDocumentError((PolicyDiagnostic("limit_collection", path),))
        for key, item in value.items():
            if not isinstance(key, str):
                raise PolicyDocumentError((PolicyDiagnostic("mapping_key_type", path),))
            if _contains_surrogate(key):
                raise PolicyDocumentError((PolicyDiagnostic("invalid_unicode", (*path, key)),))
            if len(key) > 128:
                raise PolicyDocumentError((PolicyDiagnostic("limit_key", (*path, key)),))
            normalized_key = re.sub(r"[^a-z0-9]", "", key.lower())
            if normalized_key in _SENSITIVE_KEY_NAMES and not any(
                isinstance(part, str) and part.startswith("x-") for part in path
            ):
                raise PolicyDocumentError((PolicyDiagnostic("forbidden_sensitive_field", (*path, key)),))
            _validate_bounds(item, (*path, key), depth + 1)


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


def _schema_diagnostics(text: str, value: object) -> tuple[PolicyDiagnostic, ...]:
    try:
        source_node = yaml.compose(text, Loader=_PolicyLoader)
    except yaml.YAMLError:
        source_node = None
    diagnostics: list[PolicyDiagnostic] = []
    errors = sorted(
        _policy_document_validator().iter_errors(cast(JsonSchemaValue, value)),
        key=lambda item: tuple(str(part) for part in item.path),
    )
    for error in errors[:MAX_DIAGNOSTICS]:
        path: JsonPath = tuple(error.absolute_path)
        node = _node_for_path(source_node, path)
        diagnostics.append(
            PolicyDiagnostic(
                f"schema_{error.validator}",
                path,
                line=node.start_mark.line + 1 if node is not None else None,
                column=node.start_mark.column + 1 if node is not None else None,
            )
        )
    return tuple(diagnostics)


def _validate_rule_ids(value: dict[str, object]) -> None:
    spec = value.get("spec")
    if not isinstance(spec, dict):
        return
    rules = spec.get("rules")
    if not isinstance(rules, list):
        return
    seen: set[str] = set()
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue
        rule_id = rule.get("id")
        if not isinstance(rule_id, str):
            continue
        if rule_id in seen:
            raise PolicyDocumentError((PolicyDiagnostic("duplicate_rule_id", ("spec", "rules", index, "id")),))
        seen.add(rule_id)


def _validate_timestamps(value: dict[str, object]) -> None:
    spec = value.get("spec")
    if not isinstance(spec, dict):
        return
    rules = spec.get("rules")
    if not isinstance(rules, list):
        return
    timestamp_paths: list[tuple[JsonPath, object]] = []
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue
        lifetime = rule.get("lifetime")
        provenance = rule.get("provenance")
        if isinstance(lifetime, dict) and lifetime.get("expiresAt") is not None:
            timestamp_paths.append((("spec", "rules", index, "lifetime", "expiresAt"), lifetime.get("expiresAt")))
        if isinstance(provenance, dict):
            timestamp_paths.append((("spec", "rules", index, "provenance", "createdAt"), provenance.get("createdAt")))
            timestamp_paths.append((("spec", "rules", index, "provenance", "updatedAt"), provenance.get("updatedAt")))
    for path, timestamp in timestamp_paths:
        if not isinstance(timestamp, str):
            continue
        try:
            datetime.fromisoformat(timestamp.removesuffix("Z") + "+00:00")
        except ValueError as error:
            raise PolicyDocumentError((PolicyDiagnostic("invalid_timestamp", path),)) from error


def parse_policy_document_yaml(source: str | bytes) -> GuardPolicyDocument:
    """Parse and validate one strict GuardPolicy YAML document."""

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
    diagnostics = _schema_diagnostics(text, value)
    if diagnostics:
        raise PolicyDocumentError(diagnostics)
    if not isinstance(value, dict):
        raise PolicyDocumentError((PolicyDiagnostic("schema_type"),))
    _validate_rule_ids(value)
    _validate_timestamps(value)
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

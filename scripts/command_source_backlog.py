#!/usr/bin/env python3
"""Convert reviewed open command-extension heads without executing PR code.

The backlog contains generated Python modules written by contributors.  This
module deliberately treats those modules as untrusted text: it parses them
with :mod:`ast`, evaluates a small allowlist of literal expressions and known
matcher constructors, and emits the versioned native source document.  It is
development tooling only.  The Rust compiler remains the authority for source
validation and program admission.

The command line entry point consumes a pinned backlog inventory and an
optional directory of already fetched blobs.  It never fetches or imports a
PR, mutates an author branch, or posts to a remote service.  Proposed files
are written with create-only/idempotent semantics and every result carries
the pinned repository, head, source path, and blob digest.
"""

from __future__ import annotations

import argparse
import ast
import dataclasses
import hashlib
import json
import re
import subprocess
import sys
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import ClassVar

SOURCE_SCHEMA = "guard.command-extension-source.v1"
BUILD_SCHEMA = "guard.command-extension-build.v1"
INVENTORY_SCHEMA = "guard.declarative-backlog-inventory.v1"
MAX_SOURCE_BYTES = 262_144
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_AST_NODES = 30_000
MAX_AST_DEPTH = 64
MAX_COMPREHENSION_ITEMS = 4_096
MAX_EVALUATION_STEPS = 100_000
MAX_EVALUATED_ITEMS = 32_768
MAX_SEQUENCE_ITEMS = 16_384
MAX_STRING_BYTES = 1 * 1024 * 1024
MAX_OUTPUT_FILES = 512

_ID = re.compile(r"^[a-z0-9][a-z0-9.-]*$")
_EXTENSION_ID = re.compile(r"^command\.[a-z0-9][a-z0-9.-]*$")
_SHA1 = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


# Imports are provenance declarations only: the converter never loads them.
# Keep the module and symbol pair closed so an attacker cannot make a reviewed
# constructor name resolve to an arbitrary local module.
_REVIEWED_IMPORTS: dict[str, frozenset[str]] = {
    "command_rules": frozenset(
        {
            "AnyMatcher",
            "AllMatcher",
            "PipelineMatcher",
            "ArgumentMatcher",
            "ExecutableMatcher",
            "ExecutablePathSetMatcher",
            "OperandGatedFlagMatcher",
            "EnvironmentNameMatcher",
            "LeadingSubcommandMatcher",
            "CommandSequenceMatcher",
            "SubcommandOperandPrefixMatcher",
            "OptionValueKeyMatcher",
            "LeadingOperandCountMatcher",
            "TrailingOperandPrefixMatcher",
            "TrailingOperandHostTargetMatcher",
            "TrailingOperandRemoteAliasMatcher",
            "_ZeroOperandFlagMatcher",
            "PhpArtisanScriptMatcher",
            "CurlElasticsearchDeleteMatcher",
            "Repo2nbUnresolvedExpansionMatcher",
            "TuiRunnerUnresolvedExpansionMatcher",
            "ReviewedLiteralCommandMatcher",
            "CommandSafetyRule",
            "CommandSafeVariant",
        }
    ),
    "command_extension_matchers": frozenset(
        {
            "executable_names",
            "executable_matcher",
            "executable_path_set_matcher",
            "with_required_flag",
            "safe_flag_variant",
            "safe_option_variant",
        }
    ),
    "command_extension_specs": frozenset({"CommandExtensionSpec"}),
    "command_operand_matchers": frozenset(
        {
            "OperandGatedFlagMatcher",
            "TrailingOperandPrefixMatcher",
            "TrailingOperandHostTargetMatcher",
            "TrailingOperandRemoteAliasMatcher",
        }
    ),
    "command_structured_matchers": frozenset(
        {
            "LeadingOperandCountMatcher",
            "SubcommandOperandPrefixMatcher",
            "OptionValueKeyMatcher",
            "EnvironmentNameMatcher",
        }
    ),
    "command_database_matchers": frozenset(
        {"ArgumentCommandMatcher", "CommandSequenceMatcher", "LeadingSubcommandMatcher"}
    ),
    "command_path_set_matcher": frozenset({"ExecutablePathSetMatcher"}),
    "command_framework_extensions": frozenset({"PhpArtisanScriptMatcher"}),
    "command_search_messaging_extensions": frozenset({"CurlElasticsearchDeleteMatcher"}),
    "command_repo2nb_extensions": frozenset({"Repo2nbUnresolvedExpansionMatcher"}),
    "command_tui_runner_extensions": frozenset({"TuiRunnerUnresolvedExpansionMatcher"}),
    "command_reviewed_literal_matcher": frozenset({"ReviewedLiteralCommandMatcher"}),
}


@dataclasses.dataclass(frozen=True)
class Diagnostic:
    """One actionable structural conversion diagnostic."""

    code: str
    message: str
    filename: str
    line: int = 0
    column: int = 0
    pointer: str = ""
    native_operation: str | None = None

    def as_dict(self) -> dict[str, object]:
        value: dict[str, object] = {
            "code": self.code,
            "message": self.message,
            "file": self.filename,
            "line": self.line,
            "column": self.column,
        }
        if self.pointer:
            value["pointer"] = self.pointer
        if self.native_operation:
            value["required_native_operation"] = self.native_operation
        return value


class ConversionRejectedError(ValueError):
    """Raised internally when a source cannot be proven structural."""

    def __init__(self, diagnostic: Diagnostic):
        super().__init__(diagnostic.message)
        self.diagnostic = diagnostic


# Keep the short historical name available to callers and tests.
ConversionRejected = ConversionRejectedError


@dataclasses.dataclass(frozen=True)
class MatcherNode:
    op: str
    config: dict[str, object]
    matchers: tuple[MatcherNode, ...] = ()
    producer: MatcherNode | None = None
    consumer: MatcherNode | None = None

    def to_source(self) -> dict[str, object]:
        value: dict[str, object] = {"op": self.op, "config": _json_value(self.config)}
        if self.matchers:
            value["matchers"] = [child.to_source() for child in self.matchers]
        if self.producer is not None:
            value["producer"] = self.producer.to_source()
        if self.consumer is not None:
            value["consumer"] = self.consumer.to_source()
        return value


@dataclasses.dataclass(frozen=True)
class ConstructorValue:
    kind: str
    fields: dict[str, object]


@dataclasses.dataclass(frozen=True)
class ConversionResult:
    source: dict[str, object] | None
    diagnostics: tuple[Diagnostic, ...]
    symbols: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return self.source is not None and not self.diagnostics


def _json_value(value: object) -> object:
    """Turn evaluator containers into deterministic JSON-compatible values."""

    if isinstance(value, MatcherNode):
        return value.to_source()
    if isinstance(value, ConstructorValue):
        return {"__kind": value.kind, **{key: _json_value(item) for key, item in value.fields.items()}}
    if isinstance(value, frozenset):
        return sorted((_json_value(item) for item in value), key=lambda item: json.dumps(item, sort_keys=True))
    if isinstance(value, tuple):
        return [_json_value(item) for item in value]
    if isinstance(value, list):
        return [_json_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    return value


def _as_sequence(value: object, *, name: str) -> tuple[object, ...]:
    if isinstance(value, (tuple, list, frozenset)):
        return tuple(value)
    raise TypeError(f"{name} must be a static sequence")


def _as_strings(value: object, *, name: str) -> tuple[str, ...]:
    values = _as_sequence(value, name=name)
    if any(not isinstance(item, str) for item in values):
        raise TypeError(f"{name} must contain only strings")
    return tuple(str(item) for item in values)


def _scalar_frozenset(value: object, *, node: ast.AST, name: str, filename: str) -> frozenset[object]:
    """Build a static set only from scalar values, before Python hashes them."""

    values = _as_sequence(value, name=name)
    if any(not isinstance(item, (str, bool, int)) and item is not None for item in values):
        raise ConversionRejected(
            Diagnostic(
                "non_scalar_set_rejected",
                f"{name} may contain only scalar strings, booleans, integers, or nulls",
                filename,
                line=getattr(node, "lineno", 0),
                column=getattr(node, "col_offset", 0),
            )
        )
    try:
        return frozenset(values)
    except TypeError as error:
        raise ConversionRejected(
            Diagnostic("non_scalar_set_rejected", f"{name} contains an unhashable value", filename)
        ) from error


def _as_bool(value: object, *, name: str) -> bool:
    if not isinstance(value, bool):
        raise TypeError(f"{name} must be a boolean")
    return value


def _as_matcher(value: object, *, name: str) -> MatcherNode:
    if not isinstance(value, MatcherNode):
        raise TypeError(f"{name} must be a known matcher")
    return value


class _RestrictedEvaluator:
    """Bounded AST evaluator for generated, literal-only extension modules."""

    _MATCHERS: ClassVar[set[str]] = {
        "AnyMatcher",
        "AllMatcher",
        "PipelineMatcher",
        "ArgumentMatcher",
        "ExecutableMatcher",
        "ExecutablePathSetMatcher",
        "ArgumentCommandMatcher",
        "LeadingOperandCountMatcher",
        "OperandGatedFlagMatcher",
        "EnvironmentNameMatcher",
        "LeadingSubcommandMatcher",
        "CommandSequenceMatcher",
        "SubcommandOperandPrefixMatcher",
        "OptionValueKeyMatcher",
        "TrailingOperandPrefixMatcher",
        "TrailingOperandHostTargetMatcher",
        "TrailingOperandRemoteAliasMatcher",
        "_ZeroOperandFlagMatcher",
        "PhpArtisanScriptMatcher",
        "CurlElasticsearchDeleteMatcher",
        "Repo2nbUnresolvedExpansionMatcher",
        "TuiRunnerUnresolvedExpansionMatcher",
        "ReviewedLiteralCommandMatcher",
    }
    _NATIVE_MATCHER_SPECS: ClassVar[dict[str, tuple[object, ...]]] = {
        "ExecutablePathSetMatcher": (
            "executable-path-set.v1",
            (
                "executables",
                "required_flags",
                "forbidden_flags",
                "allow_leading_options",
                "leading_options_with_values",
                "interspersed_options_with_values",
                "interspersed_flags",
                "options_with_values",
                "inverse_flag_pairs",
                "required_option_values",
                "required_flags_in_all_arguments",
                "fail_secure_unknown_options",
                "paths",
            ),
            ("executables", "paths"),
        ),
        "ArgumentCommandMatcher": (
            "argument-command.v1",
            ("executables", "command", "minimum_abbreviation_length", "minimum_position"),
            ("executables", "command", "minimum_abbreviation_length"),
        ),
        "CommandSequenceMatcher": (
            "command-sequence.v1",
            ("executables", "command_arities", "target_commands", "options_with_values", "forbidden_flags"),
            ("executables", "command_arities", "target_commands"),
        ),
        "LeadingSubcommandMatcher": (
            "leading-subcommand.v1",
            (
                "executables",
                "subcommands",
                "options_with_values",
                "forbidden_flags",
                "required_flags_anywhere",
                "interleaved_options_with_values",
                "forbidden_flags_before_delimiter",
            ),
            ("executables", "subcommands"),
        ),
        "LeadingOperandCountMatcher": (
            "leading-operand-count.v1",
            ("executables", "minimum_operands", "options_with_values", "forbidden_flags"),
            ("executables", "minimum_operands"),
        ),
        "SubcommandOperandPrefixMatcher": (
            "subcommand-operand-prefix.v1",
            (
                "executables",
                "subcommands",
                "operand_prefixes",
                "leading_options_with_values",
                "options_with_values",
                "leading_operands_to_skip",
                "options_supplying_leading_operands",
            ),
            ("executables", "subcommands", "operand_prefixes"),
        ),
        "OptionValueKeyMatcher": (
            "option-value-key.v1",
            (
                "executables",
                "option_names",
                "value_keys",
                "forbidden_flags",
                "ignored_values",
                "required_key_values",
                "cluster_options_with_values",
            ),
            ("executables", "option_names", "value_keys"),
        ),
        "EnvironmentNameMatcher": (
            "environment-name.v1",
            ("executables", "environment_names"),
            ("executables", "environment_names"),
        ),
        "OperandGatedFlagMatcher": (
            "operand-gated-flags.v1",
            (
                "executables",
                "required_flags",
                "options_with_values",
                "forbidden_flags",
                "minimum_operands",
                "excluded_first_arguments",
            ),
            ("executables", "required_flags"),
        ),
        "TrailingOperandPrefixMatcher": (
            "trailing-operand-prefix.v1",
            (
                "executables",
                "options_with_values",
                "required_flags",
                "forbidden_flags",
                "minimum_operands",
                "excluded_first_arguments",
                "operand_prefixes",
            ),
            ("executables", "operand_prefixes"),
        ),
        "TrailingOperandHostTargetMatcher": (
            "trailing-operand-host-target.v1",
            (
                "executables",
                "options_with_values",
                "required_flags",
                "forbidden_flags",
                "minimum_operands",
                "excluded_first_arguments",
            ),
            ("executables",),
        ),
        "TrailingOperandRemoteAliasMatcher": (
            "trailing-operand-remote-alias.v1",
            (
                "executables",
                "options_with_values",
                "required_flags",
                "forbidden_flags",
                "minimum_operands",
                "excluded_first_arguments",
                "allow_bare_names",
                "bare_names_only",
            ),
            ("executables",),
        ),
        "_ZeroOperandFlagMatcher": (
            "zero-operand-flags.v1",
            ("executables", "required_flags", "options_with_values"),
            ("executables", "required_flags", "options_with_values"),
        ),
        "PhpArtisanScriptMatcher": ("php-artisan-script.v1", ("subcommands", "required_flags"), ("subcommands",)),
        "CurlElasticsearchDeleteMatcher": ("curl-elasticsearch-delete.v1", ("executables", "service_ports"), ()),
        "Repo2nbUnresolvedExpansionMatcher": (
            "repo2nb-expansion.v1",
            ("subcommand", "launchers", "leading_options_with_values", "expansion_markers"),
            (),
        ),
        "TuiRunnerUnresolvedExpansionMatcher": (
            "tui-runner-expansion.v1",
            ("launchers", "leading_options_with_values", "expansion_markers"),
            (),
        ),
        "ReviewedLiteralCommandMatcher": (
            "reviewed-literal.v1",
            ("executable", "arguments"),
            ("executable", "arguments"),
        ),
    }
    _HELPERS: ClassVar[set[str]] = {
        "executable_names",
        "executable_matcher",
        "executable_path_set_matcher",
        "with_required_flag",
        "safe_flag_variant",
        "safe_option_variant",
    }
    _STRUCTURED: ClassVar[set[str]] = {"CommandSafetyRule", "CommandSafeVariant", "CommandExtensionSpec"}
    _LITERAL_CALLS: ClassVar[set[str]] = {"tuple", "list", "set", "frozenset"}

    def __init__(self, source: str, filename: str):
        self.source = source
        self.filename = filename
        self.env: dict[str, object] = {}
        self.diagnostics: list[Diagnostic] = []
        self.node_count = 0
        self._bindings: list[str] = []
        self._evaluation_steps = 0
        self._evaluation_depth = 0
        self._evaluated_items = 0
        self._string_bytes = 0
        self._imported_names: dict[str, str] = {}

    def _step(self, node: ast.AST) -> None:
        self._evaluation_steps += 1
        if self._evaluation_steps > MAX_EVALUATION_STEPS:
            self.reject(
                node, "evaluation_budget_exceeded", f"restricted evaluation exceeds {MAX_EVALUATION_STEPS} steps"
            )

    def _charge_items(self, node: ast.AST, count: int) -> None:
        if count < 0 or count > MAX_SEQUENCE_ITEMS:
            self.reject(node, "sequence_budget_exceeded", f"one static sequence exceeds {MAX_SEQUENCE_ITEMS} items")
        self._evaluated_items += count
        if self._evaluated_items > MAX_EVALUATED_ITEMS:
            self.reject(
                node,
                "evaluation_item_budget_exceeded",
                f"restricted evaluation materializes more than {MAX_EVALUATED_ITEMS} items",
            )

    def _charge_string_size(self, node: ast.AST, size: int) -> None:
        if size > MAX_STRING_BYTES:
            self.reject(node, "string_budget_exceeded", f"one static string exceeds {MAX_STRING_BYTES} bytes")
        self._string_bytes += size
        if self._string_bytes > MAX_STRING_BYTES:
            self.reject(
                node,
                "string_budget_exceeded",
                f"restricted evaluation materializes more than {MAX_STRING_BYTES} string bytes",
            )

    def _charge_string(self, node: ast.AST, value: str) -> None:
        self._charge_string_size(node, len(value.encode("utf-8")))

    def diagnostic(
        self,
        node: ast.AST,
        code: str,
        message: str,
        *,
        pointer: str = "",
        native_operation: str | None = None,
    ) -> None:
        self.diagnostics.append(
            Diagnostic(
                code=code,
                message=message,
                filename=self.filename,
                line=getattr(node, "lineno", 0),
                column=getattr(node, "col_offset", 0),
                pointer=pointer,
                native_operation=native_operation,
            )
        )

    def reject(
        self,
        node: ast.AST,
        code: str,
        message: str,
        *,
        pointer: str = "",
        native_operation: str | None = None,
    ) -> None:
        diagnostic = Diagnostic(
            code=code,
            message=message,
            filename=self.filename,
            line=getattr(node, "lineno", 0),
            column=getattr(node, "col_offset", 0),
            pointer=pointer,
            native_operation=native_operation,
        )
        raise ConversionRejected(diagnostic)

    def parse(self) -> ast.Module:
        encoded = self.source.encode("utf-8")
        if len(encoded) > MAX_SOURCE_BYTES:
            self.reject(
                ast.Module(body=[], type_ignores=[]), "source_too_large", f"source exceeds {MAX_SOURCE_BYTES} bytes"
            )
        try:
            tree = ast.parse(self.source, filename=self.filename, mode="exec")
        except RecursionError:
            self.reject(
                ast.Module(body=[], type_ignores=[]),
                "ast_depth_exceeded",
                f"AST nesting exceeds {MAX_AST_DEPTH} levels",
            )
        except SyntaxError as error:
            self.diagnostics.append(
                Diagnostic(
                    code="python_syntax_error",
                    message=f"Python syntax cannot be structurally converted: {error.msg}",
                    filename=self.filename,
                    line=error.lineno or 0,
                    column=error.offset or 0,
                )
            )
            raise ConversionRejected(self.diagnostics[-1]) from error
        pending: list[tuple[ast.AST, int]] = [(tree, 1)]
        while pending:
            node, depth = pending.pop()
            self.node_count += 1
            if self.node_count > MAX_AST_NODES:
                self.reject(node, "ast_budget_exceeded", f"AST exceeds {MAX_AST_NODES} nodes")
            if depth > MAX_AST_DEPTH:
                self.reject(node, "ast_depth_exceeded", f"AST nesting exceeds {MAX_AST_DEPTH} levels")
            pending.extend((child, depth + 1) for child in ast.iter_child_nodes(node))
        return tree

    def evaluate(self) -> dict[str, object]:
        tree = self.parse()
        for statement in tree.body:
            self._step(statement)
            self.statement(statement)
        return self.env

    def statement(self, statement: ast.stmt) -> None:
        if isinstance(statement, ast.ImportFrom):
            if statement.module == "__future__" and all(alias.name == "annotations" for alias in statement.names):
                return
            allowed_names = _REVIEWED_IMPORTS.get(statement.module or "")
            if (
                statement.level == 1
                and allowed_names is not None
                and all(alias.name in allowed_names and alias.asname is None for alias in statement.names)
            ):
                for alias in statement.names:
                    self._imported_names[alias.name] = statement.module or ""
                return
            self.reject(
                statement,
                "dynamic_import_rejected",
                "imports are not evaluated; only reviewed local matcher declarations are permitted",
            )
        if isinstance(statement, ast.Import):
            self.reject(
                statement,
                "dynamic_import_rejected",
                "imports are not evaluated; conversion accepts only literals and known constructors",
            )
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            self.reject(
                statement,
                "custom_code_rejected",
                "custom functions and matcher classes require an explicit native operation "
                "and regression cases before admission",
                native_operation="reviewed-native-operation-and-regression-required",
            )
        if isinstance(
            statement, (ast.For, ast.AsyncFor, ast.While, ast.If, ast.Try, ast.With, ast.AsyncWith, ast.Match)
        ):
            self.reject(
                statement,
                "dynamic_control_flow_rejected",
                "control flow is not part of the restricted conversion grammar",
            )
        if isinstance(statement, ast.Expr):
            if isinstance(statement.value, ast.Constant) and isinstance(statement.value.value, str):
                return
            self.reject(
                statement,
                "top_level_expression_rejected",
                "top-level expressions could execute code and are not converted",
            )
        if isinstance(statement, (ast.Assign, ast.AnnAssign)):
            target = statement.targets[0] if isinstance(statement, ast.Assign) else statement.target
            if not isinstance(target, ast.Name):
                self.reject(statement, "mutation_expression_rejected", "only immutable name bindings are supported")
            if target.id in self._MATCHERS | self._HELPERS | self._STRUCTURED:
                self.reject(
                    target,
                    "constructor_rebinding_rejected",
                    f"reviewed constructor name {target.id!r} cannot be rebound",
                )
            value_node = statement.value
            value = self.expression(value_node)
            if isinstance(statement, ast.Assign):
                for item in statement.targets:
                    if not isinstance(item, ast.Name):
                        self.reject(
                            item, "mutation_expression_rejected", "attribute and subscript assignment is rejected"
                        )
                    self.env[item.id] = value
                    self._bindings.append(item.id)
            else:
                self.env[target.id] = value
                self._bindings.append(target.id)
            return
        if isinstance(
            statement, (ast.AugAssign, ast.Delete, ast.Raise, ast.Assert, ast.Return, ast.Break, ast.Continue, ast.Pass)
        ):
            if isinstance(statement, ast.Pass):
                return
            self.reject(
                statement, "mutation_expression_rejected", "mutation, deletion, and executable statements are rejected"
            )
        self.reject(statement, "unsupported_python_construct", f"unsupported syntax: {type(statement).__name__}")

    def expression(self, node: ast.AST, local: Mapping[str, object] | None = None) -> object:
        self._step(node)
        self._evaluation_depth += 1
        if self._evaluation_depth > MAX_AST_DEPTH:
            self._evaluation_depth -= 1
            self.reject(node, "ast_depth_exceeded", f"expression nesting exceeds {MAX_AST_DEPTH} levels")
        try:
            return self._expression(node, local)
        finally:
            self._evaluation_depth -= 1

    def _expression(self, node: ast.AST, local: Mapping[str, object] | None = None) -> object:
        bindings = self.env if local is None else {**self.env, **local}
        if isinstance(node, ast.Constant):
            if isinstance(node.value, (str, bool, int)) or node.value is None:
                if isinstance(node.value, str):
                    self._charge_string(node, node.value)
                return node.value
            self.reject(node, "literal_type_rejected", "only string, boolean, integer, and null literals are allowed")
        if isinstance(node, ast.Name):
            if node.id in bindings:
                return bindings[node.id]
            if node.id in {"True", "False", "None"}:
                return {"True": True, "False": False, "None": None}[node.id]
            self.reject(node, "unbound_name_rejected", f"name {node.id!r} is not a reviewed literal binding")
        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            if len(node.elts) > MAX_SEQUENCE_ITEMS:
                self.reject(node, "sequence_budget_exceeded", f"one static sequence exceeds {MAX_SEQUENCE_ITEMS} items")
            values: list[object] = []
            for item in node.elts:
                value = self.expression(item.value if isinstance(item, ast.Starred) else item, bindings)
                if isinstance(item, ast.Starred):
                    expanded = _as_sequence(value, name="starred literal")
                    if len(values) + len(expanded) > MAX_SEQUENCE_ITEMS:
                        self.reject(
                            item,
                            "sequence_budget_exceeded",
                            f"expanded static sequence exceeds {MAX_SEQUENCE_ITEMS} items",
                        )
                    self._charge_items(item, len(expanded))
                    values.extend(expanded)
                else:
                    values.append(value)
            self._charge_items(node, len(values))
            if isinstance(node, ast.Set):
                return _scalar_frozenset(values, node=node, name="set values", filename=self.filename)
            return tuple(values)
        if isinstance(node, ast.Dict):
            if len(node.keys) > MAX_SEQUENCE_ITEMS:
                self.reject(node, "sequence_budget_exceeded", f"one static mapping exceeds {MAX_SEQUENCE_ITEMS} items")
            result: dict[object, object] = {}
            for key, value in zip(node.keys, node.values, strict=True):
                if key is None:
                    self.reject(node, "mapping_unpack_rejected", "mapping unpacking is not supported")
                key_value = self.expression(key, bindings)
                if not isinstance(key_value, str):
                    self.reject(key, "mapping_key_rejected", "mapping keys must be strings")
                if key_value in result:
                    self.reject(key, "duplicate_mapping_key", f"duplicate mapping key {key_value!r}")
                result[key_value] = self.expression(value, bindings)
            self._charge_items(node, len(result))
            return result
        if isinstance(node, ast.Starred):
            return self.expression(node.value, bindings)
        if isinstance(node, (ast.ListComp, ast.GeneratorExp, ast.SetComp, ast.DictComp)):
            return self.comprehension(node, bindings)
        if isinstance(node, ast.Call):
            return self.call(node, bindings)
        if isinstance(node, ast.Subscript):
            value = self.expression(node.value, bindings)
            index = self.expression(node.slice, bindings)
            if not isinstance(index, (str, int)):
                self.reject(node, "subscript_index_rejected", "static subscripts require string or integer indices")
            try:
                return value[index]  # type: ignore[index]
            except (IndexError, KeyError, TypeError):
                self.reject(node, "subscript_index_invalid", "static subscript is outside its bound value")
        if isinstance(node, ast.Compare):
            left = self.expression(node.left, bindings)
            result = True
            for operation, comparator in zip(node.ops, node.comparators, strict=True):
                right = self.expression(comparator, bindings)
                if isinstance(operation, ast.In):
                    current = left in right
                elif isinstance(operation, ast.NotIn):
                    current = left not in right
                elif isinstance(operation, ast.Eq):
                    current = left == right
                elif isinstance(operation, ast.NotEq):
                    current = left != right
                else:
                    self.reject(
                        node,
                        "comparison_operator_rejected",
                        "only static membership and equality comparisons are supported",
                    )
                result = result and current
                left = right
            return result
        if isinstance(node, ast.IfExp):
            condition = self.expression(node.test, bindings)
            if not isinstance(condition, bool):
                self.reject(
                    node.test, "conditional_test_rejected", "conditional expressions require a static boolean test"
                )
            return self.expression(node.body if condition else node.orelse, bindings)
        if isinstance(node, ast.JoinedStr):
            parts: list[str] = []
            for part in node.values:
                if isinstance(part, ast.Constant) and isinstance(part.value, str):
                    parts.append(part.value)
                    continue
                if not isinstance(part, ast.FormattedValue) or part.conversion not in {-1, ord("s")}:
                    self.reject(node, "dynamic_expression_rejected", "f-strings may only format static scalar values")
                if not isinstance(part.format_spec, ast.Constant) or part.format_spec.value not in (None, ""):
                    self.reject(
                        node,
                        "dynamic_expression_rejected",
                        "f-string format specifications are not structurally converted",
                    )
                value = self.expression(part.value, bindings)
                if not isinstance(value, (str, int, bool)):
                    self.reject(
                        node,
                        "dynamic_expression_rejected",
                        "f-string values must be static strings, integers, or booleans",
                    )
                parts.append(str(value))
            value = "".join(parts)
            self._charge_string(node, value)
            return value
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self.expression(node.left, bindings)
            right = self.expression(node.right, bindings)
            if isinstance(left, str) and isinstance(right, str):
                self._charge_string_size(node, len(left.encode("utf-8")) + len(right.encode("utf-8")))
                return left + right
            if isinstance(left, (tuple, list)) and isinstance(right, type(left)):
                if len(left) + len(right) > MAX_SEQUENCE_ITEMS:
                    self.reject(
                        node, "sequence_budget_exceeded", f"one static sequence exceeds {MAX_SEQUENCE_ITEMS} items"
                    )
                self._charge_items(node, len(left) + len(right))
                return left + right
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
            left = self.expression(node.left, bindings)
            right = self.expression(node.right, bindings)
            if isinstance(left, frozenset) and isinstance(right, frozenset):
                value = left | right
                self._charge_items(node, len(value))
                return value
            if isinstance(left, dict) and isinstance(right, dict):
                overlap = set(left) & set(right)
                if overlap:
                    self.reject(
                        node, "mapping_union_overlap", "static mapping union cannot silently replace an existing key"
                    )
                value = {**left, **right}
                self._charge_items(node, len(value))
                return value
            self.reject(
                node, "binary_expression_rejected", "static union requires two non-overlapping sets or mappings"
            )
            self.reject(node, "binary_expression_rejected", "only static string or sequence concatenation is supported")
        if isinstance(node, ast.Attribute):
            value = self.expression(node.value, bindings)
            if isinstance(value, MatcherNode) and node.attr == "matchers":
                return value.matchers
            self.reject(
                node, "dynamic_expression_rejected", "only the reviewed MatcherNode.matchers attribute is readable"
            )
        if isinstance(node, (ast.UnaryOp, ast.BoolOp, ast.Lambda)):
            self.reject(
                node, "dynamic_expression_rejected", f"dynamic expression {type(node).__name__} is not converted"
            )
        self.reject(node, "unsupported_expression", f"unsupported expression: {type(node).__name__}")

    def comprehension(self, node: ast.AST, local: Mapping[str, object]) -> object:
        self._step(node)
        generators = getattr(node, "generators", ())
        if not generators or any(generator.ifs or generator.is_async for generator in generators):
            self.reject(
                node,
                "dynamic_comprehension_rejected",
                "comprehensions may only iterate over static values without conditions",
            )
        rows: list[dict[str, object]] = []

        def walk(index: int, bindings: dict[str, object]) -> None:
            if len(rows) >= MAX_COMPREHENSION_ITEMS:
                self.reject(
                    node, "comprehension_budget_exceeded", f"comprehension exceeds {MAX_COMPREHENSION_ITEMS} items"
                )
            if index == len(generators):
                rows.append(bindings.copy())
                return
            generator = generators[index]
            iterable = self.expression(generator.iter, bindings)
            try:
                values = tuple(iterable)
            except TypeError:
                self.reject(generator.iter, "comprehension_iterable_rejected", "comprehension iterable is not static")
            if len(values) > MAX_SEQUENCE_ITEMS:
                self.reject(
                    generator.iter,
                    "sequence_budget_exceeded",
                    f"one comprehension source exceeds {MAX_SEQUENCE_ITEMS} items",
                )
            for value in values:
                next_bindings = dict(bindings)
                self.bind_comprehension_target(generator.target, value, next_bindings)
                walk(index + 1, next_bindings)

        walk(0, dict(local))
        if isinstance(node, ast.DictComp):
            self._charge_items(node, len(rows))
            return tuple((self.expression(node.key, row), self.expression(node.value, row)) for row in rows)
        values = [self.expression(node.elt, row) for row in rows]
        self._charge_items(node, len(values))
        if isinstance(node, ast.SetComp):
            return frozenset(values)
        return tuple(values)

    def bind_comprehension_target(self, target: ast.AST, value: object, bindings: dict[str, object]) -> None:
        """Bind only fixed-shape tuple targets; starred targets stay rejected."""

        if isinstance(target, ast.Name):
            bindings[target.id] = value
            return
        if isinstance(target, (ast.Tuple, ast.List)):
            if any(isinstance(item, ast.Starred) for item in target.elts):
                self.reject(
                    target,
                    "comprehension_target_rejected",
                    "starred comprehension targets are not structurally bounded",
                )
            values = _as_sequence(value, name="comprehension target")
            if len(values) != len(target.elts):
                self.reject(
                    target, "comprehension_target_rejected", "tuple comprehension targets require an exact static shape"
                )
            for child, child_value in zip(target.elts, values, strict=True):
                self.bind_comprehension_target(child, child_value, bindings)
            return
        self.reject(
            target, "comprehension_target_rejected", "comprehension targets must be names or fixed-shape tuples"
        )

    def call(self, node: ast.Call, local: Mapping[str, object]) -> object:
        if not isinstance(node.func, ast.Name):
            self.reject(node, "dynamic_call_rejected", "attribute calls and imported callables are not evaluated")
        name = node.func.id
        positional: list[object] = []
        for argument in node.args:
            value = self.expression(argument, local)
            if isinstance(argument, ast.Starred):
                expanded = _as_sequence(value, name=f"{name} starred argument")
                if len(positional) + len(expanded) > MAX_SEQUENCE_ITEMS:
                    self.reject(
                        argument,
                        "sequence_budget_exceeded",
                        f"expanded {name} arguments exceed {MAX_SEQUENCE_ITEMS} items",
                    )
                self._charge_items(argument, len(expanded))
                positional.extend(expanded)
            else:
                positional.append(value)
        keywords: dict[str, object] = {}
        for keyword in node.keywords:
            if keyword.arg is None:
                self.reject(keyword, "call_unpacking_rejected", f"{name} keyword unpacking is not supported")
            if keyword.arg in keywords:
                self.reject(keyword, "duplicate_call_argument", f"duplicate keyword {keyword.arg!r}")
            keywords[keyword.arg] = self.expression(keyword.value, local)

        if name in self._LITERAL_CALLS:
            if len(positional) > 1 or keywords:
                self.reject(node, "literal_call_shape_rejected", f"{name} accepts one positional static value")
            if not positional:
                return {"tuple": (), "list": [], "set": frozenset(), "frozenset": frozenset()}[name]
            values = _as_sequence(positional[0], name=name)
            self._charge_items(node, len(values))
            if name == "tuple":
                return tuple(values)
            if name == "list":
                return list(values)
            return _scalar_frozenset(values, node=node, name=name, filename=self.filename)
        if name == "sorted":
            if len(positional) != 1 or keywords:
                self.reject(node, "literal_call_shape_rejected", "sorted accepts one positional static sequence")
            values = _as_sequence(positional[0], name="sorted")
            if any(not isinstance(item, (str, int)) for item in values):
                self.reject(node, "literal_type_rejected", "sorted values must be scalar strings or integers")
            self._charge_items(node, len(values))
            return sorted(values)
        if name == "executable_names":
            if len(positional) != 1 or keywords or not isinstance(positional[0], str):
                self.reject(node, "known_helper_arguments_invalid", "executable_names requires one literal name")
            value = positional[0]
            return frozenset((value, f"{value}.cmd", f"{value}.exe"))
        if name == "executable_matcher":
            return self.executable_matcher(node, positional, keywords)
        if name == "executable_path_set_matcher":
            return self.executable_path_set_helper(node, positional, keywords)
        if name in {"AnyMatcher", "AllMatcher"}:
            if positional and "matchers" in keywords:
                self.reject(node, "duplicate_call_argument", "matcher children supplied twice")
            children = keywords.get("matchers", positional[0] if positional else None)
            if children is None:
                self.reject(node, "matcher_arguments_invalid", f"{name} requires matchers")
            children_nodes = tuple(
                _as_matcher(item, name=f"{name}.matchers") for item in _as_sequence(children, name="matchers")
            )
            if not children_nodes:
                self.reject(node, "matcher_arguments_invalid", f"{name} requires at least one child")
            if name == "AnyMatcher":
                return MatcherNode("any.v1", {}, matchers=children_nodes)
            return MatcherNode("all.v1", {}, matchers=children_nodes)
        if name == "PipelineMatcher":
            if keywords.keys() != {"producer", "consumer"} or positional:
                self.reject(node, "matcher_arguments_invalid", "PipelineMatcher requires producer and consumer")
            return MatcherNode(
                "pipeline.v1",
                {},
                producer=_as_matcher(keywords["producer"], name="producer"),
                consumer=_as_matcher(keywords["consumer"], name="consumer"),
            )
        if name == "ArgumentMatcher":
            return self.argument_matcher(node, positional, keywords)
        if name == "ExecutableMatcher":
            return self.executable_matcher_constructor(node, positional, keywords)
        if name in self._NATIVE_MATCHER_SPECS:
            return self.native_matcher_constructor(node, name, positional, keywords)
        if name in {"with_required_flag", "safe_flag_variant", "safe_option_variant"}:
            return self.safe_variant_helper(node, name, positional, keywords)
        if name == "CommandSafeVariant":
            fields = self.constructor_fields(node, name, positional, keywords, ("variant_id", "title", "matcher"))
            return ConstructorValue("safe_variant", fields)
        if name == "CommandSafetyRule":
            fields = self.constructor_fields(node, name, positional, keywords, ())
            return ConstructorValue("rule", fields)
        if name == "CommandExtensionSpec":
            fields = self.constructor_fields(node, name, positional, keywords, ())
            return ConstructorValue("extension", fields)
        if name in self._MATCHERS:
            self.reject(
                node,
                "native_operation_required",
                f"{name} is not mapped by the restricted converter",
                native_operation=f"{name}.v1",
            )
        if name in self._STRUCTURED or name in self._HELPERS:
            self.reject(
                node, "known_constructor_arguments_invalid", f"{name} arguments are not structurally understood"
            )
        self.reject(node, "dynamic_call_rejected", f"call to {name!r} is not in the reviewed conversion allowlist")

    def native_matcher_constructor(
        self,
        node: ast.Call,
        name: str,
        positional: Sequence[object],
        keywords: Mapping[str, object],
    ) -> MatcherNode:
        operation, field_names, required_names = self._NATIVE_MATCHER_SPECS[name]
        fields = self.constructor_fields(node, name, positional, keywords, field_names)
        unknown = set(fields) - set(field_names)
        if unknown:
            self.reject(
                node,
                "known_constructor_arguments_invalid",
                f"{name} has unknown arguments: {sorted(unknown)}",
                native_operation=operation,
            )
        missing = [field for field in required_names if field not in fields]
        if missing:
            self.reject(
                node, "matcher_arguments_invalid", f"{name} requires: {', '.join(missing)}", native_operation=operation
            )
        config = {key: _json_value(value) for key, value in fields.items()}
        return MatcherNode(operation, config)

    def executable_path_set_helper(
        self,
        node: ast.Call,
        positional: Sequence[object],
        keywords: Mapping[str, object],
    ) -> MatcherNode:
        fields = self.constructor_fields(
            node, "executable_path_set_matcher", positional, keywords, ("executable", "paths")
        )
        allowed = {"executable", "paths", "global_options_with_values", "global_flags", "fail_secure_unknown_options"}
        unknown = set(fields) - allowed
        if unknown:
            self.reject(
                node,
                "known_helper_arguments_invalid",
                f"executable_path_set_matcher has unknown arguments: {sorted(unknown)}",
            )
        executable = fields.get("executable")
        if not isinstance(executable, str) or not executable:
            self.reject(node, "matcher_arguments_invalid", "executable_path_set_matcher requires a literal executable")
        if "paths" not in fields:
            self.reject(
                node,
                "matcher_arguments_invalid",
                "executable_path_set_matcher requires paths",
                native_operation="executable-path-set.v1",
            )
        config: dict[str, object] = {
            "executables": [executable, f"{executable}.cmd", f"{executable}.exe"],
            "paths": _json_value(fields["paths"]),
        }
        mapping = {
            "global_options_with_values": "interspersed_options_with_values",
            "global_flags": "interspersed_flags",
            "fail_secure_unknown_options": "fail_secure_unknown_options",
        }
        for source_name, target_name in mapping.items():
            value = fields.get(source_name)
            if value in (None, (), frozenset(), False):
                continue
            config[target_name] = _json_value(value)
        return MatcherNode("executable-path-set.v1", config)

    def constructor_fields(
        self,
        node: ast.Call,
        name: str,
        positional: Sequence[object],
        keywords: Mapping[str, object],
        positional_names: Sequence[str],
    ) -> dict[str, object]:
        if len(positional) > len(positional_names):
            self.reject(node, "constructor_arguments_invalid", f"{name} has too many positional arguments")
        fields = {key: value for key, value in zip(positional_names, positional, strict=False)}
        for key, value in keywords.items():
            if key in fields:
                self.reject(node, "duplicate_call_argument", f"duplicate {name} argument {key!r}")
            fields[key] = value
        return fields

    def argument_matcher(
        self, node: ast.Call, positional: Sequence[object], keywords: Mapping[str, object]
    ) -> MatcherNode:
        fields = self.constructor_fields(
            node, "ArgumentMatcher", positional, keywords, ("executables", "required_arguments")
        )
        try:
            executables = _as_strings(fields["executables"], name="executables")
            required = _as_strings(fields["required_arguments"], name="required_arguments")
        except (KeyError, TypeError) as error:
            self.reject(node, "matcher_arguments_invalid", str(error))
        if not executables or not required:
            self.reject(
                node, "matcher_arguments_invalid", "ArgumentMatcher requires executables and required arguments"
            )
        return MatcherNode(
            "arguments.v1", {"executables": sorted(set(executables)), "required_arguments": sorted(set(required))}
        )

    def executable_matcher(
        self, node: ast.Call, positional: Sequence[object], keywords: Mapping[str, object]
    ) -> MatcherNode:
        if not positional or not isinstance(positional[0], str):
            self.reject(node, "matcher_arguments_invalid", "executable_matcher requires a literal executable")
        executable = positional[0]
        subcommands = positional[1:]
        if any(not isinstance(value, str) for value in subcommands):
            self.reject(node, "matcher_arguments_invalid", "subcommands must be literal strings")
        fields = dict(keywords)
        defaults: dict[str, object] = {
            "required_flags": frozenset(),
            "forbidden_flags": frozenset(),
            "global_options_with_values": frozenset(),
            "global_flags": frozenset(),
            "allow_leading_options": False,
            "leading_options_with_values": frozenset(),
            "options_with_values": frozenset(),
            "fail_secure_unknown_options": False,
        }
        unknown = set(fields) - set(defaults)
        if unknown:
            self.reject(
                node, "known_helper_arguments_invalid", f"executable_matcher has unknown arguments: {sorted(unknown)}"
            )
        defaults.update(fields)
        executable_names = (executable, f"{executable}.cmd", f"{executable}.exe")
        return self.executable_config(node, executable, subcommands, defaults, executables=executable_names)

    def executable_matcher_constructor(
        self, node: ast.Call, positional: Sequence[object], keywords: Mapping[str, object]
    ) -> MatcherNode:
        fields = self.constructor_fields(node, "ExecutableMatcher", positional, keywords, ("executables",))
        try:
            executables = _as_strings(fields.pop("executables"), name="executables")
        except (KeyError, TypeError) as error:
            self.reject(node, "matcher_arguments_invalid", str(error))
        subcommands = tuple(_as_strings(fields.pop("subcommands", ()), name="subcommands"))
        defaults: dict[str, object] = {
            "required_flags": frozenset(),
            "forbidden_flags": frozenset(),
            "allow_leading_options": False,
            "leading_options_with_values": frozenset(),
            "interspersed_options_with_values": frozenset(),
            "interspersed_flags": frozenset(),
            "options_with_values": frozenset(),
            "inverse_flag_pairs": frozenset(),
            "required_option_values": (),
            "required_flags_in_all_arguments": False,
            "fail_secure_unknown_options": False,
        }
        unknown = set(fields) - set(defaults)
        if unknown:
            self.reject(
                node,
                "known_constructor_arguments_invalid",
                f"ExecutableMatcher has unknown arguments: {sorted(unknown)}",
            )
        defaults.update(fields)
        return self.executable_config(
            node, executables[0] if len(executables) == 1 else None, subcommands, defaults, executables=executables
        )

    def executable_config(
        self,
        node: ast.Call,
        executable: str | None,
        subcommands: Sequence[object],
        fields: Mapping[str, object],
        *,
        executables: Sequence[str] | None = None,
    ) -> MatcherNode:
        names = tuple(executables or (executable,))
        if any(not isinstance(item, str) or not item for item in names):
            self.reject(node, "matcher_arguments_invalid", "executable names must be non-empty strings")
        config: dict[str, object] = {
            "executables": sorted(set(names)),
            "subcommands": list(subcommands),
        }
        mapping = {
            "required_flags": "required_flags",
            "forbidden_flags": "forbidden_flags",
            "allow_leading_options": "allow_leading_options",
            "leading_options_with_values": "leading_options_with_values",
            "global_options_with_values": "interspersed_options_with_values",
            "interspersed_options_with_values": "interspersed_options_with_values",
            "global_flags": "interspersed_flags",
            "interspersed_flags": "interspersed_flags",
            "options_with_values": "options_with_values",
            "inverse_flag_pairs": "inverse_flag_pairs",
            "required_option_values": "required_option_values",
            "required_flags_in_all_arguments": "required_flags_in_all_arguments",
            "fail_secure_unknown_options": "fail_secure_unknown_options",
        }
        for source_name, target_name in mapping.items():
            value = fields.get(source_name)
            if value in (None, (), frozenset(), False):
                continue
            if isinstance(value, frozenset):
                value = sorted(value)
            elif isinstance(value, tuple):
                value = [_json_value(item) for item in value]
            config[target_name] = value
        return MatcherNode("executable.v1", _json_value(config))

    def safe_variant_helper(
        self, node: ast.Call, name: str, positional: Sequence[object], keywords: Mapping[str, object]
    ) -> object:
        if name == "with_required_flag":
            if not positional or not isinstance(positional[0], MatcherNode):
                self.reject(node, "safe_variant_arguments_invalid", "with_required_flag requires a known matcher")
            matcher = positional[0]
            flag = positional[1] if len(positional) > 1 else keywords.get("flag")
            inverse = keywords.get("inverse_flag")
            if not isinstance(flag, str) or (inverse is not None and not isinstance(inverse, str)):
                self.reject(node, "safe_variant_arguments_invalid", "safe flag values must be literal strings")
            return self.clone_required_flag(node, matcher, flag, inverse)
        if name == "safe_flag_variant":
            fields = dict(keywords)
            if len(positional) > 1:
                self.reject(
                    node, "safe_variant_arguments_invalid", "safe_flag_variant accepts matcher plus keyword metadata"
                )
            matcher = positional[0] if positional else fields.pop("matcher", None)
            flag = fields.pop("flag", None)
            variant_id = fields.pop("variant_id", None)
            title = fields.pop("title", None)
            inverse = fields.pop("inverse_flag", None)
            if (
                fields
                or not isinstance(matcher, MatcherNode)
                or not all(isinstance(item, str) for item in (flag, variant_id, title))
                or (inverse is not None and not isinstance(inverse, str))
            ):
                self.reject(
                    node,
                    "safe_variant_arguments_invalid",
                    "safe_flag_variant requires matcher, variant_id, title, and flag literals",
                )
            return ConstructorValue(
                "safe_variant",
                {
                    "variant_id": variant_id,
                    "title": title,
                    "matcher": self.clone_required_flag(node, matcher, flag, inverse),
                },
            )
        fields = dict(keywords)
        matcher = positional[0] if positional else fields.pop("matcher", None)
        variant_id = fields.pop("variant_id", None)
        title = fields.pop("title", None)
        option = fields.pop("option", None)
        allowed = fields.pop("allowed_values", None)
        if (
            fields
            or not isinstance(matcher, MatcherNode)
            or not all(isinstance(item, str) for item in (variant_id, title, option))
        ):
            self.reject(node, "safe_variant_arguments_invalid", "safe_option_variant metadata must be literal")
        allowed_values = _as_strings(allowed, name="allowed_values")
        return ConstructorValue(
            "safe_variant",
            {
                "variant_id": variant_id,
                "title": title,
                "matcher": self.clone_option(node, matcher, option, allowed_values),
            },
        )

    def clone_required_flag(self, node: ast.Call, matcher: MatcherNode, flag: str, inverse: str | None) -> MatcherNode:
        if matcher.op != "any.v1" or any(
            child.op not in {"executable.v1", "executable-path-set.v1"} for child in matcher.matchers
        ):
            self.reject(
                node, "safe_variant_shape_invalid", "safe variants require an any matcher of executable children"
            )
        children = []
        for child in matcher.matchers:
            config = dict(child.config)
            required = set(config.get("required_flags", []))
            required.add(flag)
            config["required_flags"] = sorted(required)
            config["required_flags_in_all_arguments"] = True
            if inverse is not None:
                pairs = [tuple(pair) for pair in config.get("inverse_flag_pairs", [])]
                pairs.append((flag, inverse))
                config["inverse_flag_pairs"] = sorted(set(pairs))
            children.append(MatcherNode(child.op, config, child.matchers, child.producer, child.consumer))
        return MatcherNode("any.v1", {}, matchers=tuple(children))

    def clone_option(self, node: ast.Call, matcher: MatcherNode, option: str, allowed: Sequence[str]) -> MatcherNode:
        if matcher.op != "any.v1" or any(
            child.op not in {"executable.v1", "executable-path-set.v1"} for child in matcher.matchers
        ):
            self.reject(
                node, "safe_variant_shape_invalid", "safe variants require an any matcher of executable children"
            )
        children = []
        for child in matcher.matchers:
            config = dict(child.config)
            options = set(config.get("options_with_values", []))
            options.add(option)
            config["options_with_values"] = sorted(options)
            values = [tuple(item) for item in config.get("required_option_values", [])]
            values.append((option, list(allowed)))
            config["required_option_values"] = sorted(values)
            children.append(MatcherNode(child.op, config, child.matchers, child.producer, child.consumer))
        return MatcherNode("any.v1", {}, matchers=tuple(children))


def _validate_expanded_values(values: object, *, filename: str) -> None:
    """Bound repeated references before recursive discovery or JSON expansion.

    The evaluator constructs immutable graphs, not necessarily trees. Counting
    allocations alone does not bound a graph's expanded JSON representation.
    Deliberately charge each occurrence rather than deduplicating object IDs.
    """
    pending = [(values, 0)]
    items = 0
    string_bytes = 0

    def enqueue(children: Iterable[object], count: int, depth: int) -> None:
        if items + len(pending) + count > MAX_EVALUATED_ITEMS:
            raise ConversionRejected(
                Diagnostic(
                    "expanded_value_budget_exceeded",
                    "expanded static values exceed the item budget",
                    filename,
                )
            )
        pending.extend((child, depth) for child in children)

    while pending:
        value, depth = pending.pop()
        items += 1
        if items > MAX_EVALUATED_ITEMS or depth > MAX_AST_DEPTH:
            raise ConversionRejected(
                Diagnostic(
                    "expanded_value_budget_exceeded",
                    "expanded static values exceed the item or nesting budget",
                    filename,
                )
            )
        if isinstance(value, str):
            string_bytes += len(value.encode("utf-8"))
            if string_bytes > MAX_JSON_BYTES:
                raise ConversionRejected(
                    Diagnostic(
                        "expanded_value_budget_exceeded",
                        "expanded static strings exceed the output byte budget",
                        filename,
                    )
                )
        elif isinstance(value, MatcherNode):
            children = [value.config, *value.matchers]
            if value.producer is not None:
                children.append(value.producer)
            if value.consumer is not None:
                children.append(value.consumer)
            enqueue(children, len(children), depth + 1)
        elif isinstance(value, ConstructorValue):
            enqueue((value.fields,), 1, depth + 1)
        elif isinstance(value, dict):
            enqueue((child for pair in value.items() for child in pair), 2 * len(value), depth + 1)
        elif isinstance(value, (tuple, list, frozenset)):
            enqueue(value, len(value), depth + 1)


def convert_python_source(
    source: str,
    *,
    filename: str = "<source>",
    descriptor: Mapping[str, object] | None = None,
    extension_id: str | None = None,
) -> ConversionResult:
    """Convert one generated module using only the restricted AST grammar."""

    evaluator = _RestrictedEvaluator(source, filename)
    try:
        symbols = evaluator.evaluate()
        _validate_expanded_values((symbols, descriptor or {}), filename=filename)
    except ConversionRejected as error:
        return ConversionResult(None, (*evaluator.diagnostics, error.diagnostic), tuple(evaluator._bindings))
    except RecursionError:
        diagnostic = Diagnostic("ast_depth_exceeded", f"restricted evaluation exceeds {MAX_AST_DEPTH} levels", filename)
        return ConversionResult(None, (diagnostic,), tuple(evaluator._bindings))
    except (TypeError, ValueError, KeyError) as error:
        diagnostic = Diagnostic("structural_conversion_error", str(error), filename)
        return ConversionResult(None, (diagnostic,), tuple(evaluator._bindings))
    rules: list[dict[str, object]] = []
    extensions: list[dict[str, object]] = []
    seen_constructor_objects: set[int] = set()
    for value in symbols.values():
        for item in _walk_constructor_values(value):
            if not isinstance(item, ConstructorValue):
                continue
            # Generated modules commonly bind the same immutable rule tuple
            # under a public registry name and private aliases.  Preserve a
            # genuine duplicate constructor, while avoiding counting one
            # object reached through two reviewed aliases twice.
            if id(item) in seen_constructor_objects:
                continue
            seen_constructor_objects.add(id(item))
            if item.kind == "rule":
                rules.append(item.fields)
            elif item.kind == "extension":
                extensions.append(item.fields)
    if not rules:
        return ConversionResult(
            None,
            (Diagnostic("no_rules_found", "no statically constructed CommandSafetyRule was found", filename),),
            tuple(evaluator._bindings),
        )
    metadata = dict(descriptor or {})
    if extensions:
        metadata = {**extensions[0], **metadata}
    selected_id = extension_id or metadata.get("id") or metadata.get("extension_id")
    if not isinstance(selected_id, str):
        return ConversionResult(
            None,
            (
                Diagnostic(
                    "extension_identity_missing",
                    "extension ID must come from reviewed metadata or an explicit argument",
                    filename,
                ),
            ),
            tuple(evaluator._bindings),
        )
    if not _EXTENSION_ID.fullmatch(selected_id):
        return ConversionResult(
            None,
            (Diagnostic("extension_identity_invalid", f"invalid command extension ID: {selected_id!r}", filename),),
            tuple(evaluator._bindings),
        )

    converted_rules: list[dict[str, object]] = []
    permissions: list[dict[str, object]] = []
    seen_rules: set[str] = set()
    for raw in rules:
        rule_id = raw.get("rule_id")
        if not isinstance(rule_id, str) or not rule_id.startswith(f"{selected_id}."):
            return ConversionResult(
                None,
                (
                    Diagnostic(
                        "rule_identity_invalid",
                        f"rule ID {rule_id!r} is missing or is not owned by {selected_id}",
                        filename,
                    ),
                ),
                tuple(evaluator._bindings),
            )
        if rule_id in seen_rules:
            return ConversionResult(
                None,
                (Diagnostic("duplicate_rule_id", f"duplicate rule ID {rule_id!r}", filename),),
                tuple(evaluator._bindings),
            )
        seen_rules.add(rule_id)
        permission_id = raw.get("permission_id")
        if permission_id is None:
            permission_id = f"{selected_id}.permission.{rule_id.rsplit('.', 1)[-1]}"
        if not isinstance(permission_id, str):
            return ConversionResult(
                None,
                (Diagnostic("permission_identity_invalid", f"permission ID for {rule_id} must be a string", filename),),
                tuple(evaluator._bindings),
            )
        matcher = raw.get("matcher")
        if matcher is not None and not isinstance(matcher, MatcherNode):
            return ConversionResult(
                None,
                (
                    Diagnostic(
                        "matcher_conversion_invalid", f"matcher for {rule_id} is not a known native matcher", filename
                    ),
                ),
                tuple(evaluator._bindings),
            )
        variants = raw.get("safe_variants", ())
        variant_rows: list[dict[str, object]] = []
        for variant in _as_sequence(variants, name="safe_variants"):
            if not isinstance(variant, ConstructorValue) or variant.kind != "safe_variant":
                return ConversionResult(
                    None,
                    (
                        Diagnostic(
                            "safe_variant_conversion_invalid",
                            f"safe variant for {rule_id} is not structurally understood",
                            filename,
                        ),
                    ),
                    tuple(evaluator._bindings),
                )
            variant_rows.append(
                {
                    "variant_id": variant.fields.get("variant_id"),
                    "title": variant.fields.get("title"),
                    "matcher": _as_matcher(variant.fields.get("matcher"), name="safe variant matcher").to_source(),
                }
            )
        required_fields = {
            "rule_id": rule_id,
            "rule_version": raw.get("rule_version", "1.0.0"),
            "permission_id": permission_id,
            "title": raw.get("title", rule_id),
            "description": raw.get("description", raw.get("title", rule_id)),
            "severity": raw.get("severity", "high"),
            "risk_classes": raw.get(
                "risk_classes", metadata.get("riskClasses", metadata.get("risk_classes", ["destructive_shell"]))
            ),
            "action_classes": raw.get(
                "action_classes", metadata.get("actionClasses", metadata.get("action_classes", [rule_id]))
            ),
            "safer_alternatives": raw.get(
                "safer_alternatives",
                metadata.get(
                    "saferAlternatives", metadata.get("safer_alternatives", ["Review the command before continuing."])
                ),
            ),
            "default_mode": raw.get("default_mode", "review"),
            "safe_variants": variant_rows,
        }
        if matcher is not None:
            required_fields["matcher"] = matcher.to_source()
        elif raw.get("native_capability") is not None:
            required_fields["native_capability"] = raw["native_capability"]
        converted_rules.append(required_fields)
        example = raw.get("example_command") or _example_for_matcher(matcher)
        permissions.append(
            {
                "permission_id": permission_id,
                "implementation_version": str(raw.get("rule_version", "1.0.0")),
                "label": str(raw.get("title", rule_id)),
                "description": str(raw.get("description", raw.get("title", rule_id))),
                "risk_tier": str(raw.get("severity", "high")),
                "baseline_floor": "review",
                "default_enabled": True,
                "configurable": True,
                "typed_capabilities": [],
                "action_classes": _json_value(required_fields["action_classes"]),
                "dependencies": [],
                "conflicts": [],
                "implied_permissions": [],
                "introduced_version": str(metadata.get("version", "1.0.0")),
                "deprecated": False,
                "safer_guidance": _json_value(required_fields["safer_alternatives"]),
                "example_command": example or str(rule_id),
            }
        )

    def get(key: str, *alternatives: str, default: object) -> object:
        for candidate in (key, *alternatives):
            if candidate in metadata and metadata[candidate] is not None:
                return metadata[candidate]
        return default

    extension = {
        "extension_id": selected_id,
        "version": str(get("version", default="1.0.0")),
        "name": str(get("name", default=selected_id)),
        "description": str(get("description", default="Migrated command extension.")),
        "action_classes": _json_value(get("action_classes", "actionClasses", default=[])),
        "risk_classes": _json_value(get("risk_classes", "riskClasses", default=["destructive_shell"])),
        "safer_alternatives": _json_value(
            get("safer_alternatives", "saferAlternatives", default=["Review the command before continuing."])
        ),
        "reference_urls": _json_value(get("reference_urls", "referenceUrls", default=[])),
        "required": bool(get("required", default=False)),
        "source": str(get("source", default="local-admin")),
        "aliases": _json_value(get("aliases", default=[])),
        "dependencies": _json_value(get("dependencies", default=[])),
        "conflicts": _json_value(get("conflicts", default=[])),
        "ecosystem_ids": _json_value(get("ecosystem_ids", "ecosystemIds", default=[])),
        "executables": _json_value(get("executables", default=[])),
        "project_markers": _json_value(get("project_markers", "projectMarkers", default=[])),
        "permissions": permissions,
        "rules": converted_rules,
    }
    for optional in ("homepage", "license", "publisher", "delegated_protection"):
        if optional in metadata:
            extension[optional] = _json_value(metadata[optional])
    return ConversionResult({"schema": SOURCE_SCHEMA, "extension": extension}, (), tuple(evaluator._bindings))


def _walk_constructor_values(value: object) -> Iterable[object]:
    if isinstance(value, ConstructorValue):
        yield value
        for item in value.fields.values():
            yield from _walk_constructor_values(item)
    elif isinstance(value, MatcherNode):
        yield value
        for child in value.matchers:
            yield from _walk_constructor_values(child)
        if value.producer:
            yield from _walk_constructor_values(value.producer)
        if value.consumer:
            yield from _walk_constructor_values(value.consumer)
    elif isinstance(value, (tuple, list, frozenset)):
        for item in value:
            yield from _walk_constructor_values(item)
    elif isinstance(value, dict):
        for item in value.values():
            yield from _walk_constructor_values(item)


def _example_for_matcher(matcher: object) -> str | None:
    if not isinstance(matcher, MatcherNode):
        return None
    if matcher.op == "executable.v1":
        executables = matcher.config.get("executables")
        subcommands = matcher.config.get("subcommands", [])
        required = matcher.config.get("required_flags", [])
        if (
            isinstance(executables, list)
            and executables
            and isinstance(subcommands, list)
            and isinstance(required, list)
        ):
            return " ".join(
                [str(executables[0]), *(str(item) for item in subcommands), *(str(item) for item in required)]
            )
    if matcher.op == "arguments.v1":
        executables = matcher.config.get("executables")
        required = matcher.config.get("required_arguments")
        if isinstance(executables, list) and executables and isinstance(required, list):
            return " ".join([str(executables[0]), *(str(item) for item in required)])
    for child in matcher.matchers:
        example = _example_for_matcher(child)
        if example:
            return example
    return _example_for_matcher(matcher.producer) or _example_for_matcher(matcher.consumer)


def canonical_json(value: object) -> bytes:
    return (json.dumps(_json_value(value), ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def build_request(
    sources: Sequence[Mapping[str, object]],
    trust: Mapping[str, object],
    *,
    base: str | None = "packaged",
    mcp_sources: Sequence[Mapping[str, object]] = (),
) -> dict[str, object]:
    request: dict[str, object] = {
        "schema": BUILD_SCHEMA,
        "sources": list(sources),
        "mcp_sources": list(mcp_sources),
        "trust": dict(trust),
    }
    if base is not None:
        request["base"] = base
    return request


def validate_with_rust(request: Mapping[str, object], compiler: Path, *, timeout: float = 60.0) -> dict[str, object]:
    """Validate one build request through the native compiler's stdin API."""

    if compiler.is_symlink() or not compiler.is_file() or not compiler.stat().st_mode & 0o111:
        return {
            "ok": False,
            "status": "compiler_unavailable",
            "diagnostic": "compiler path is not an executable regular file",
        }
    try:
        result = subprocess.run(
            [str(compiler.resolve()), "compile"],
            input=canonical_json(request),
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        return {"ok": False, "status": "compiler_error", "diagnostic": str(error)}
    try:
        output = json.loads(result.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        output = {"stdout": result.stdout.decode("utf-8", errors="replace")[:4096]}
    if result.returncode:
        return {
            "ok": False,
            "status": "native_validation_failed",
            "exit_code": result.returncode,
            "output": output,
            "stderr": result.stderr.decode("utf-8", errors="replace")[:4096],
        }
    return {"ok": True, "status": "native_admitted", "output": output}


def _load_json(path: Path, *, max_bytes: int = MAX_JSON_BYTES) -> object:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > max_bytes:
        raise ValueError(f"bounded JSON input rejected: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def _existing_packaged_ids(repository: Path) -> set[str]:
    path = repository / "contracts/extensions/native-command-program.v1.json"
    try:
        value = _load_json(path)
    except (OSError, ValueError, json.JSONDecodeError):
        return set()
    return {
        row.get("extension_id")
        for row in value.get("extensions", [])
        if isinstance(row, dict) and isinstance(row.get("extension_id"), str)
    }


def _full_catalog_request(
    repository: Path,
    replacements: Mapping[str, Mapping[str, object]],
    trust: Mapping[str, object],
) -> dict[str, object]:
    """Build a complete local catalog request with candidate IDs replaced."""

    source_dir = repository / "contributions/command-sources"
    mcp_dir = repository / "contributions/mcp-servers"
    source_paths = sorted(path for path in source_dir.glob("*.json") if path.name != "migration-manifest.json")
    if not source_paths or len(source_paths) > MAX_OUTPUT_FILES:
        raise ValueError("canonical source catalog is unavailable or exceeds the bounded file count")
    sources: list[Mapping[str, object]] = []
    seen: set[str] = set()
    for path in source_paths:
        value = _load_json(path)
        if not isinstance(value, dict) or not isinstance(value.get("extension"), dict):
            raise ValueError(f"canonical command source is not an object: {path.name}")
        extension_id = value["extension"].get("extension_id")
        if not isinstance(extension_id, str) or extension_id in seen:
            raise ValueError(f"canonical command source has invalid or duplicate identity: {path.name}")
        seen.add(extension_id)
        sources.append(replacements.get(extension_id, value))
    mcp_sources: list[Mapping[str, object]] = []
    for path in sorted(mcp_dir.glob("*.json")):
        value = _load_json(path)
        if not isinstance(value, dict):
            raise ValueError(f"MCP source is not an object: {path.name}")
        mcp_sources.append(value)
    return build_request(sources, trust, base=None, mcp_sources=mcp_sources)


def _source_candidates(blob_root: Path, pr: Mapping[str, object], evidence: Mapping[str, object]) -> list[Path]:
    number = str(pr.get("number", ""))
    path = str(evidence.get("file", ""))
    blob_sha = str(evidence.get("blob_sha", ""))
    return [
        blob_root / number / path,
        blob_root / path,
        blob_root / number / f"{blob_sha}.py",
        blob_root / f"{blob_sha}.py",
        blob_root / f"{blob_sha}",
    ]


def _read_blob(blob_root: Path, pr: Mapping[str, object], evidence: Mapping[str, object]) -> tuple[str, str] | None:
    for candidate in _source_candidates(blob_root, pr, evidence):
        if candidate.is_symlink() or not candidate.is_file() or candidate.stat().st_size > MAX_SOURCE_BYTES:
            continue
        try:
            raw = candidate.read_bytes()
            content = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        expected = evidence.get("blob_sha")
        if isinstance(expected, str) and _SHA1.fullmatch(expected):
            # Blob IDs are Git's SHA-1 over the blob header and bytes.
            actual = hashlib.sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest()
            if actual != expected:
                continue
        return str(candidate), content
    return None


def _safe_write(path: Path, data: bytes) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.is_symlink() or not path.is_file() or path.read_bytes() != data:
            raise ValueError(f"modified proposed artifact refused: {path}")
        return "unchanged"
    with path.open("xb") as stream:
        stream.write(data)
    return "created"


def _load_head_rows(path: Path) -> dict[str, str]:
    """Read a bounded JSONL head snapshot without treating it as live state."""

    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_JSON_BYTES:
        raise ValueError(f"bounded head snapshot rejected: {path}")
    heads: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if (
            not isinstance(row, dict)
            or not isinstance(row.get("number"), (str, int))
            or not isinstance(row.get("head"), str)
        ):
            raise ValueError(f"invalid head snapshot row in {path}")
        heads[str(row["number"])] = row["head"]
    return heads


def convert_backlog(
    inventory_path: Path,
    blob_root: Path,
    output: Path,
    *,
    repository: Path,
    compiler: Path | None = None,
    trust_path: Path | None = None,
    heads_path: Path | None = None,
    current_heads_path: Path | None = None,
) -> dict[str, object]:
    inventory = _load_json(inventory_path)
    if not isinstance(inventory, dict) or inventory.get("schema") != INVENTORY_SCHEMA:
        raise ValueError("unsupported backlog inventory schema")
    trust = _load_json(trust_path or repository / "contracts/extensions/trust-class-map.v1.json")
    if not isinstance(trust, dict):
        raise ValueError("trust map must be an object")
    pinned_heads: dict[str, str] = {}
    if heads_path and heads_path.is_file():
        pinned_heads = _load_head_rows(heads_path)
    current_heads = _load_head_rows(current_heads_path) if current_heads_path else {}
    existing_ids = _existing_packaged_ids(repository)
    reports: list[dict[str, object]] = []
    for pr in inventory.get("prs", []):
        if not isinstance(pr, dict) or pr.get("classification") != "declarative-compatible-candidate":
            continue
        provenance = {key: pr.get(key) for key in ("repository", "number", "author", "branch", "base", "head", "title")}
        report: dict[str, object] = {
            "schema": "guard.command-source-backlog-conversion.v1",
            **provenance,
            "status": "rejected",
            "sources": [],
            "diagnostics": [],
        }
        number = str(pr.get("number"))
        pr_dir = output / f"pr-{number}"

        def write_diagnostic_artifact(
            current_report: dict[str, object],
            current_pr_dir: Path,
            current_provenance: dict[str, object],
        ) -> None:
            current_report["artifact"] = str(current_pr_dir / "diagnostic.json")
            artifact = {
                "schema": "guard.command-source-backlog-diagnostic.v1",
                "provenance": current_provenance,
                "status": current_report["status"],
                "diagnostics": current_report["diagnostics"],
                "sources": [
                    {
                        "path": item.get("path"),
                        "blob_sha": item.get("blob_sha"),
                        "extension_id": item.get("extension_id"),
                    }
                    for item in current_report["sources"]
                ],
            }
            _safe_write(current_pr_dir / "diagnostic.json", canonical_json(artifact))

        if pinned_heads.get(number) and pinned_heads[number] != pr.get("head"):
            report["status"] = "stale-pinned-head"
            report["diagnostics"] = [
                {
                    "code": "head_changed",
                    "message": "open-pr-heads.jsonl does not match the inventory head",
                    "inventory_head": pr.get("head"),
                    "current_pinned_head": pinned_heads[number],
                }
            ]
            write_diagnostic_artifact(report, pr_dir, provenance)
            reports.append(report)
            continue
        if (
            current_heads.get(number)
            and _SHA1.fullmatch(current_heads[number])
            and current_heads[number] != pr.get("head")
        ):
            report["status"] = "stale-remote-head"
            report["diagnostics"] = [
                {
                    "code": "remote_head_changed",
                    "message": "the read-only current remote head differs from the pinned inventory head",
                    "inventory_head": pr.get("head"),
                    "current_remote_head": current_heads[number],
                }
            ]
            write_diagnostic_artifact(report, pr_dir, provenance)
            reports.append(report)
            continue
        if current_heads_path and (number not in current_heads or not _SHA1.fullmatch(current_heads.get(number, ""))):
            report["status"] = "remote-head-unavailable"
            report["diagnostics"] = [
                {
                    "code": "remote_head_unavailable",
                    "message": "the supplied read-only current remote head snapshot has no valid "
                    "SHA-1 for this candidate",
                    "inventory_head": pr.get("head"),
                    "current_remote_head": current_heads.get(number),
                }
            ]
            write_diagnostic_artifact(report, pr_dir, provenance)
            reports.append(report)
            continue
        evidence_rows = [row for row in pr.get("structural_evidence", []) if isinstance(row, dict)]
        for evidence in evidence_rows:
            loaded = _read_blob(blob_root, pr, evidence)
            if loaded is None:
                report["diagnostics"].append(
                    {
                        "code": "pinned_blob_unavailable",
                        "message": "the pinned blob was not found or failed its digest check",
                        "file": evidence.get("file"),
                        "blob_sha": evidence.get("blob_sha"),
                    }
                )
                continue
            filename, source_text = loaded
            source_path = str(evidence.get("file") or filename)
            result = convert_python_source(source_text, filename=source_path)
            if result.source is None:
                report["diagnostics"].extend(item.as_dict() for item in result.diagnostics)
                continue
            source_id = result.source["extension"]["extension_id"]
            descriptor = None
            if isinstance(source_id, str):
                descriptor_path = repository / "contributions/extensions" / f"{source_id}.json"
                if descriptor_path.is_file():
                    try:
                        descriptor = _load_json(descriptor_path)
                    except (OSError, ValueError, json.JSONDecodeError):
                        descriptor = None
                if isinstance(descriptor, dict):
                    reprocessed = convert_python_source(
                        source_text, filename=source_path, descriptor=descriptor, extension_id=source_id
                    )
                    if reprocessed.source is None:
                        report["diagnostics"].extend(item.as_dict() for item in reprocessed.diagnostics)
                        continue
                    result = reprocessed
            source_bytes = canonical_json(result.source)
            source_record = {
                "path": source_path,
                "blob_sha": evidence.get("blob_sha"),
                "blob_artifact": filename,
                "source_sha256": sha256_bytes(source_bytes),
                "extension_id": source_id,
                "source": result.source,
            }
            report["sources"].append(source_record)
        if report["diagnostics"] or not report["sources"]:
            write_diagnostic_artifact(report, pr_dir, provenance)
            reports.append(report)
            continue
        ids = {item["extension_id"] for item in report["sources"]}
        request: dict[str, object] | None = None
        if ids & existing_ids:
            replacements = {item["extension_id"]: item["source"] for item in report["sources"]}
            try:
                request = _full_catalog_request(repository, replacements, trust)
            except (OSError, ValueError, json.JSONDecodeError) as error:
                report["status"] = "needs-full-catalog"
                report["validation"] = {
                    "status": "full_catalog_unavailable",
                    "reason": str(error),
                    "replacement_ids": sorted(ids & existing_ids),
                }
            else:
                if compiler is None:
                    report["status"] = "converted-unvalidated"
                    report["validation"] = {
                        "status": "compiler_not_requested",
                        "mode": "full-catalog-replacement",
                        "replacement_ids": sorted(ids & existing_ids),
                    }
                else:
                    report["validation"] = validate_with_rust(request, compiler)
                    report["validation"]["mode"] = "full-catalog-replacement"
                    report["validation"]["replacement_ids"] = sorted(ids & existing_ids)
                    report["status"] = "converted" if report["validation"].get("ok") else "native-validation-failed"
        elif compiler is None:
            report["status"] = "converted-unvalidated"
            report["validation"] = {"status": "compiler_not_requested"}
        else:
            request = build_request([item["source"] for item in report["sources"]], trust)
            report["validation"] = validate_with_rust(request, compiler)
            report["status"] = "converted" if report["validation"].get("ok") else "native-validation-failed"
        if report["status"] in {"converted", "converted-unvalidated", "needs-full-catalog"}:
            artifact = {
                "schema": "guard.command-source-proposed-patch.v1",
                "provenance": provenance,
                "status": report["status"],
                "files": {
                    f"contributions/command-sources/{item['extension_id']}.json": item["source"]
                    for item in report["sources"]
                },
            }
            report["artifact"] = str(pr_dir / "proposed-patch.json")
            _safe_write(pr_dir / "proposed-patch.json", canonical_json(artifact))
            for item in report["sources"]:
                _safe_write(
                    pr_dir / f"contributions/command-sources/{item['extension_id']}.json",
                    canonical_json(item["source"]),
                )
            if request is not None:
                _safe_write(pr_dir / "native-build-request.json", canonical_json(request))
                _safe_write(pr_dir / "native-validation.json", canonical_json(report["validation"]))
        else:
            write_diagnostic_artifact(report, pr_dir, provenance)
        reports.append(report)
    result = {
        "schema": "guard.command-source-backlog-report.v1",
        "inventory": str(inventory_path),
        "candidate_count": sum(
            1
            for pr in inventory.get("prs", [])
            if isinstance(pr, dict) and pr.get("classification") == "declarative-compatible-candidate"
        ),
        "reports": reports,
    }
    _safe_write(output / "backlog-conversion-report.json", canonical_json(result))
    return result


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--blobs", type=Path, required=True, help="already fetched, digest-pinned source blobs")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument("--compiler", type=Path)
    parser.add_argument("--trust", type=Path)
    parser.add_argument("--heads", type=Path)
    parser.add_argument("--current-heads", type=Path, help="read-only current remote head snapshot (JSONL)")
    args = parser.parse_args(argv)
    try:
        result = convert_backlog(
            args.inventory,
            args.blobs,
            args.output,
            repository=args.repository,
            compiler=args.compiler,
            trust_path=args.trust,
            heads_path=args.heads,
            current_heads_path=args.current_heads,
        )
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(json.dumps({"ok": False, "code": "backlog_conversion_failed", "diagnostic": str(error)}), file=sys.stderr)
        return 2
    counts: dict[str, int] = {}
    for report in result["reports"]:
        counts[report["status"]] = counts.get(report["status"], 0) + 1
    print(json.dumps({"ok": True, "candidate_count": result["candidate_count"], "statuses": counts}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

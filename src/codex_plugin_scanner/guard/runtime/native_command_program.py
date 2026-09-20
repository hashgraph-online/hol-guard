"""Trusted build compiler for versioned native command matcher programs.

This module never imports a module named by a contribution or evaluates a
matcher. Its only executable inputs are the explicitly reviewed, package-owned
dataclass types below. Program compilation and native execution are separate
coverage claims; the generated manifest describes the former only.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from dataclasses import fields, is_dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

from .command_matcher_contracts import canonical_contract_digest

if TYPE_CHECKING:
    from .command_extensions import CommandSafetyExtensionRegistry

PROGRAM_SCHEMA: Final = "guard.native-command-program.v1"
COMPILER_VERSION: Final = 1
SEMANTIC_PROFILE: Final = "cpython-3.12-ucd15"
PROGRAM_DOMAIN: Final = b"hol-guard.native-command-program.v1\0"
NODE_DOMAIN: Final = b"hol-guard.native-command-matcher.v1\0"
MAX_PROGRAM_BYTES: Final = 4 * 1024 * 1024
MAX_RULES: Final = 1_024
MAX_NODES: Final = 16_384
MAX_NODE_DEPTH: Final = 32
MAX_CONFIG_ITEMS: Final = 4_096
MAX_CONFIG_STRING_BYTES: Final = 4_096
MAX_SAFE_VARIANTS: Final = 64
MAX_CONFIG_VALUES: Final = 1_000_000


class NativeCommandProgramError(ValueError):
    """A build input has no reviewed, bounded native representation."""


def canonical_program_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def _digest(domain: bytes, value: object) -> str:
    return hashlib.sha256(domain + canonical_program_bytes(value)).hexdigest()


def _reviewed_types() -> dict[type[object], str]:
    # Keep this an explicit import/identity allowlist. Matching a class name,
    # a module prefix, or a subclass would admit unreviewed Python semantics.
    from .command_database_matchers import ArgumentCommandMatcher, CommandSequenceMatcher, LeadingSubcommandMatcher
    from .command_framework_extensions import PhpArtisanScriptMatcher
    from .command_operand_matchers import (
        OperandGatedFlagMatcher,
        TrailingOperandHostTargetMatcher,
        TrailingOperandPrefixMatcher,
        TrailingOperandRemoteAliasMatcher,
    )
    from .command_path_set_matcher import ExecutablePathSetMatcher
    from .command_platform_extensions import _ZeroOperandFlagMatcher
    from .command_repo2nb_extensions import Repo2nbUnresolvedExpansionMatcher
    from .command_reviewed_literal_matcher import ReviewedLiteralCommandMatcher
    from .command_rules import AllMatcher, AnyMatcher, ArgumentMatcher, ExecutableMatcher, PipelineMatcher
    from .command_search_messaging_extensions import CurlElasticsearchDeleteMatcher
    from .command_structured_matchers import (
        EnvironmentNameMatcher,
        LeadingOperandCountMatcher,
        OptionValueKeyMatcher,
        SubcommandOperandPrefixMatcher,
    )

    return {
        ExecutableMatcher: "executable.v1",
        ExecutablePathSetMatcher: "executable-path-set.v1",
        ArgumentMatcher: "arguments.v1",
        AnyMatcher: "any.v1",
        AllMatcher: "all.v1",
        PipelineMatcher: "pipeline.v1",
        ArgumentCommandMatcher: "argument-command.v1",
        CommandSequenceMatcher: "command-sequence.v1",
        LeadingSubcommandMatcher: "leading-subcommand.v1",
        LeadingOperandCountMatcher: "leading-operand-count.v1",
        SubcommandOperandPrefixMatcher: "subcommand-operand-prefix.v1",
        OptionValueKeyMatcher: "option-value-key.v1",
        EnvironmentNameMatcher: "environment-name.v1",
        OperandGatedFlagMatcher: "operand-gated-flags.v1",
        TrailingOperandPrefixMatcher: "trailing-operand-prefix.v1",
        TrailingOperandHostTargetMatcher: "trailing-operand-host-target.v1",
        TrailingOperandRemoteAliasMatcher: "trailing-operand-remote-alias.v1",
        _ZeroOperandFlagMatcher: "zero-operand-flags.v1",
        PhpArtisanScriptMatcher: "php-artisan-script.v1",
        CurlElasticsearchDeleteMatcher: "curl-elasticsearch-delete.v1",
        Repo2nbUnresolvedExpansionMatcher: "repo2nb-expansion.v1",
        ReviewedLiteralCommandMatcher: "reviewed-literal.v1",
    }


def _config_value(value: object, *, budget: list[int], depth: int = 0) -> object:
    budget[0] -= 1
    if budget[0] < 0:
        raise NativeCommandProgramError("native_command_config_work_exceeded")
    if depth > MAX_NODE_DEPTH:
        raise NativeCommandProgramError("native_command_config_depth_exceeded")
    if value is None or type(value) is bool:
        return value
    if type(value) is int and -(2**63) <= value < 2**63:
        return value
    if type(value) is str:
        if len(value.encode("utf-8")) > MAX_CONFIG_STRING_BYTES:
            raise NativeCommandProgramError("native_command_config_string_exceeded")
        return value
    if type(value) in {tuple, list, set, frozenset}:
        collection = cast("tuple[object, ...] | list[object] | set[object] | frozenset[object]", value)
        if len(collection) > MAX_CONFIG_ITEMS:
            raise NativeCommandProgramError("native_command_config_items_exceeded")
        items = [_config_value(item, budget=budget, depth=depth + 1) for item in collection]
        return sorted(items, key=canonical_program_bytes) if type(value) in {set, frozenset} else items
    raise NativeCommandProgramError("native_command_config_type_unsupported")


class _Compiler:
    def __init__(self) -> None:
        self.types = _reviewed_types()
        self.nodes: dict[str, dict[str, object]] = {}
        self.family_counts: Counter[str] = Counter()
        self.config_budget = [MAX_CONFIG_VALUES]
        self.node_bytes = 0

    def node(self, matcher: object, *, depth: int = 0) -> str:
        if depth > MAX_NODE_DEPTH:
            raise NativeCommandProgramError("native_command_matcher_depth_exceeded")
        operation = self.types.get(type(matcher))
        if operation is None or not is_dataclass(matcher) or isinstance(matcher, type):
            raise NativeCommandProgramError("native_command_matcher_type_unsupported")
        config: dict[str, object] = {}
        children: dict[str, object] = {}
        for field in fields(matcher):
            if not field.init:
                # Cached path sorting is derived from the complete `paths`
                # field. It is not an independent semantic input to the IR.
                continue
            value = getattr(matcher, field.name)
            if field.name in {"producer", "consumer"}:
                children[field.name] = self.node(value, depth=depth + 1)
            elif field.name == "matchers":
                if type(value) is not tuple or not 0 < len(value) <= MAX_CONFIG_ITEMS:
                    raise NativeCommandProgramError("native_command_matcher_children_invalid")
                children[field.name] = [self.node(item, depth=depth + 1) for item in value]
            else:
                config[field.name] = _config_value(value, budget=self.config_budget)
        node: dict[str, object] = {"op": operation, "config": config, "children": children}
        node_id = _digest(NODE_DOMAIN, node)
        existing = self.nodes.get(node_id)
        if existing is not None and existing != node:
            raise NativeCommandProgramError("native_command_matcher_digest_conflict")
        if existing is None and len(self.nodes) >= MAX_NODES:
            raise NativeCommandProgramError("native_command_matcher_node_limit_exceeded")
        if existing is None:
            self.node_bytes += len(canonical_program_bytes(node)) + len(node_id)
            if self.node_bytes > MAX_PROGRAM_BYTES:
                raise NativeCommandProgramError("native_command_program_bytes_exceeded")
        self.nodes[node_id] = node
        self.family_counts[type(matcher).__name__] += 1
        return node_id


def _semantic_sources_digest() -> str:
    """Bind the trusted authoring semantics as well as their configuration.

    A Python matcher implementation change cannot retain the same program
    identity merely because its dataclass fields stayed identical. Runtime
    consumers never read or execute these source files.
    """
    root = Path(__file__).resolve().parent
    paths = sorted(root.glob("command_*.py"))
    paths.extend([root / "executable_flag_contract.py", Path(__file__).resolve()])
    if len(paths) > 256:
        raise NativeCommandProgramError("native_command_source_count_exceeded")
    records: list[tuple[str, str]] = []
    for path in paths:
        with path.open("rb") as source:
            content = source.read(512 * 1024 + 1)
        if len(content) > 512 * 1024:
            raise NativeCommandProgramError("native_command_source_bytes_exceeded")
        # Git may materialize text sources with CRLF on Windows. Python source
        # semantics are newline-insensitive here, so bind the canonical LF bytes
        # rather than a platform checkout representation.
        canonical_source = content.replace(b"\r\n", b"\n")
        records.append((path.name, hashlib.sha256(canonical_source).hexdigest()))
    return _digest(b"hol-guard.native-command-authoring-semantics.v1\0", records)


def compile_native_command_program(registry: CommandSafetyExtensionRegistry) -> dict[str, object]:
    """Compile reviewed definitions without invoking their match methods.

    Unknown types reject the build. Known operations describe a versioned
    semantic contract; this function does not claim the resident implements
    them. Runtime capability and coverage checks belong to program admission.
    """
    from .command_extensions import CommandSafetyExtensionRegistry
    from .command_rules import matcher_index_hints
    from .extension_trust import catalog_trust_fields
    from .mcp_server_contribution import catalog_mcp_fields

    if type(registry) is not CommandSafetyExtensionRegistry:
        raise NativeCommandProgramError("native_command_registry_type_unsupported")
    compiler = _Compiler()
    extensions: list[dict[str, object]] = []
    rules: list[dict[str, object]] = []
    coverage: list[dict[str, object]] = []
    trust_records: list[dict[str, object]] = []
    for extension in registry.extensions:
        trust = catalog_trust_fields(extension.extension_id, required=extension.required)
        trust_record = {
            "extension_id": extension.extension_id,
            "trust_class": trust["trust_class"],
            "activation": trust["activation"],
            "publisher": trust["publisher"],
        }
        trust_records.append(trust_record)
        mcp = catalog_mcp_fields(extension.extension_id)
        extensions.append(
            {
                **trust_record,
                "version": extension.version,
                "source": extension.source,
                "required": extension.required,
                "dependencies": list(extension.dependencies),
                "executables": list(extension.executables),
                "delegated_protection": extension.delegated_protection,
                "mcp": mcp,
                "permissions": [
                    {
                        "permission_id": permission.permission_id,
                        "baseline_floor": permission.baseline_floor,
                        "default_enabled": permission.default_enabled,
                        "configurable": permission.configurable,
                        "dependencies": list(permission.dependencies),
                        "implied_permissions": list(permission.implied_permissions),
                        "rule_ids": list(permission.rule_ids),
                    }
                    for permission in extension.permissions
                ],
            }
        )
        for rule in extension.rules:
            if len(rules) >= MAX_RULES or len(rule.safe_variants) > MAX_SAFE_VARIANTS:
                raise NativeCommandProgramError("native_command_rule_limit_exceeded")
            permission = registry.permission_for_rule_id(rule.rule_id)
            if permission is None:
                raise NativeCommandProgramError("native_command_permission_missing")
            matcher = compiler.node(rule.matcher) if rule.matcher is not None else None
            hints = matcher_index_hints(rule.matcher) if rule.matcher is not None else None
            variants = [
                {"variant_id": variant.variant_id, "matcher": compiler.node(variant.matcher)}
                for variant in rule.safe_variants
            ]
            rules.append(
                {
                    "rule_id": rule.rule_id,
                    "rule_version": rule.rule_version,
                    "extension_id": extension.extension_id,
                    "permission_id": permission.permission_id,
                    "baseline_floor": permission.baseline_floor,
                    "configurable": permission.configurable,
                    "default_mode": rule.default_mode,
                    "severity": rule.severity,
                    "risk_classes": list(rule.risk_classes),
                    "action_classes": list(rule.action_classes),
                    "matcher": matcher,
                    "candidate_executables": sorted(hints.executables) if hints is not None else [],
                    "candidate_keywords": sorted(hints.keywords) if hints is not None else [],
                    "candidate_unindexed": hints is None
                    or not hints.complete
                    or not (hints.executables or hints.keywords),
                    "safe_variants": variants,
                }
            )
            coverage.append(
                {
                    "rule_id": rule.rule_id,
                    "matcher_contract_digest": canonical_contract_digest(rule.matcher),
                    "translation": "declarative-ir" if matcher is not None else "compatibility-only",
                    "native_execution": "requires-runtime-admission",
                    "safe_variants": [
                        {
                            "variant_id": variant.variant_id,
                            "matcher_contract_digest": canonical_contract_digest(variant.matcher),
                        }
                        for variant in rule.safe_variants
                    ],
                }
            )
    program: dict[str, object] = {
        "schema": PROGRAM_SCHEMA,
        "compiler_version": COMPILER_VERSION,
        "semantic_profile": SEMANTIC_PROFILE,
        "authoring_semantics_digest": _semantic_sources_digest(),
        "catalog_digest": registry.catalog_digest,
        "trust_digest": _digest(b"hol-guard.native-command-trust.v1\0", trust_records),
        "extensions": extensions,
        "rules": rules,
        "nodes": compiler.nodes,
        "coverage": coverage,
        "matcher_families": dict(sorted(compiler.family_counts.items())),
    }
    program["program_digest"] = _digest(PROGRAM_DOMAIN, program)
    if len(canonical_program_bytes(program)) > MAX_PROGRAM_BYTES:
        raise NativeCommandProgramError("native_command_program_bytes_exceeded")
    return program

"""Trusted compilation is deterministic, complete, bounded, and non-executing."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.runtime import native_command_program as compiler
from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    CommandSafetyExtensionRegistry,
)
from codex_plugin_scanner.guard.runtime.command_path_set_matcher import ExecutablePathSetMatcher
from codex_plugin_scanner.guard.runtime.command_rules import AnyMatcher, ExecutableMatcher


@pytest.fixture(scope="module")
def program() -> dict[str, object]:
    return compiler.compile_native_command_program(BUILT_IN_COMMAND_EXTENSION_REGISTRY)


def test_checked_in_native_program_matches_current_authoring_semantics(program: dict[str, object]) -> None:
    artifact = Path(__file__).parents[1] / "contracts/extensions/native-command-program.v1.json"
    checked_in = json.loads(artifact.read_text(encoding="utf-8"))
    assert compiler.canonical_program_bytes(checked_in) == compiler.canonical_program_bytes(program)


def test_full_catalog_program_is_deterministic_and_covers_every_owned_variant(program: dict[str, object]) -> None:
    other = compiler.compile_native_command_program(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    assert compiler.canonical_program_bytes(other) == compiler.canonical_program_bytes(program)
    payload = dict(program)
    digest = payload.pop("program_digest")
    assert hashlib.sha256(compiler.PROGRAM_DOMAIN + compiler.canonical_program_bytes(payload)).hexdigest() == digest
    assert len(compiler.canonical_program_bytes(program)) <= compiler.MAX_PROGRAM_BYTES
    registry_rules = [rule for extension in BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions for rule in extension.rules]
    coverage = cast("list[dict[str, object]]", program["coverage"])
    rules = cast("list[dict[str, object]]", program["rules"])
    assert [item["rule_id"] for item in rules] == [rule.rule_id for rule in registry_rules]
    assert [item["rule_id"] for item in coverage] == [rule.rule_id for rule in registry_rules]
    for source, emitted, manifest in zip(registry_rules, rules, coverage, strict=True):
        variants = cast("list[dict[str, object]]", emitted["safe_variants"])
        covered_variants = cast("list[dict[str, object]]", manifest["safe_variants"])
        assert [item["variant_id"] for item in variants] == [item.variant_id for item in source.safe_variants]
        assert [item["variant_id"] for item in covered_variants] == [item.variant_id for item in source.safe_variants]
        assert manifest["native_execution"] == "requires-runtime-admission"
    nodes = cast("dict[str, dict[str, object]]", program["nodes"])
    for node_id, node in nodes.items():
        assert hashlib.sha256(compiler.NODE_DOMAIN + compiler.canonical_program_bytes(node)).hexdigest() == node_id
        children = cast("dict[str, object]", node["children"])
        for value in children.values():
            references = value if isinstance(value, list) else [value]
            assert all(reference in nodes for reference in references)


def test_compile_never_invokes_matcher_implementations(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden_match(*_args: object) -> None:
        pytest.fail("offline compilation invoked a matcher")

    for matcher_type in compiler._reviewed_types():
        monkeypatch.setattr(matcher_type, "match", forbidden_match)
    program = compiler.compile_native_command_program(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    assert program["schema"] == compiler.PROGRAM_SCHEMA


def test_compiler_rejects_unreviewed_dataclass_even_with_matching_name() -> None:
    @dataclass(frozen=True)
    class ExecutableMatcher:
        executables: frozenset[str]

    with pytest.raises(compiler.NativeCommandProgramError, match="matcher_type_unsupported"):
        compiler._Compiler().node(ExecutableMatcher(frozenset({"ollama"})))


def test_compiler_preserves_full_executable_and_path_set_contracts() -> None:
    matcher = ExecutableMatcher(
        executables=frozenset({"ollama", "ollama.exe"}),
        subcommands=("push",),
        required_flags=frozenset({"--help"}),
        forbidden_flags=frozenset({"--unsafe"}),
        allow_leading_options=True,
        leading_options_with_values=frozenset({"--config"}),
        interspersed_options_with_values=frozenset({"--server"}),
        interspersed_flags=frozenset({"--verbose"}),
        options_with_values=frozenset({"--format"}),
        inverse_flag_pairs=frozenset({("--read-only", "--no-read-only")}),
        required_option_values=(("--format", frozenset({"json", "yaml"})),),
        required_flags_in_all_arguments=True,
        fail_secure_unknown_options=True,
    )
    state = compiler._Compiler()
    node = state.nodes[state.node(matcher)]
    config = cast("dict[str, object]", node["config"])
    assert len(config) == 13
    assert config["required_option_values"] == [["--format", ["json", "yaml"]]]
    assert config["inverse_flag_pairs"] == [["--read-only", "--no-read-only"]]
    assert config["required_flags_in_all_arguments"] is True
    assert config["fail_secure_unknown_options"] is True
    path_set = ExecutablePathSetMatcher(executables=frozenset({"cloud"}), paths=frozenset({("a",), ("a", "b")}))
    config = cast("dict[str, object]", state.nodes[state.node(path_set)]["config"])
    assert config["paths"] == [["a", "b"], ["a"]]
    assert not any(key.startswith("_") for key in config)


def test_compiler_rejects_nested_work_and_unbounded_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    matcher = ExecutableMatcher(executables=frozenset({"ollama"}))
    nested = AnyMatcher((matcher,))
    for _ in range(compiler.MAX_NODE_DEPTH + 1):
        nested = AnyMatcher((nested,))
    with pytest.raises(compiler.NativeCommandProgramError, match="matcher_depth_exceeded"):
        compiler._Compiler().node(nested)
    with pytest.raises(compiler.NativeCommandProgramError, match="config_string_exceeded"):
        compiler._Compiler().node(
            replace(matcher, executables=frozenset({"x" * (compiler.MAX_CONFIG_STRING_BYTES + 1)}))
        )
    monkeypatch.setattr(compiler, "MAX_CONFIG_VALUES", 2)
    with pytest.raises(compiler.NativeCommandProgramError, match="config_work_exceeded"):
        compiler._Compiler().node(matcher)


def test_compiler_rejects_node_and_program_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    matcher = ExecutableMatcher(executables=frozenset({"ollama"}))
    monkeypatch.setattr(compiler, "MAX_NODES", 0)
    with pytest.raises(compiler.NativeCommandProgramError, match="node_limit_exceeded"):
        compiler._Compiler().node(matcher)
    monkeypatch.setattr(compiler, "MAX_NODES", 10)
    monkeypatch.setattr(compiler, "MAX_PROGRAM_BYTES", 16)
    with pytest.raises(compiler.NativeCommandProgramError, match="program_bytes_exceeded"):
        compiler._Compiler().node(matcher)


def test_reordered_catalog_inputs_keep_program_identity() -> None:
    extensions = BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions
    first = compiler.compile_native_command_program(CommandSafetyExtensionRegistry(extensions[:2]))
    second = compiler.compile_native_command_program(CommandSafetyExtensionRegistry(tuple(reversed(extensions[:2]))))
    assert first == second

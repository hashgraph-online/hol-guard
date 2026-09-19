"""Native command associations remain complete, immutable and authenticated."""

from __future__ import annotations

import copy
import json
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.native_policy_authority_compile import compile_native_policy_authority
from codex_plugin_scanner.guard.native_policy_authority_contract import (
    NATIVE_SCOPED_AUTHORITY_FEATURE,
    NativePolicyAuthorityCapabilities,
)
from codex_plugin_scanner.guard.native_policy_authority_decode import native_policy_authority_from_mapping
from codex_plugin_scanner.guard.native_policy_authority_expressions import (
    NATIVE_COMMAND_EXPRESSIONS_FEATURE,
    NativeScopedCommandExpression,
)
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError
from codex_plugin_scanner.guard.native_policy_snapshot_v4 import (
    build_policy_snapshot_v4,
    policy_digest_v4,
    verify_snapshot_v4,
)


def expression(**changes: object) -> dict[str, object]:
    return {
        "combinator": "all",
        "conditions": [
            {
                "field": "command",
                "operator": "startsWith",
                "value": "printf",
                "caseSensitive": True,
                **changes,
            }
        ],
    }


def encoded(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def row(**changes: object) -> dict[str, object]:
    return {
        "decision_id": 4,
        "harness": "codex",
        "scope": "workspace",
        "artifact_id": "synthetic-artifact",
        "artifact_hash": "sha256:" + "a" * 64,
        "workspace": "synthetic-workspace",
        "publisher": None,
        "action": "block",
        "source": "policy-bundle-canonical",
        "updated_at": "2026-09-17T00:00:00Z",
        "expires_at": "2026-09-18T00:00:00Z",
        "exact_command_sha256": "b" * 64,
        "_command_expression_json": encoded(expression()),
        **changes,
    }


def capabilities(*, expressions: bool = True) -> NativePolicyAuthorityCapabilities:
    features = {NATIVE_SCOPED_AUTHORITY_FEATURE}
    if expressions:
        features.add(NATIVE_COMMAND_EXPRESSIONS_FEATURE)
    return NativePolicyAuthorityCapabilities(4, frozenset(features))


def test_actual_compiler_retains_expression_and_all_selectors() -> None:
    source = row()
    draft = compile_native_policy_authority([source])
    wire = draft.for_snapshot(capabilities())
    rows = wire["rows"]
    assert isinstance(rows, list) and len(rows) == 1
    actual = rows[0]
    assert isinstance(actual, dict)
    for key in ("harness", "scope", "action", "artifact_id", "artifact_hash", "workspace", "exact_command_sha256"):
        assert actual[key] == source[key]
    assert actual["expires_at_ms"] == 1789689600000
    assert wire["command_expressions"] == [{"decision_id": 4, "expression": expression()}]
    assert native_policy_authority_from_mapping(wire) == draft
    with pytest.raises(NativePolicySnapshotError, match="capability_unsupported"):
        draft.for_snapshot(capabilities(expressions=False))


def test_legacy_bytes_unchanged_and_expression_inputs_detached() -> None:
    source = row()
    del source["_command_expression_json"]
    generic = compile_native_policy_authority([source])
    original = generic.for_snapshot(capabilities(expressions=False))
    assert "command_expressions" not in original
    assert native_policy_authority_from_mapping({**original, "command_expressions": []}) == generic
    draft = compile_native_policy_authority([row()])
    digest = draft.content_digest
    wire = draft.for_snapshot(capabilities())
    bindings = wire["command_expressions"]
    assert isinstance(bindings, list)
    bindings.clear()
    assert draft.content_digest == digest and draft.content_digest != generic.content_digest


@pytest.mark.parametrize(
    "value",
    [
        None,
        True,
        {},
        "{}",
        "",
        encoded(expression(caseSensitive=False)),
        encoded(expression(operator="regex")),
        encoded(expression(operator="glob")),
        encoded(expression(field="cwd")),
        encoded(expression(value=" printf ")),
        encoded(expression(extra=True)),
        encoded({**expression(), "extra": True}),
        encoded({"combinator": "all", "conditions": []}),
        encoded({"combinator": "all", "conditions": [{"field": "command", "operator": "exact", "value": "printf"}]}),
        encoded(expression(value="x" * 513)),
        encoded(expression(value="\ud800")),
    ],
)
def test_marker_cannot_be_silently_erased_or_accept_a_broader_ast(value: object) -> None:
    with pytest.raises(NativePolicySnapshotError):
        compile_native_policy_authority([row(_command_expression_json=value)])


@pytest.mark.parametrize(
    "value",
    [
        None,
        {},
        True,
        "[]",
        [None],
        [{"decision_id": True, "expression": expression()}],
        [{"decision_id": 4.0, "expression": expression()}],
        [{"decision_id": "4", "expression": expression()}],
        [{"decision_id": 4, "expression": expression(), "extra": True}],
        [{"decision_id": 5, "expression": expression()}],
        [{"decision_id": 4, "expression": expression()}] * 2,
    ],
)
def test_strict_wire_refuses_null_types_unknown_or_orphan_bindings(value: object) -> None:
    wire = compile_native_policy_authority([row()]).for_snapshot(capabilities())
    wire["command_expressions"] = value
    with pytest.raises(NativePolicySnapshotError):
        native_policy_authority_from_mapping(wire)


@pytest.mark.parametrize("source", ["local", "cloud-signed-memory"])
def test_associations_cannot_authorize_unsigned_or_memory_expression_rows(source: str) -> None:
    with pytest.raises(NativePolicySnapshotError, match="command_expression_invalid"):
        compile_native_policy_authority([row(source=source)])


def test_immutable_constructor_and_draft_reject_invalid_values() -> None:
    draft = compile_native_policy_authority([row()])
    with pytest.raises(NativePolicySnapshotError):
        replace(draft, command_expressions=list(draft.command_expressions))
    with pytest.raises(NativePolicySnapshotError):
        NativeScopedCommandExpression(4, '{"combinator":"all","combinator":"all","conditions":[]}')


def test_real_snapshot_mac_binds_the_association_and_expression(tmp_path: Path) -> None:
    key = b"k" * 32
    snapshot = build_policy_snapshot_v4(
        config=GuardConfig(guard_home=tmp_path, workspace=None),
        guard_home=tmp_path,
        runtime_identity="a" * 64,
        rule_digest="b" * 64,
        verifier_key=key,
        generation=4,
        authority=compile_native_policy_authority([row()]),
        capabilities=capabilities(),
        source_input_digest="c" * 64,
        issued_at_ms=1000,
        expires_at_ms=2000,
    )

    def verify(value: Mapping[str, object]) -> None:
        verify_snapshot_v4(
            value,
            verifier_key=key,
            expected_runtime_identity="a" * 64,
            expected_rule_digest="b" * 64,
            minimum_generation=4,
            now_ms=1500,
        )

    verify(snapshot)
    for operation in ("remove", "replace"):
        tampered = copy.deepcopy(snapshot)
        authority = tampered["scoped_authority"]
        assert isinstance(authority, dict)
        if operation == "remove":
            del authority["command_expressions"]
        else:
            authority["command_expressions"] = [{"decision_id": 4, "expression": expression(value="whoami")}]
        tampered["policy_digest"] = policy_digest_v4(tampered)
        with pytest.raises(NativePolicySnapshotError, match="integrity_mismatch"):
            verify(tampered)

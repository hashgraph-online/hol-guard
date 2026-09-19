"""HGP-157: generic matcher representability is a published capability."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.policy_document import GuardPolicyDocument
from codex_plugin_scanner.guard.policy_document_compile import compile_policy_document
from codex_plugin_scanner.guard.policy_document_types import PolicyCompilationError
from codex_plugin_scanner.guard.policy_matcher_capability import (
    GENERIC_MATCH_KEYS,
    published_generic_matcher_capability,
    unsupported_matcher_reason,
)


def _document(match: dict[str, object], *, rule_id: str = "rule-1") -> GuardPolicyDocument:
    return GuardPolicyDocument.from_mapping(
        {
            "apiVersion": "guard.hashgraphonline.com/v1alpha1",
            "kind": "GuardPolicy",
            "metadata": {
                "id": "doc",
                "name": "Matchers",
                "revision": 1,
                "createdAt": "2026-07-16T12:00:00Z",
                "updatedAt": "2026-07-16T12:00:00Z",
            },
            "spec": {
                "defaults": {"mode": "prompt"},
                "rules": [
                    {
                        "id": rule_id,
                        "enabled": True,
                        "match": match,
                        "effect": "block",
                        "lifetime": {"mode": "permanent"},
                        "provenance": {"source": "import", "createdAt": "2026-07-16T12:00:00Z"},
                    }
                ],
            },
        }
    )


def test_published_capability_lists_generic_lane() -> None:
    capability = published_generic_matcher_capability()
    generic = capability["lanes"]["generic-local-sqlite"]
    assert set(generic["match_keys"]) == GENERIC_MATCH_KEYS
    assert generic["unknown_matchers"] == "reject"


def test_unknown_matcher_does_not_compile_as_global() -> None:
    reason = unsupported_matcher_reason({"secretTypes": ["aws"]}, rule_id="secret-rule")
    assert reason is not None
    assert reason["rule_id"] == "secret-rule"
    assert "secretTypes" in reason["unsupported_keys"]
    with pytest.raises(PolicyCompilationError, match="unsupported_policy_match") as error:
        compile_policy_document(_document({"secretTypes": ["aws"]}, rule_id="secret-rule"))
    assert error.value.rule_id == "secret-rule"


def test_supported_artifact_matcher_compiles() -> None:
    rows = compile_policy_document(_document({"artifacts": ["codex:project:demo"]}))
    assert len(rows) == 1
    assert rows[0].decision.artifact_id == "codex:project:demo"
    assert rows[0].decision.scope == "artifact"


def test_tool_matcher_preserves_supported_family_and_rejects_unknown_values() -> None:
    assert "tools" in GENERIC_MATCH_KEYS
    rows = compile_policy_document(_document({"tools": ["mcp"], "harnesses": ["codex"]}))
    assert len(rows) == 1
    assert rows[0].decision.artifact_id == "family:mcp"
    assert rows[0].decision.harness == "codex"
    with pytest.raises(PolicyCompilationError, match="unsupported_policy_match"):
        compile_policy_document(_document({"tools": ["fixture-tool"]}))


def test_published_capability_cannot_mutate_future_advertisements() -> None:
    original = published_generic_matcher_capability()
    changed = published_generic_matcher_capability()
    changed["lanes"]["generic-local-sqlite"]["match_keys"].append("tools")
    assert published_generic_matcher_capability() == original

"""Published matcher descriptions must agree with the actual compiler."""

from __future__ import annotations

from typing import cast

from codex_plugin_scanner.guard.policy_capability_inventory import local_row_projection_capabilities
from codex_plugin_scanner.guard.policy_document import GuardPolicyDocument
from codex_plugin_scanner.guard.policy_document_compile import compile_policy_document
from codex_plugin_scanner.guard.policy_matcher_capability import GENERIC_MATCH_KEYS, unsupported_matcher_reason

EXACT_SELECTOR: dict[str, str] = {
    "contractVersion": "guard.exact-command.v1",
    "sha256": "a" * 64,
}


def _document(match: dict[str, object]) -> GuardPolicyDocument:
    return GuardPolicyDocument.from_mapping(
        {
            "apiVersion": "guard.hashgraphonline.com/v1alpha1",
            "kind": "GuardPolicy",
            "metadata": {
                "id": "lane-contract",
                "name": "Lane contract",
                "revision": 1,
                "createdAt": "2026-09-18T00:00:00Z",
                "updatedAt": "2026-09-18T00:00:00Z",
            },
            "spec": {
                "defaults": {"mode": "prompt"},
                "rules": [
                    {
                        "id": "exact-rule",
                        "enabled": True,
                        "effect": "block",
                        "match": match,
                        "lifetime": {"mode": "permanent"},
                        "provenance": {"source": "import", "createdAt": "2026-09-18T00:00:00Z"},
                    }
                ],
            },
        }
    )


def test_exact_selector_is_a_published_generic_matcher() -> None:
    assert "exactCommand" in GENERIC_MATCH_KEYS
    assert (
        unsupported_matcher_reason(
            {
                "artifacts": ["shell:echo"],
                "exactCommand": EXACT_SELECTOR,
            },
            rule_id="exact-rule",
        )
        is None
    )


def test_exact_selector_has_a_published_lossless_combination() -> None:
    profile = local_row_projection_capabilities()
    combinations = cast(list[list[str]], profile["supported_match_combinations"])
    expected = {"artifacts", "exactCommand", "harnesses", "workspaces"}
    assert expected in [set(keys) for keys in combinations]


def test_actual_compiler_keeps_exact_selector_and_all_context() -> None:
    rows = compile_policy_document(
        _document(
            {
                "artifacts": ["shell:echo"],
                "harnesses": ["codex"],
                "workspaces": ["/synthetic/workspace"],
                "exactCommand": EXACT_SELECTOR,
            }
        )
    )
    assert len(rows) == 1
    assert rows[0].rule_id == "exact-rule"
    assert rows[0].decision.artifact_id == "shell:echo"
    assert rows[0].decision.harness == "codex"
    assert rows[0].decision.workspace == "/synthetic/workspace"
    assert rows[0].decision.exact_command_sha256 == "a" * 64
    assert rows[0].decision.action == "block"

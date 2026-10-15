"""Draft conformance must not turn unsupported business rules into local allows."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
import yaml

from codex_plugin_scanner.guard.policy_document import canonical_policy_document_bytes
from codex_plugin_scanner.guard.policy_document_compile import compile_policy_document
from codex_plugin_scanner.guard.policy_document_types import PolicyCompilationError
from codex_plugin_scanner.guard.policy_document_yaml import (
    PolicyDocumentError,
    format_policy_document_yaml,
    parse_policy_document_yaml,
)

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "contracts" / "business-policy"
SELECTORS = json.loads((CONTRACTS / "selector-v1-fixtures.json").read_text())
DOMAINS = json.loads((CONTRACTS / "recipient-domains-v1-fixtures.json").read_text())


@pytest.mark.parametrize("enabled", [True, False])
def test_budget_drafts_round_trip_and_cannot_be_flattened_into_local_rows(enabled: bool) -> None:
    selector = {
        "schema": "guard.business-policy-match.v1",
        "version": 1,
        "services": ["google_gmail"],
        "operations": ["mail_send"],
    }
    source = yaml.safe_load(_draft(selector, effect="allow"))
    source["spec"]["rules"][0]["enabled"] = enabled
    source["spec"]["rules"][0]["match"] = {"artifacts": ["artifact.test"]}
    source["spec"]["budgets"] = [{
        "schema": "guard.business-budget.v1", "version": 1, "id": "mail.daily", "scope": "account",
        "match": selector, "windowMs": 86400000, "maximumActions": 0,
        "maximumRecipients": 10, "maximumRecords": 10, "maximumBytes": 10000,
    }]
    document = parse_policy_document_yaml(yaml.safe_dump(source))
    reparsed = parse_policy_document_yaml(format_policy_document_yaml(document))
    assert reparsed.to_mapping()["spec"]["budgets"] == source["spec"]["budgets"]
    assert canonical_policy_document_bytes(reparsed) == canonical_policy_document_bytes(document)
    with pytest.raises(PolicyCompilationError, match="unsupported_policy_budgets"):
        compile_policy_document(reparsed)


def _draft(selector: object, *, effect: str = "block", extra: dict[str, object] | None = None) -> str:
    return yaml.safe_dump(
        {
            "apiVersion": "guard.hashgraphonline.com/v1alpha1",
            "kind": "GuardPolicy",
            "metadata": {"id": "business-draft", "name": "Business draft", "revision": 1},
            "spec": {
                "defaults": {"mode": "enforce"},
                "rules": [
                    {
                        "id": "mail-rule",
                        "enabled": True,
                        "effect": effect,
                        "match": {"business": selector, **(extra or {})},
                        "lifetime": {"mode": "permanent"},
                        "provenance": {"source": "local", "createdAt": "2026-10-05T00:00:00Z"},
                    }
                ],
            },
        },
        sort_keys=False,
    )


def _assert_conformance(selector: object, *, valid: bool) -> None:
    source = _draft(selector)
    if not valid:
        with pytest.raises(PolicyDocumentError):
            parse_policy_document_yaml(source)
        return
    document = parse_policy_document_yaml(source)
    assert document.rules[0].match.to_mapping()["business"] == selector
    reparsed = parse_policy_document_yaml(format_policy_document_yaml(document))
    assert canonical_policy_document_bytes(reparsed) == canonical_policy_document_bytes(document)
    with pytest.raises(PolicyCompilationError, match="unsupported_policy_match"):
        compile_policy_document(reparsed)


@pytest.mark.parametrize("case", SELECTORS["cases"], ids=lambda case: case["id"])
def test_shared_native_selector_conformance(case: dict[str, object]) -> None:
    selector = copy.deepcopy(SELECTORS["base"])
    selector.update(case["patch"])
    for field in case.get("remove", []):
        selector.pop(field)
    _assert_conformance(selector, valid=case["valid"])


@pytest.mark.parametrize("case", DOMAINS["cases"], ids=lambda case: case["id"])
def test_shared_native_recipient_domain_conformance(case: dict[str, object]) -> None:
    selector = {**SELECTORS["base"], "recipientDomains": case["domains"]}
    _assert_conformance(selector, valid=case["valid"])


@pytest.mark.parametrize("effect", ["allow", "block"])
@pytest.mark.parametrize(
    "extra",
    [{}, {"actors": ["actor-1"]}, {"workspaces": ["workspace-1"]}, {"harnesses": ["codex"]}],
)
def test_business_draft_preserves_intersection_and_cannot_compile(effect: str, extra: dict[str, object]) -> None:
    selector = SELECTORS["base"]
    document = parse_policy_document_yaml(_draft(selector, effect=effect, extra=extra))
    expected = {"business": selector, **extra}
    assert document.rules[0].match.to_mapping() == expected
    reparsed = parse_policy_document_yaml(format_policy_document_yaml(document))
    assert reparsed.rules[0].match.to_mapping() == expected
    with pytest.raises(PolicyCompilationError, match="unsupported_policy_match"):
        compile_policy_document(reparsed)


@pytest.mark.parametrize("selector", [None, {}, [], "business", True])
def test_malformed_business_field_never_becomes_wildcard(selector: object) -> None:
    _assert_conformance(selector, valid=False)


@pytest.mark.parametrize("suffix", ["\n", "\r\n", "\u2028", "\u2029"])
def test_account_binding_requires_exact_bytes(suffix: str) -> None:
    _assert_conformance({**SELECTORS["base"], "accountBindings": ["a" * 64 + suffix]}, valid=False)


def _large_selector(count: int) -> dict[str, object]:
    return {
        **SELECTORS["base"],
        "accountBindings": [f"{index:064x}" for index in range(count)],
        "recipientDomains": [
            ".".join([f"{index:03d}" + "a" * 60, "b" * 63, "c" * 63, "d" * 61]) for index in range(count)
        ],
    }


def test_aggregate_selector_limit_rejects_individually_valid_arrays() -> None:
    selector = _large_selector(256)
    source = _draft(selector)
    assert len(source.encode()) < 1_048_576
    with pytest.raises(PolicyDocumentError) as caught:
        parse_policy_document_yaml(source)
    diagnostic = caught.value.diagnostics[0]
    assert diagnostic.code == "business_selector_limit_bytes"
    assert diagnostic.path == ("spec", "rules", 0, "match", "business")
    assert "aaaaaaaa" not in str(caught.value)


def test_bounded_selector_keeps_all_values() -> None:
    _assert_conformance(_large_selector(100), valid=True)

"""Executable checks for the published local row capability inventory."""

from __future__ import annotations

import itertools
import json

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.policy_document import GuardPolicyDocument
from codex_plugin_scanner.guard.policy_document_compile import compile_policy_document
from codex_plugin_scanner.guard.policy_document_types import PolicyCompilationError
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_policy_cli_error_guidance import policy

SELECTORS = {
    "artifacts": ["skill:capability"],
    "harnesses": ["codex"],
    "publishers": ["verified-publisher"],
    "tools": ["shell"],
    "workspaces": ["/workspace/project"],
}
KEY_SETS = [tuple(keys) for n in range(6) for keys in itertools.combinations(SELECTORS, n)]


def inventory(capsys):
    assert main(["guard", "policy", "capabilities", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["guard_version"]
    return payload["local_row_projection"]


@pytest.mark.parametrize("keys", KEY_SETS)
@pytest.mark.parametrize("effect", ["allow", "block", "review"])
@pytest.mark.parametrize("lifetime", ["permanent", "until"])
def test_advertised_combinations_match_real_compiler(capsys, keys, effect, lifetime):
    capability = inventory(capsys)
    value = policy(match={key: SELECTORS[key] for key in keys}, lifetime=lifetime)
    # Empty match is an explicit global rule, not a fallback from unknown fields.
    value["spec"]["rules"][0]["match"] = {key: SELECTORS[key] for key in keys}
    value["spec"]["rules"][0]["effect"] = effect
    if lifetime == "until":
        value["spec"]["rules"][0]["lifetime"]["expiresAt"] = "2030-01-01T00:00:00Z"
    document = GuardPolicyDocument.from_mapping(value)
    combinations = {frozenset(item) for item in capability["supported_match_combinations"]}
    if frozenset(keys) in combinations:
        rows = compile_policy_document(document)
        assert len(rows) == 1 and rows[0].decision.action == effect
        row = rows[0].decision
        assert row.harness == ("codex" if "harnesses" in keys else "*")
        assert row.workspace == ("/workspace/project" if "workspaces" in keys else None)
        assert row.publisher == ("verified-publisher" if "publishers" in keys else None)
        expected_artifact = None
        if "artifacts" in keys:
            expected_artifact = "skill:capability"
        elif "tools" in keys:
            expected_artifact = "family:tool-action"
        assert row.artifact_id == expected_artifact
        assert rows[0].decision.expires_at == ("2030-01-01T00:00:00Z" if lifetime == "until" else None)
    else:
        with pytest.raises(PolicyCompilationError) as rejected:
            compile_policy_document(document)
        assert rejected.value.code in {"unsupported_policy_match", "unsupported_policy_scope_projection"}
        assert rejected.value.rule_id == "affected-rule"


def test_inventory_does_not_promise_device_command_or_session_row_support(capsys):
    capability = inventory(capsys)
    assert capability["effects"] == ["allow", "block", "review"]
    assert capability["inert_effects"] == ["ignore"]
    assert capability["lifetimes"] == ["permanent", "until"]
    assert capability["maximum_compiled_rows"] == 10_000
    assert capability["device_selection"] == "cloud_installation_id_filter_before_compilation"
    assert capability["command_expressions"] == "cli_evaluator_only; authenticated_application_unsupported"
    assert capability["required_validation"] == "policy validate"
    assert "devices" not in capability["match_fields"]
    assert capability["tool_families"]["shell"] == "tool-action"


@pytest.mark.parametrize(
    ("keys", "artifact", "off_target"),
    [
        (("artifacts", "harnesses", "workspaces"), "skill:capability", {"workspace": "/workspace/other"}),
        (("publishers", "harnesses"), "skill:arbitrary", {"publisher": "other-publisher"}),
        (
            ("tools", "harnesses", "workspaces"),
            "codex:project:tool-action:capability",
            {"workspace": "/workspace/other"},
        ),
    ],
)
def test_maximal_supported_sets_preserve_restrictions_in_real_store(tmp_path, keys, artifact, off_target):
    document = GuardPolicyDocument.from_mapping(policy(match={key: SELECTORS[key] for key in keys}))
    store = GuardStore(tmp_path)
    store.import_policy_document(
        document, compile_policy_document(document), mode="merge", now="2026-09-17T12:00:00Z", approval_gate_grant=None
    )
    context = {"workspace": "/workspace/project", "publisher": "verified-publisher", "now": "2026-09-17T12:00:01Z"}
    result = store.resolve_policy_decision_lookup("codex", artifact, **context)["decision"]
    assert result is not None and result["action"] == "block"
    assert store.resolve_policy_decision_lookup("other-harness", artifact, **context)["decision"] is None
    assert store.resolve_policy_decision_lookup("codex", artifact, **(context | off_target))["decision"] is None

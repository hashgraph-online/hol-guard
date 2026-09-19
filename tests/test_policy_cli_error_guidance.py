"""Public CLI diagnostics from actual bounded policy parsing and compilation."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
import yaml

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.policy_document_io import write_private_policy_text


def policy(*, match: dict[str, object] | None = None, lifetime: str = "permanent") -> dict[str, object]:
    return {
        "apiVersion": "guard.hashgraphonline.com/v1alpha1",
        "kind": "GuardPolicy",
        "metadata": {"id": "diagnostic-fixture", "name": "Diagnostics", "revision": 1},
        "spec": {
            "defaults": {"mode": "prompt"},
            "rules": [
                {
                    "id": "affected-rule",
                    "enabled": True,
                    "effect": "block",
                    "match": match or {"artifacts": ["skill:example"]},
                    "lifetime": {"mode": lifetime, "expiresAt": None},
                    "provenance": {"source": "review-decision", "createdAt": "2026-09-17T00:00:00Z"},
                }
            ],
        },
    }


def run_validate(tmp_path: Path, capsys: pytest.CaptureFixture[str], value: dict[str, object]):
    path = tmp_path / "policy.yaml"
    write_private_policy_text(path, yaml.safe_dump(value))
    result = main(["guard", "policy", "validate", str(path), "--json"])
    output = capsys.readouterr().out
    return result, json.loads(output), output


@pytest.mark.parametrize(
    ("value", "code", "field", "remedy"),
    [
        (policy(match={"domains": ["private.example.invalid"]}), "unsupported_policy_match", "match", "supported"),
        (policy(lifetime="session"), "unsupported_policy_lifetime", "lifetime", "permanent"),
        (
            policy(
                match={
                    "artifacts": [f"skill:{i}" for i in range(101)],
                    "harnesses": [f"harness-{i}" for i in range(100)],
                }
            ),
            "policy_compilation_limit",
            "match",
            "10,000",
        ),
    ],
)
def test_compilation_errors_identify_rule_field_and_remedy(tmp_path, capsys, value, code, field, remedy):
    result, payload, output = run_validate(tmp_path, capsys, value)
    assert result == 4
    assert payload["error"] == code
    diagnostic = payload["diagnostics"][0]
    assert diagnostic["code"] == code
    assert diagnostic["rule_id"] == "affected-rule"
    assert diagnostic["path"] == f"$.spec.rules[*].{field}"
    assert remedy in diagnostic["remediation"]
    assert "private.example.invalid" not in output
    assert len(output) < 2048


def test_parser_error_never_echoes_extension_key_or_value(tmp_path, capsys):
    value = policy()
    value["credential-canary-DO-NOT-ECHO"] = {"token": "secret-value-DO-NOT-ECHO"}
    result, payload, output = run_validate(tmp_path, capsys, value)
    assert result == 4
    assert "credential-canary-DO-NOT-ECHO" not in output
    assert "secret-value-DO-NOT-ECHO" not in output
    diagnostic = payload["diagnostics"][0]
    assert diagnostic["code"] == "forbidden_sensitive_field"
    assert diagnostic["rule_id"] is None
    assert diagnostic["path"] == "$"
    assert "credential" in diagnostic["remediation"].lower()


def test_unknown_matcher_has_safe_indexed_location(tmp_path, capsys):
    result, payload, output = run_validate(
        tmp_path, capsys, policy(match={"unknown-credential-canary": ["secret-target"]})
    )
    assert result == 4
    assert payload["error"] == "PolicyDocumentError"
    diagnostic = payload["diagnostics"][0]
    assert diagnostic["code"] == "schema_additionalProperties"
    assert diagnostic["path"] == "$.spec.rules[0].match"
    assert diagnostic["rule_id"] is None  # Parsing failed before any rule was trusted.
    assert "schema" in diagnostic["remediation"]
    assert "unknown-credential-canary" not in output
    assert "secret-target" not in output


def test_parser_keeps_byte_limit_with_bounded_public_output(tmp_path, capsys):
    path = tmp_path / "oversized.yaml"
    path.write_text("# credential-canary\n" * 60_000)
    path.chmod(0o600)
    result = main(["guard", "policy", "validate", str(path), "--json"])
    output = capsys.readouterr().out
    payload = json.loads(output)
    assert result == 4
    assert payload["error"] == "policy_file_too_large"
    assert "credential-canary" not in output
    assert len(output) < 1024


def test_many_parse_errors_remain_bounded(tmp_path, capsys):
    value = policy()
    value["spec"]["rules"] = [
        dict(copy.deepcopy(value["spec"]["rules"][0]), id=f"rule-{i}", enabled="invalid-secret-value")
        for i in range(50)
    ]
    result, payload, output = run_validate(tmp_path, capsys, value)
    assert result == 4
    assert len(payload["diagnostics"]) == 20
    assert len(output) < 10_000
    assert "invalid-secret-value" not in output
    assert all(item["code"] == "schema_type" for item in payload["diagnostics"])


def test_text_mode_includes_rule_and_safe_corrective_action(tmp_path, capsys):
    path = tmp_path / "policy.yaml"
    write_private_policy_text(path, yaml.safe_dump(policy(lifetime="session")))
    assert main(["guard", "policy", "validate", str(path)]) == 4
    output = capsys.readouterr().out
    assert "affected-rule" in output
    assert "$.spec.rules[*].lifetime" in output
    assert "permanent or until" in output
    assert len(output) < 1024


def test_regex_parse_failure_has_stable_code_without_engine_exception_text(tmp_path, capsys):
    result, payload, output = run_validate(
        tmp_path,
        capsys,
        policy(
            match={
                "commands": {
                    "combinator": "any",
                    "conditions": [{"field": "command", "operator": "regex", "value": "(?P<credential-canary>a)"}],
                }
            }
        ),
    )
    assert result == 4
    diagnostic = payload["diagnostics"][0]
    assert diagnostic["code"] == "invalid_command_regex"
    assert diagnostic["path"] == "$.spec.rules[0].match.commands"
    assert "credential-canary" not in output
    assert "bad character" not in output

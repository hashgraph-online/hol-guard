"""Exercise the actual parser, trusted file loader, and CLI lane diagnostics."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.policy_document_io import write_private_policy_text


def _write_policy(directory: Path, match: dict[str, object]) -> Path:
    directory.mkdir(mode=0o700)
    path = directory / "policy.yaml"
    write_private_policy_text(
        path,
        json.dumps(
            {
                "apiVersion": "guard.hashgraphonline.com/v1alpha1",
                "kind": "GuardPolicy",
                "metadata": {"id": "synthetic-cli", "name": "Synthetic CLI", "revision": 1},
                "spec": {
                    "defaults": {"mode": "prompt"},
                    "rules": [
                        {
                            "id": "rule-a",
                            "enabled": True,
                            "effect": "block",
                            "match": match,
                            "lifetime": {"mode": "permanent", "expiresAt": None},
                            "provenance": {
                                "source": "import",
                                "createdAt": "2026-09-18T00:00:00Z",
                                "receiptIds": [],
                            },
                        }
                    ],
                },
            }
        ),
    )
    return path


def test_cli_reports_static_profiles_separately_from_activation(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["guard", "policy", "capabilities", "--json"]) == 0
    value = json.loads(capsys.readouterr().out)
    assert value["runtime_lanes"]["activation_evidence"] == "not_evaluated"
    assert value["command_pattern_expressions"]["evaluation_scope"] == "cli_evaluator_only"
    assert value["command_pattern_expressions"]["authenticated_application"] == "unsupported"
    assert value["runtime_lanes"]["lanes"]["native-scoped-v4"]["activation"]["advertised"] is False


@pytest.mark.parametrize(
    ("lane", "expected"),
    [("generic-local-sqlite", 0), ("native-intrinsic", 2), ("native-scoped-v4", 2)],
)
def test_cli_selects_real_validator_after_trusted_loading(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], lane: str, expected: int
) -> None:
    path = _write_policy(tmp_path / "private", {"artifacts": ["shell:echo"]})
    assert main(["guard", "policy", "validate", str(path), "--runtime-lane", lane, "--json"]) == expected
    value = json.loads(capsys.readouterr().out)
    assert value["runtime_lane"] == lane
    assert value["valid"] is (expected == 0)
    assert value["activation_evidence"] == "not_evaluated"
    assert value["compiled_rows"] == 1


@pytest.mark.parametrize("invalid", [None, [], ["unknown"], {}])
def test_cli_does_not_normalize_invalid_selector_into_global_scope(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], invalid: object
) -> None:
    path = _write_policy(tmp_path / "private", {"notASelector": invalid})
    assert (
        main(
            [
                "guard",
                "policy",
                "validate",
                str(path),
                "--runtime-lane",
                "generic-local-sqlite",
                "--json",
            ]
        )
        != 0
    )
    value = json.loads(capsys.readouterr().out)
    assert value["error"] == "PolicyDocumentError"


def test_cli_expression_evaluation_cannot_claim_authenticated_admission(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    expression: dict[str, object] = {
        "combinator": "any",
        "conditions": [{"field": "command", "operator": "exact", "value": "echo synthetic"}],
    }
    path = _write_policy(tmp_path / "private", {"commands": expression})
    assert main(["guard", "policy", "evaluate-command", str(path), "--command", "echo synthetic", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["action"] == "block"
    assert (
        main(
            [
                "guard",
                "policy",
                "validate",
                str(path),
                "--runtime-lane",
                "generic-local-sqlite",
                "--json",
            ]
        )
        == 2
    )
    value = json.loads(capsys.readouterr().out)
    assert value["valid"] is False
    assert value["rule_diagnostics"][0]["rule_id"] == "rule-a"


@pytest.mark.parametrize("effect", ["allow", "review", "block", "warn"])
def test_advertised_evaluator_effects_match_actual_trusted_loading(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], effect: str
) -> None:
    path = _write_policy(
        tmp_path / "private",
        {
            "commands": {
                "combinator": "any",
                "conditions": [
                    {"field": "command", "operator": "exact", "value": "echo synthetic"},
                ],
            },
        },
    )
    content = json.loads(path.read_text())
    content["spec"]["rules"][0]["effect"] = effect
    write_private_policy_text(path, json.dumps(content))
    status = main(["guard", "policy", "evaluate-command", str(path), "--command", "echo synthetic", "--json"])
    value = json.loads(capsys.readouterr().out)
    if effect == "warn":
        assert status != 0
        assert value["error"] == "PolicyDocumentError"
    else:
        assert status == 0
        assert value["action"] == effect


@pytest.mark.parametrize("restriction", ["workspace", "until", "local", "managed-rule", "managed-root", "generic"])
def test_actual_evaluator_refuses_to_drop_additional_authority(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], restriction: str
) -> None:
    path = _write_policy(
        tmp_path / "private",
        {
            "commands": {
                "combinator": "any",
                "conditions": [
                    {"field": "command", "operator": "exact", "value": "echo synthetic"},
                ],
            },
        },
    )
    content = json.loads(path.read_text())
    rule = content["spec"]["rules"][0]
    if restriction == "workspace":
        rule["match"]["workspaces"] = ["/synthetic/workspace"]
    elif restriction == "until":
        rule["lifetime"] = {"mode": "until", "expiresAt": "2030-01-01T00:00:00Z"}
    elif restriction == "local":
        rule["x-hol-local"] = {"artifactHash": "synthetic-context"}
    elif restriction == "managed-rule":
        rule["x-hol-extension-targets"] = []
    elif restriction == "managed-root":
        content["x-hol-extension-controls"] = {}
    else:
        rule["match"] = {"artifacts": ["shell:echo"]}
    write_private_policy_text(path, json.dumps(content))
    assert main(["guard", "policy", "evaluate-command", str(path), "--command", "echo synthetic", "--json"]) != 0
    value = json.loads(capsys.readouterr().out)
    assert value["code"] == "command_evaluator_scope_unsupported"


def test_trusted_loader_already_refuses_unpublished_network_extension(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = _write_policy(
        tmp_path / "private",
        {
            "commands": {
                "combinator": "any",
                "conditions": [
                    {"field": "command", "operator": "exact", "value": "echo synthetic"},
                ],
            },
        },
    )
    content = json.loads(path.read_text())
    content["spec"]["networkPolicy"] = {
        "schemaVersion": "guard.network-policy.v1",
        "rules": [{"action": "block", "destination": "invalid.example"}],
    }
    write_private_policy_text(path, json.dumps(content))
    assert main(["guard", "policy", "evaluate-command", str(path), "--command", "echo synthetic", "--json"]) != 0
    assert json.loads(capsys.readouterr().out)["error"] == "PolicyDocumentError"

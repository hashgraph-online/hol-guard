"""HGP-158: bounded actionable policy compile errors."""

from __future__ import annotations

import json
from io import StringIO
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli.commands_dispatch_policy_document import _run_guard_policy_document_command
from codex_plugin_scanner.guard.policy_document import GuardPolicyDocument
from codex_plugin_scanner.guard.policy_document_compile import compile_policy_document
from codex_plugin_scanner.guard.policy_document_io import write_private_policy_text
from codex_plugin_scanner.guard.policy_document_types import PolicyCompilationError
from codex_plugin_scanner.guard.policy_document_yaml import format_policy_document_yaml
from codex_plugin_scanner.guard.policy_error_guidance import public_policy_document_error


def _args(command: str, path: Path) -> object:
    return type(
        "Args",
        (),
        {
            "policy_command": command,
            "file": str(path),
            "check": False,
            "include_provenance": False,
            "mode": "merge",
            "dry_run": True,
            "command_text": "",
            "json": True,
        },
    )()


def test_unknown_matcher_error_identifies_rule_and_remedy() -> None:
    error = PolicyCompilationError("unsupported_policy_match", "rule-secret")
    payload = public_policy_document_error(error)
    assert payload["rule_id"] == "rule-secret"
    assert payload["field_path"].endswith(".match")
    assert "artifacts" in payload["remediation"]
    assert "refresh_token" not in json.dumps(payload)


def test_cli_validate_returns_bounded_compile_error(tmp_path: Path) -> None:
    document = GuardPolicyDocument.from_mapping(
        {
            "apiVersion": "guard.hashgraphonline.com/v1alpha1",
            "kind": "GuardPolicy",
            "metadata": {"id": "doc", "name": "Bad", "revision": 1},
            "spec": {
                "defaults": {"mode": "prompt"},
                "rules": [
                    {
                        "id": "fanout-rule",
                        "enabled": True,
                        "match": {"domains": ["example.com"]},
                        "effect": "block",
                        "lifetime": {"mode": "session"},
                        "provenance": {"source": "import", "createdAt": "2026-07-16T12:00:00Z"},
                    }
                ],
            },
        }
    )
    policy_directory = tmp_path / "private-policy"
    policy_directory.mkdir(mode=0o700)
    path = policy_directory / "policy.yaml"
    write_private_policy_text(path, format_policy_document_yaml(document))
    stream = StringIO()
    code = _run_guard_policy_document_command(_args("validate", path), output_stream=stream)
    payload = json.loads(stream.getvalue())
    assert code == 4
    assert payload["code"] in {"unsupported_policy_match", "unsupported_policy_lifetime"}
    assert payload["rule_id"] == "fanout-rule"
    assert "remediation" in payload
    assert "refresh_token" not in json.dumps(payload)


def test_fanout_limit_names_the_rule() -> None:
    with pytest.raises(PolicyCompilationError) as error:
        compile_policy_document(
            GuardPolicyDocument.from_mapping(
                {
                    "apiVersion": "guard.hashgraphonline.com/v1alpha1",
                    "kind": "GuardPolicy",
                    "metadata": {
                        "id": "doc",
                        "name": "Fanout",
                        "revision": 1,
                        "createdAt": "2026-07-16T12:00:00Z",
                        "updatedAt": "2026-07-16T12:00:00Z",
                    },
                    "spec": {
                        "defaults": {"mode": "prompt"},
                        "rules": [
                            {
                                "id": "too-wide",
                                "enabled": True,
                                "match": {
                                    "artifacts": [f"skill:hol/{index}" for index in range(101)],
                                    "harnesses": [f"h{index}" for index in range(101)],
                                },
                                "effect": "block",
                                "lifetime": {"mode": "permanent"},
                                "provenance": {"source": "import", "createdAt": "2026-07-16T12:00:00Z"},
                            }
                        ],
                    },
                }
            )
        )
    payload = public_policy_document_error(error.value)
    assert payload["code"] == "policy_compilation_limit"
    assert payload["rule_id"] == "too-wide"

"""Regression coverage for command-coverage follow-up fixes."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.command_inspection import inspect_command


@pytest.mark.parametrize("value", ["all", "local"])
def test_compose_rmi_accepts_documented_values(value: str, tmp_path: Path) -> None:
    payload = inspect_command(
        f"docker compose down --rmi={value}",
        cwd=tmp_path,
        home_dir=tmp_path,
    )

    assert payload["status"] == "review"
    assert "command.container-runtime.compose-destructive-cleanup" in {
        rule["rule_id"] for rule in payload["rules"]
    }


@pytest.mark.parametrize(
    "command",
    [
        "docker compose down --rmi=none",
        "docker compose down --rmi none",
        "docker compose down --rmi=invalid",
    ],
)
def test_compose_rmi_rejects_undocumented_values(command: str, tmp_path: Path) -> None:
    payload = inspect_command(command, cwd=tmp_path, home_dir=tmp_path)

    assert payload["status"] == "no_match"


@pytest.mark.parametrize(
    ("command", "rule_id"),
    [
        ("docker --context prod system prune", "command.container-runtime.system-prune"),
        ("docker --context prod volume rm app-data", "command.container-runtime.volume-removal"),
        ("kubectl --context prod delete pod api", "command.kubernetes-operations.delete-resources"),
        ("kubectl --context prod apply -f deployment.yaml", "command.kubernetes-operations.apply-resources"),
        ("helm --namespace prod uninstall api", "command.kubernetes-operations.helm-uninstall"),
        ("helm --namespace prod upgrade api ./chart", "command.kubernetes-operations.helm-upgrade"),
    ],
)
def test_shared_infrastructure_grammar_preserves_legacy_and_expanded_rules(
    command: str,
    rule_id: str,
    tmp_path: Path,
) -> None:
    payload = inspect_command(command, cwd=tmp_path, home_dir=tmp_path)

    assert payload["status"] == "review"
    assert rule_id in {rule["rule_id"] for rule in payload["rules"]}

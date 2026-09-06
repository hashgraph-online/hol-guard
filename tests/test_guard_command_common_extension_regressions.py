"""Regression coverage for common container and Kubernetes command extensions."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.command_inspection import inspect_command


@pytest.mark.parametrize(
    ("command", "rule_id"),
    [
        ("docker service remove api", "command.container-runtime.swarm-resource-removal"),
        ("docker stack down prod", "command.container-runtime.swarm-resource-removal"),
        ("kubectl -v 6 apply -f deployment.yaml", "command.kubernetes-operations.apply-resources"),
        ("kubectl --v 6 scale deployment api --replicas=2", "command.kubernetes-operations.scale-resources"),
        (
            "helm --kube-tls-server-name cluster.example upgrade api ./chart",
            "command.kubernetes-operations.helm-upgrade",
        ),
    ],
)
def test_documented_aliases_and_global_options_preserve_sensitive_matches(
    command: str,
    rule_id: str,
    tmp_path: Path,
) -> None:
    payload = inspect_command(command, cwd=tmp_path, home_dir=tmp_path)

    assert payload["status"] == "review"
    assert rule_id in {rule["rule_id"] for rule in payload["rules"]}


@pytest.mark.parametrize(
    "command",
    [
        "kubectl apply -f deployment.yaml --dry-run=client",
        "kubectl replace -f deployment.yaml --dry-run=server",
        "kubectl apply -f deployment.yaml --dry-run=none --dry-run=client",
        "helm uninstall api --dry-run=client",
    ],
)
def test_option_value_safe_variants_use_effective_full_argument_value(command: str, tmp_path: Path) -> None:
    payload = inspect_command(command, cwd=tmp_path, home_dir=tmp_path)

    assert payload["status"] == "no_match"

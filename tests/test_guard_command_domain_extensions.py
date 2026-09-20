"""Structured container, cluster, and infrastructure command extension tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from tests.native_command_test_support import (
    extract_sensitive_tool_action_request_native_test as extract_sensitive_tool_action_request,
)
from tests.native_command_test_support import inspect_command_native_test as inspect_command
from tests.native_command_test_support import real_native_command_evaluation


def _rule_ids(payload: dict[str, object]) -> list[str]:
    return [str(item["rule_id"]) for item in payload["rules"]]


_SAFE_VARIANT_RULE_IDS = {
    "command.container-runtime.system-prune",
    "command.container-runtime.forced-container-removal",
    "command.container-runtime.privileged-run",
    "command.kubernetes-operations.delete-resources",
    "command.kubernetes-operations.drain-node",
}


@pytest.mark.parametrize(
    ("command", "action_class", "rule_id"),
    [
        (
            "docker --context local system prune -a --volumes",
            "docker-sensitive command",
            "command.container-runtime.system-prune",
        ),
        (
            "docker container rm --force api",
            "docker-sensitive command",
            "command.container-runtime.forced-container-removal",
        ),
        (
            "docker rm -f api",
            "docker-sensitive command",
            "command.container-runtime.forced-container-removal",
        ),
        (
            "docker container rm -f api",
            "docker-sensitive command",
            "command.container-runtime.forced-container-removal",
        ),
        (
            "docker run --privileged alpine sh",
            "docker-sensitive command",
            "command.container-runtime.privileged-run",
        ),
        (
            "kubectl --context prod delete deployment api",
            "Kubernetes destructive command",
            "command.kubernetes-operations.delete-resources",
        ),
        (
            "kubectl --kubeconfig cluster.yaml drain node-a",
            "Kubernetes destructive command",
            "command.kubernetes-operations.drain-node",
        ),
        (
            "helm --namespace prod uninstall api",
            "Kubernetes destructive command",
            "command.kubernetes-operations.helm-uninstall",
        ),
        (
            "terraform -chdir=infra destroy -auto-approve",
            "infrastructure destructive command",
            "command.infrastructure-as-code.destroy",
        ),
        (
            "tofu apply -destroy -auto-approve",
            "infrastructure destructive command",
            "command.infrastructure-as-code.destroy",
        ),
        (
            "pulumi --stack prod destroy --yes",
            "infrastructure destructive command",
            "command.infrastructure-as-code.destroy",
        ),
    ],
)
def test_domain_rules_feed_inspection_and_runtime_hooks(
    command: str,
    action_class: str,
    rule_id: str,
    tmp_path: Path,
) -> None:
    evaluation = real_native_command_evaluation(command, cwd=tmp_path, home_dir=tmp_path).evaluation

    assert evaluation.matched
    assert evaluation.controlling_action_class == action_class
    assert rule_id in {owned.match.rule.rule_id for owned in evaluation.matches}
    assert evaluation.controlling_rule_id == rule_id
    runtime_match = extract_sensitive_tool_action_request(
        "Shell",
        {"command": command},
        cwd=tmp_path,
        home_dir=tmp_path,
    )
    assert runtime_match is not None
    assert runtime_match.action_class == action_class


@pytest.mark.parametrize(
    "command",
    [
        "docker system prune --help",
        "docker rm --force --help",
        "docker run --privileged --help",
        "kubectl delete deployment api --dry-run=client",
        "kubectl drain node-a --dry-run=server",
        "helm uninstall api --dry-run",
        "terraform plan -destroy",
        "terraform destroy --help",
        "tofu plan -destroy",
        "pulumi preview",
        "pulumi destroy --preview-only",
        "grep 'docker system prune|kubectl delete|terraform destroy' scripts/guard-test",
        "printf '%s\\n' 'kubectl delete namespace prod'",
    ],
)
def test_domain_preview_and_help_commands_remain_safe(command: str, tmp_path: Path) -> None:
    payload = inspect_command(command, cwd=tmp_path, home_dir=tmp_path)

    assert set(_rule_ids(payload)).isdisjoint(_SAFE_VARIANT_RULE_IDS)


@pytest.mark.parametrize(
    "command",
    [
        "kubectl delete deployment api --dry-run=none",
        "kubectl drain node-a --dry-run=none",
    ],
)
def test_kubernetes_dry_run_none_remains_live_execution(command: str, tmp_path: Path) -> None:
    payload = inspect_command(command, cwd=tmp_path, home_dir=tmp_path)

    assert payload["status"] == "review"
    assert payload["classification"]["action_class"] == "Kubernetes destructive command"
    assert (
        extract_sensitive_tool_action_request(
            "Shell",
            {"command": command},
            cwd=tmp_path,
            home_dir=tmp_path,
        )
        is not None
    )


@pytest.mark.parametrize(
    "command",
    [
        "docker system prune --help=false",
        "docker system prune --help --help=false",
        "kubectl delete deployment api --help=false",
        "kubectl delete deployment api --dry-run=client --dry-run=none",
        "kubectl drain node-a --dry-run=server --dry-run=false",
        "helm uninstall api --dry-run=false",
        "helm uninstall api --dry-run --dry-run=false",
        "terraform destroy --help=false",
        "tofu destroy --help --help=false",
        "pulumi destroy --preview-only=false",
        "pulumi destroy --preview-only --preview-only=false",
    ],
)
def test_false_or_overridden_safe_variants_remain_live_execution(command: str, tmp_path: Path) -> None:
    payload = inspect_command(command, cwd=tmp_path, home_dir=tmp_path)

    assert payload["status"] == "review"
    assert (
        extract_sensitive_tool_action_request(
            "Shell",
            {"command": command},
            cwd=tmp_path,
            home_dir=tmp_path,
        )
        is not None
    )


@pytest.mark.parametrize(
    "command",
    [
        "docker system prune --help=true",
        "kubectl delete deployment api --help=true",
        "kubectl delete deployment api --dry-run=none --dry-run=client",
        "helm uninstall api --dry-run=true",
        "terraform destroy --help=true",
        "tofu destroy --help=false --help",
        "pulumi destroy --preview-only=true",
        "pulumi destroy --preview-only=false --preview-only=yes",
    ],
)
def test_truthy_or_effective_safe_variants_remain_quiet(command: str, tmp_path: Path) -> None:
    payload = inspect_command(command, cwd=tmp_path, home_dir=tmp_path)

    assert set(_rule_ids(payload)).isdisjoint(_SAFE_VARIANT_RULE_IDS)


def test_container_argument_named_help_remains_runtime_execution(tmp_path: Path) -> None:
    evaluation = real_native_command_evaluation(
        "docker run alpine --help", cwd=tmp_path, home_dir=tmp_path
    ).evaluation

    assert evaluation.matched
    assert evaluation.controlling_action_class == "docker-sensitive command"


def test_container_short_host_flag_remains_runtime_execution(tmp_path: Path) -> None:
    evaluation = real_native_command_evaluation(
        "docker run -h api.internal alpine", cwd=tmp_path, home_dir=tmp_path
    ).evaluation

    assert evaluation.matched
    assert evaluation.controlling_action_class == "docker-sensitive command"


def test_container_structured_rule_controls_compatibility_evidence(tmp_path: Path) -> None:
    payload = inspect_command("docker system prune --volumes", cwd=tmp_path, home_dir=tmp_path)

    assert set(_rule_ids(payload)) == {
        "command.container-runtime.system-prune",
        "command.container-runtime.docker-sensitive",
    }
    assert payload["controlling_rule_id"] == "command.container-runtime.system-prune"


def test_safe_domain_variant_does_not_hide_destructive_segment(tmp_path: Path) -> None:
    payload = inspect_command(
        "kubectl delete deployment api --dry-run=client && terraform destroy",
        cwd=tmp_path,
        home_dir=tmp_path,
    )

    rule_ids = set(_rule_ids(payload))
    assert "command.infrastructure-as-code.destroy" in rule_ids
    assert "command.kubernetes-operations.delete-resources" not in rule_ids
    assert payload["controlling_rule_id"] == "command.infrastructure-as-code.destroy"


def test_domain_extensions_publish_primary_references() -> None:
    for extension_id in (
        "command.container-runtime",
        "command.kubernetes-secrets",
        "command.kubernetes-operations",
        "command.infrastructure-as-code",
    ):
        extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get(extension_id)

        assert extension is not None
        assert extension.reference_urls
        assert all(url.startswith("https://") for url in extension.reference_urls)

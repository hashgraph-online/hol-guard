"""Structured cloud provider command extension tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.command_extension_matchers import with_required_flag
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.command_inspection import inspect_command
from codex_plugin_scanner.guard.runtime.command_rules import AnyMatcher, ExecutableMatcher
from codex_plugin_scanner.guard.runtime.secret_file_requests import extract_sensitive_tool_action_request


@pytest.mark.parametrize(
    ("command", "action_class", "rule_id"),
    [
        (
            "aws --profile prod --region us-east-1 ec2 terminate-instances --instance-ids i-123",
            "AWS destructive command",
            "command.cloud.aws.resource-deletion",
        ),
        (
            "aws rds delete-db-instance --db-instance-identifier app-db",
            "AWS destructive command",
            "command.cloud.aws.resource-deletion",
        ),
        (
            "aws eks delete-cluster --name app-cluster",
            "AWS destructive command",
            "command.cloud.aws.resource-deletion",
        ),
        (
            "gcloud --project app-prod compute instances delete api-1 --zone us-central1-a --quiet",
            "Google Cloud destructive command",
            "command.cloud.gcp.resource-deletion",
        ),
        (
            "gcloud beta sql instances delete app-db",
            "Google Cloud destructive command",
            "command.cloud.gcp.resource-deletion",
        ),
        (
            "az --subscription app-prod vm delete --resource-group app --name api-1 --yes",
            "Azure destructive command",
            "command.cloud.azure.resource-deletion",
        ),
        (
            "aws.exe ec2 --region us-east-1 terminate-instances --instance-ids i-123",
            "AWS destructive command",
            "command.cloud.aws.resource-deletion",
        ),
        (
            "aws --no-cli-pager ec2 terminate-instances --instance-ids i-123",
            "AWS destructive command",
            "command.cloud.aws.resource-deletion",
        ),
        (
            "aws --no-paginate ec2 terminate-instances --instance-ids i-123",
            "AWS destructive command",
            "command.cloud.aws.resource-deletion",
        ),
        (
            "aws ec2 --cli-auto-prompt terminate-instances --instance-ids i-123",
            "AWS destructive command",
            "command.cloud.aws.resource-deletion",
        ),
        (
            "aws ec2 terminate-instances --no-cli-auto-prompt --instance-ids i-123",
            "AWS destructive command",
            "command.cloud.aws.resource-deletion",
        ),
        (
            "aws --no-color ec2 terminate-instances --instance-ids i-123",
            "AWS destructive command",
            "command.cloud.aws.resource-deletion",
        ),
        (
            "aws -- ec2 terminate-instances --instance-ids i-123",
            "AWS destructive command",
            "command.cloud.aws.resource-deletion",
        ),
        (
            "gcloud.cmd compute --project app-prod instances delete api-1",
            "Google Cloud destructive command",
            "command.cloud.gcp.resource-deletion",
        ),
        (
            "gcloud --quiet compute instances delete api-1",
            "Google Cloud destructive command",
            "command.cloud.gcp.resource-deletion",
        ),
        (
            "gcloud -q compute instances delete api-1",
            "Google Cloud destructive command",
            "command.cloud.gcp.resource-deletion",
        ),
        (
            "gcloud --no-log-http sql instances delete app-db",
            "Google Cloud destructive command",
            "command.cloud.gcp.resource-deletion",
        ),
        (
            "az.cmd vm --subscription app-prod delete --resource-group app --name api-1 --yes",
            "Azure destructive command",
            "command.cloud.azure.resource-deletion",
        ),
        (
            "az --only-show-errors vm delete --resource-group app --name api-1 --yes",
            "Azure destructive command",
            "command.cloud.azure.resource-deletion",
        ),
    ],
)
def test_cloud_rules_feed_inspection_and_runtime_hooks(
    command: str,
    action_class: str,
    rule_id: str,
    tmp_path: Path,
) -> None:
    payload = inspect_command(command, cwd=tmp_path, home_dir=tmp_path)

    assert payload["status"] == "review"
    assert payload["classification"]["action_class"] == action_class
    assert payload["controlling_rule_id"] == rule_id
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
        "aws ec2 terminate-instances --help",
        "aws ec2 terminate-instances --instance-ids i-123 --dry-run",
        "aws rds delete-db-instance --generate-cli-skeleton input",
        "gcloud compute instances delete --help",
        "gcloud preview sql instances delete --help",
        "az vm delete --help",
        "aws ec2 describe-instances --instance-ids i-123",
        "gcloud compute instances describe api-1",
        "az vm show --resource-group app --name api-1",
        "grep 'terminate-instances|instances delete|vm delete' scripts/guard-test",
        "printf '%s\\n' 'aws eks delete-cluster --name app-cluster'",
    ],
)
def test_cloud_help_preview_and_read_commands_remain_safe(command: str, tmp_path: Path) -> None:
    payload = inspect_command(command, cwd=tmp_path, home_dir=tmp_path)

    assert payload["status"] == "no_match"
    assert (
        extract_sensitive_tool_action_request(
            "Shell",
            {"command": command},
            cwd=tmp_path,
            home_dir=tmp_path,
        )
        is None
    )


def test_safe_cloud_variant_does_not_hide_destructive_segment(tmp_path: Path) -> None:
    payload = inspect_command(
        "aws ec2 terminate-instances --dry-run && az vm delete --name api-1 --resource-group app --yes",
        cwd=tmp_path,
        home_dir=tmp_path,
    )

    assert [rule["rule_id"] for rule in payload["rules"]] == ["command.cloud.azure.resource-deletion"]
    assert payload["controlling_rule_id"] == "command.cloud.azure.resource-deletion"


def test_cloud_extensions_publish_primary_references() -> None:
    for extension_id in ("command.cloud.aws", "command.cloud.gcp", "command.cloud.azure"):
        extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get(extension_id)

        assert extension is not None
        assert extension.reference_urls
        assert all(url.startswith("https://") for url in extension.reference_urls)


def test_cloud_safe_variant_rejects_unsupported_matcher_nesting() -> None:
    nested = AnyMatcher(matchers=(AnyMatcher(matchers=(ExecutableMatcher(executables=frozenset({"aws"})),)),))

    with pytest.raises(ValueError, match="executable matcher children"):
        with_required_flag(nested, "--help")

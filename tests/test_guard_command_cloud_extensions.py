"""Structured cloud provider command extension tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.command_extension_matchers import (
    executable_path_set_matcher,
    safe_flag_variant,
    safe_option_variant,
    with_required_flag,
)
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.command_path_set_matcher import ExecutablePathSetMatcher
from codex_plugin_scanner.guard.runtime.command_rules import AnyMatcher, ExecutableMatcher
from tests.command_extension_contracts import assert_reviewed_command_cases, assert_safe_command_cases
from tests.native_command_test_support import (
    extract_sensitive_tool_action_request_native_test as extract_sensitive_tool_action_request,
)
from tests.native_command_test_support import inspect_command_native_test as inspect_command

CLOUD_REVIEW_CASES: tuple[tuple[str, str, str], ...] = (
    (
        "aws --profile prod --region us-east-1 ec2 terminate-instances --instance-ids i-123",
        "AWS destructive command",
        "command.cloud.aws.resource-deletion",
    ),
    (
        "aws --profile=prod ec2 terminate-instances --instance-ids i-123",
        "AWS destructive command",
        "command.cloud.aws.resource-deletion",
    ),
    (
        "aws --future-global-option account ec2 terminate-instances --instance-ids i-123",
        "AWS destructive command",
        "command.cloud.aws.resource-deletion",
    ),
    (
        "aws --future-global-option=account ec2 terminate-instances --instance-ids i-123",
        "AWS destructive command",
        "command.cloud.aws.resource-deletion",
    ),
    (
        "aws --future-global-option --help ec2 terminate-instances --instance-ids i-123",
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
        "gcloud --filter active compute instances delete api-1",
        "Google Cloud destructive command",
        "command.cloud.gcp.resource-deletion",
    ),
    (
        "gcloud --filter=active compute instances delete api-1",
        "Google Cloud destructive command",
        "command.cloud.gcp.resource-deletion",
    ),
    (
        "gcloud --future-global-option --help compute instances delete api-1",
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
        "az --subscription=app-prod vm delete --resource-group app --name api-1 --yes",
        "Azure destructive command",
        "command.cloud.azure.resource-deletion",
    ),
    (
        "az --future-global-option tenant vm delete --resource-group app --name api-1 --yes",
        "Azure destructive command",
        "command.cloud.azure.resource-deletion",
    ),
    (
        "az --future-global-option=tenant vm delete --resource-group app --name api-1 --yes",
        "Azure destructive command",
        "command.cloud.azure.resource-deletion",
    ),
    (
        "az --future-global-option --help vm delete --resource-group app --name api-1 --yes",
        "Azure destructive command",
        "command.cloud.azure.resource-deletion",
    ),
    (
        "aws ec2 terminate-instances --instance-ids i-123 --dry-run --dry-run=false",
        "AWS destructive command",
        "command.cloud.aws.resource-deletion",
    ),
    (
        "gcloud compute instances delete api-1 --help --help=false",
        "Google Cloud destructive command",
        "command.cloud.gcp.resource-deletion",
    ),
    (
        "az vm delete --resource-group app --name api-1 --help --help=false",
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
    (
        "az -otable vm delete --resource-group app --name api-1 --yes",
        "Azure destructive command",
        "command.cloud.azure.resource-deletion",
    ),
    (
        "az vm -otable delete --resource-group app --name api-1 --yes",
        "Azure destructive command",
        "command.cloud.azure.resource-deletion",
    ),
    (
        "az --output table vm delete --resource-group app --name api-1 --yes",
        "Azure destructive command",
        "command.cloud.azure.resource-deletion",
    ),
    (
        "az vm --output table delete --resource-group app --name api-1 --yes",
        "Azure destructive command",
        "command.cloud.azure.resource-deletion",
    ),
)


def test_cloud_rules_feed_inspection_and_runtime_hooks(tmp_path: Path) -> None:
    assert_reviewed_command_cases(CLOUD_REVIEW_CASES, tmp_path)


CLOUD_SAFE_COMMANDS: tuple[str, ...] = (
    "aws ec2 terminate-instances --help",
    "aws ec2 terminate-instances --instance-ids i-123 --dry-run",
    "aws ec2 terminate-instances --instance-ids i-123 --no-dry-run --dry-run",
    "aws ec2 terminate-instances --instance-ids i-123 --no-dry-run=false",
    "aws rds delete-db-instance --generate-cli-skeleton input",
    "aws rds delete-db-instance --generate-cli-skeleton=output",
    "aws rds delete-db-instance --generate-cli-skeleton=yaml-input",
    "aws rds delete-db-instance --generate-cli-skeleton=bogus --generate-cli-skeleton=output",
    "gcloud compute instances delete --help",
    "gcloud preview sql instances delete --help",
    "az vm delete --help",
    "aws --future-global-option account ec2 terminate-instances --instance-ids i-123 --dry-run",
    "gcloud --future-global-option account compute instances delete api-1 --help",
    "az --future-global-option tenant vm delete --resource-group app --name api-1 --help",
    "aws ec2 terminate-instances --instance-ids i-123 --dry-run=false --dry-run",
    "gcloud compute instances delete api-1 --help=false --help",
    "az vm delete --resource-group app --name api-1 --help=false --help",
    "aws ec2 describe-instances --instance-ids i-123",
    "aws --future-global-option account ec2 describe-instances --instance-ids i-123",
    "gcloud compute instances describe api-1",
    "gcloud --filter active compute instances describe api-1",
    "az vm show --resource-group app --name api-1",
    "az --future-global-option tenant vm show --resource-group app --name api-1",
    "grep 'terminate-instances|instances delete|vm delete' scripts/guard-test",
    "printf '%s\\n' 'aws eks delete-cluster --name app-cluster'",
)


def test_cloud_help_preview_and_read_commands_remain_safe(tmp_path: Path) -> None:
    assert_safe_command_cases(CLOUD_SAFE_COMMANDS, tmp_path)


@pytest.mark.parametrize(
    "command",
    [
        "aws ec2 terminate-instances --instance-ids i-123 --dry-run --no-dry-run",
        "aws ec2 terminate-instances --instance-ids i-123 --dry-run=true --no-dry-run=true",
        "aws rds delete-db-instance --generate-cli-skeleton=bogus",
        "aws rds delete-db-instance --generate-cli-skeleton=output --generate-cli-skeleton=bogus",
    ],
)
def test_cloud_disabled_or_invalid_safe_options_remain_live_execution(command: str, tmp_path: Path) -> None:
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
    with pytest.raises(ValueError, match="executable matcher children"):
        safe_option_variant(
            nested,
            variant_id="skeleton",
            title="Request skeleton",
            option="--generate-cli-skeleton",
            allowed_values=frozenset({"output"}),
        )


def test_cloud_safe_option_variant_requires_allowed_values() -> None:
    matcher = AnyMatcher(matchers=(ExecutableMatcher(executables=frozenset({"aws"})),))

    with pytest.raises(ValueError, match="at least one allowed value"):
        safe_option_variant(
            matcher,
            variant_id="skeleton",
            title="Request skeleton",
            option="--generate-cli-skeleton",
            allowed_values=frozenset(),
        )


def test_cloud_safe_variants_clone_path_set_matcher_constraints() -> None:
    matcher = AnyMatcher(
        matchers=(
            executable_path_set_matcher(
                "kubectl",
                (("delete", "pod"),),
                global_options_with_values=frozenset({"--context"}),
                global_flags=frozenset({"--quiet"}),
                fail_secure_unknown_options=True,
            ),
        )
    )
    flag_variant = safe_flag_variant(
        matcher,
        variant_id="dry-run",
        title="Dry run",
        flag="--dry-run",
        inverse_flag="--no-dry-run",
    )
    option_variant = safe_option_variant(
        flag_variant.matcher,
        variant_id="output-name",
        title="Output name",
        option="--output",
        allowed_values=frozenset({"name"}),
    )

    cloned, = option_variant.matcher.matchers

    assert isinstance(cloned, ExecutablePathSetMatcher)
    assert cloned.paths == frozenset({("delete", "pod")})
    assert cloned.required_flags == frozenset({"--dry-run"})
    assert cloned.inverse_flag_pairs == frozenset({("--dry-run", "--no-dry-run")})
    assert cloned.interspersed_options_with_values == frozenset({"--context"})
    assert cloned.interspersed_flags == frozenset({"--quiet"})
    assert cloned.options_with_values == frozenset({"--output"})
    assert cloned.required_option_values == (("--output", frozenset({"name"})),)
    assert cloned.required_flags_in_all_arguments is True
    assert cloned.fail_secure_unknown_options is True

"""Structured rules and metadata for cloud provider command extensions."""

from __future__ import annotations

from .command_extension_matchers import executable_matcher, safe_flag_variant, safe_option_variant
from .command_extension_specs import CommandExtensionSpec
from .command_rules import AnyMatcher, CommandSafetyRule, CommandSafeVariant

_AWS_GLOBAL_OPTIONS = frozenset(
    {
        "--ca-bundle",
        "--cli-connect-timeout",
        "--cli-binary-format",
        "--cli-read-timeout",
        "--color",
        "--endpoint-url",
        "--output",
        "--profile",
        "--query",
        "--region",
    }
)
_AWS_GLOBAL_FLAGS = frozenset(
    {
        "--cli-auto-prompt",
        "--debug",
        "--no-cli-auto-prompt",
        "--no-cli-pager",
        "--no-color",
        "--no-paginate",
        "--no-sign-request",
        "--no-verify-ssl",
    }
)
_GCLOUD_GLOBAL_OPTIONS = frozenset(
    {
        "--access-token-file",
        "--account",
        "--billing-project",
        "--configuration",
        "--flags-file",
        "--format",
        "--impersonate-service-account",
        "--project",
        "--trace-token",
        "--verbosity",
    }
)
_GCLOUD_GLOBAL_FLAGS = frozenset(
    {
        "--help",
        "--log-http",
        "--no-log-http",
        "--quiet",
        "-q",
        "--user-output-enabled",
        "--no-user-output-enabled",
    }
)
_AZURE_GLOBAL_OPTIONS = frozenset({"--output", "-o", "--query", "--subscription"})
_AZURE_GLOBAL_FLAGS = frozenset({"--debug", "--only-show-errors", "--verbose"})
_AWS_RESOURCE_DELETE = AnyMatcher(
    matchers=(
        executable_matcher(
            "aws",
            "ec2",
            "terminate-instances",
            global_options_with_values=_AWS_GLOBAL_OPTIONS,
            global_flags=_AWS_GLOBAL_FLAGS,
        ),
        executable_matcher(
            "aws",
            "rds",
            "delete-db-instance",
            global_options_with_values=_AWS_GLOBAL_OPTIONS,
            global_flags=_AWS_GLOBAL_FLAGS,
        ),
        executable_matcher(
            "aws",
            "rds",
            "delete-db-cluster",
            global_options_with_values=_AWS_GLOBAL_OPTIONS,
            global_flags=_AWS_GLOBAL_FLAGS,
        ),
        executable_matcher(
            "aws",
            "eks",
            "delete-cluster",
            global_options_with_values=_AWS_GLOBAL_OPTIONS,
            global_flags=_AWS_GLOBAL_FLAGS,
        ),
    )
)
_AWS_EC2_TERMINATE = AnyMatcher(
    matchers=(
        executable_matcher(
            "aws",
            "ec2",
            "terminate-instances",
            global_options_with_values=_AWS_GLOBAL_OPTIONS,
            global_flags=_AWS_GLOBAL_FLAGS,
        ),
    )
)
_GCLOUD_RESOURCE_DELETE = AnyMatcher(
    matchers=(
        *(
            executable_matcher(
                "gcloud",
                *track,
                *operation,
                global_options_with_values=_GCLOUD_GLOBAL_OPTIONS,
                global_flags=_GCLOUD_GLOBAL_FLAGS,
            )
            for track in ((), ("alpha",), ("beta",), ("preview",))
            for operation in (("compute", "instances", "delete"),)
        ),
        *(
            executable_matcher(
                "gcloud",
                *track,
                "sql",
                "instances",
                "delete",
                global_options_with_values=_GCLOUD_GLOBAL_OPTIONS,
                global_flags=_GCLOUD_GLOBAL_FLAGS,
            )
            for track in ((), ("alpha",), ("beta",))
        ),
    )
)
_AZURE_RESOURCE_DELETE = AnyMatcher(
    matchers=(
        executable_matcher(
            "az",
            "vm",
            "delete",
            global_options_with_values=_AZURE_GLOBAL_OPTIONS,
            global_flags=_AZURE_GLOBAL_FLAGS,
        ),
    )
)


def _cloud_delete_rule(
    *,
    rule_id: str,
    title: str,
    description: str,
    matcher: AnyMatcher,
    action_class: str,
    safer_alternative: str,
    safe_variants: tuple[CommandSafeVariant, ...],
) -> CommandSafetyRule:
    return CommandSafetyRule(
        rule_id=rule_id,
        title=title,
        description=description,
        severity="critical",
        risk_classes=("destructive_shell", "network_egress"),
        action_classes=(action_class,),
        safer_alternatives=(safer_alternative,),
        matcher=matcher,
        safe_variants=safe_variants,
    )


CLOUD_COMMAND_RULES = (
    _cloud_delete_rule(
        rule_id="command.cloud.aws.resource-deletion",
        title="AWS resource deletion",
        description="Identifies termination or deletion of compute, database, and cluster resources through AWS CLI.",
        matcher=_AWS_RESOURCE_DELETE,
        action_class="AWS destructive command",
        safer_alternative="Describe the exact resources and confirm the active account and region before deletion.",
        safe_variants=(
            safe_flag_variant(_AWS_RESOURCE_DELETE, variant_id="help", title="AWS command help", flag="--help"),
            safe_option_variant(
                _AWS_RESOURCE_DELETE,
                variant_id="generate-cli-skeleton",
                title="AWS request skeleton",
                option="--generate-cli-skeleton",
                allowed_values=frozenset({"input", "output", "yaml-input"}),
            ),
            safe_flag_variant(
                _AWS_EC2_TERMINATE,
                variant_id="dry-run",
                title="EC2 termination permission check",
                flag="--dry-run",
                inverse_flag="--no-dry-run",
            ),
        ),
    ),
    _cloud_delete_rule(
        rule_id="command.cloud.gcp.resource-deletion",
        title="Google Cloud resource deletion",
        description="Identifies deletion of compute and database resources through Google Cloud CLI.",
        matcher=_GCLOUD_RESOURCE_DELETE,
        action_class="Google Cloud destructive command",
        safer_alternative="Describe the exact resources and confirm the active project and location before deletion.",
        safe_variants=(
            safe_flag_variant(
                _GCLOUD_RESOURCE_DELETE,
                variant_id="help",
                title="Google Cloud command help",
                flag="--help",
            ),
        ),
    ),
    _cloud_delete_rule(
        rule_id="command.cloud.azure.resource-deletion",
        title="Azure resource deletion",
        description="Identifies deletion of virtual machines through Azure CLI.",
        matcher=_AZURE_RESOURCE_DELETE,
        action_class="Azure destructive command",
        safer_alternative=(
            "Show the exact resource and confirm the active subscription and resource group before deletion."
        ),
        safe_variants=(
            safe_flag_variant(
                _AZURE_RESOURCE_DELETE,
                variant_id="help",
                title="Azure command help",
                flag="--help",
            ),
        ),
    ),
)


CLOUD_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.cloud.aws",
        name="AWS command protection",
        description="Reviews AWS CLI operations that permanently delete compute, database, or cluster resources.",
        action_classes=("AWS destructive command",),
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternatives=("Inspect resource state, account, region, and recovery options before deletion.",),
        reference_urls=(
            "https://docs.aws.amazon.com/cli/latest/reference/ec2/terminate-instances.html",
            "https://docs.aws.amazon.com/cli/latest/reference/rds/delete-db-instance.html",
            "https://docs.aws.amazon.com/cli/latest/reference/rds/delete-db-cluster.html",
            "https://docs.aws.amazon.com/cli/latest/reference/eks/delete-cluster.html",
        ),
    ),
    CommandExtensionSpec(
        extension_id="command.cloud.gcp",
        name="Google Cloud command protection",
        description="Reviews Google Cloud CLI operations that permanently delete compute or database resources.",
        action_classes=("Google Cloud destructive command",),
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternatives=("Inspect resource state, project, location, and recovery options before deletion.",),
        reference_urls=(
            "https://cloud.google.com/sdk/gcloud/reference/compute/instances/delete",
            "https://cloud.google.com/sdk/gcloud/reference/sql/instances/delete",
        ),
    ),
    CommandExtensionSpec(
        extension_id="command.cloud.azure",
        name="Azure command protection",
        description="Reviews Azure CLI operations that permanently delete virtual machines.",
        action_classes=("Azure destructive command",),
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternatives=("Inspect resource state, subscription, resource group, and attached resources first.",),
        reference_urls=("https://learn.microsoft.com/cli/azure/vm#az-vm-delete",),
    ),
)

"""Structured rules and metadata for object-storage command extensions."""

from __future__ import annotations

from .command_extension_matchers import executable_matcher, safe_flag_variant
from .command_extension_specs import CommandExtensionSpec
from .command_rules import AnyMatcher, CommandSafetyRule, CommandSafeVariant

_AWS_GLOBAL_OPTIONS = frozenset(
    {
        "--ca-bundle",
        "--cli-binary-format",
        "--cli-connect-timeout",
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
        "--filter",
        "--flags-file",
        "--flatten",
        "--format",
        "--impersonate-service-account",
        "--limit",
        "--page-size",
        "--project",
        "--sort-by",
        "--trace-token",
        "--verbosity",
    }
)
_GCLOUD_GLOBAL_FLAGS = frozenset(
    {
        "--help",
        "--log-http",
        "--no-log-http",
        "--no-user-output-enabled",
        "--quiet",
        "--user-output-enabled",
        "-q",
    }
)
_AZURE_GLOBAL_OPTIONS = frozenset({"--output", "-o", "--query", "--subscription"})
_AZURE_GLOBAL_FLAGS = frozenset({"--debug", "--only-show-errors", "--verbose"})
_MINIO_GLOBAL_OPTIONS = frozenset({"--config-dir", "-C", "--custom-header", "-H", "--resolve"})
_MINIO_GLOBAL_FLAGS = frozenset(
    {"--debug", "--disable-pager", "--dp", "--dtrace", "--insecure", "--json", "--no-color", "--quiet"}
)

_AWS_STORAGE_DELETE = AnyMatcher(
    matchers=(
        executable_matcher(
            "aws",
            "s3",
            "rm",
            global_options_with_values=_AWS_GLOBAL_OPTIONS,
            global_flags=_AWS_GLOBAL_FLAGS,
            fail_secure_unknown_options=True,
        ),
        executable_matcher(
            "aws",
            "s3",
            "rb",
            global_options_with_values=_AWS_GLOBAL_OPTIONS,
            global_flags=_AWS_GLOBAL_FLAGS,
            fail_secure_unknown_options=True,
        ),
        executable_matcher(
            "aws",
            "s3",
            "sync",
            required_flags=frozenset({"--delete"}),
            global_options_with_values=_AWS_GLOBAL_OPTIONS,
            global_flags=_AWS_GLOBAL_FLAGS,
            fail_secure_unknown_options=True,
        ),
        executable_matcher(
            "aws",
            "s3api",
            "delete-object",
            global_options_with_values=_AWS_GLOBAL_OPTIONS,
            global_flags=_AWS_GLOBAL_FLAGS,
            fail_secure_unknown_options=True,
        ),
        executable_matcher(
            "aws",
            "s3api",
            "delete-objects",
            global_options_with_values=_AWS_GLOBAL_OPTIONS,
            global_flags=_AWS_GLOBAL_FLAGS,
            fail_secure_unknown_options=True,
        ),
        executable_matcher(
            "aws",
            "s3api",
            "delete-bucket",
            global_options_with_values=_AWS_GLOBAL_OPTIONS,
            global_flags=_AWS_GLOBAL_FLAGS,
            fail_secure_unknown_options=True,
        ),
    )
)
_AWS_STORAGE_DRY_RUN = AnyMatcher(
    matchers=(
        executable_matcher(
            "aws",
            "s3",
            "rm",
            global_options_with_values=_AWS_GLOBAL_OPTIONS,
            global_flags=_AWS_GLOBAL_FLAGS,
            fail_secure_unknown_options=True,
        ),
        executable_matcher(
            "aws",
            "s3",
            "sync",
            required_flags=frozenset({"--delete"}),
            global_options_with_values=_AWS_GLOBAL_OPTIONS,
            global_flags=_AWS_GLOBAL_FLAGS,
            fail_secure_unknown_options=True,
        ),
    )
)
_GCS_STORAGE_DELETE = AnyMatcher(
    matchers=(
        executable_matcher(
            "gcloud",
            "storage",
            "rm",
            global_options_with_values=_GCLOUD_GLOBAL_OPTIONS,
            global_flags=_GCLOUD_GLOBAL_FLAGS,
            fail_secure_unknown_options=True,
        ),
        executable_matcher(
            "gcloud",
            "storage",
            "buckets",
            "delete",
            global_options_with_values=_GCLOUD_GLOBAL_OPTIONS,
            global_flags=_GCLOUD_GLOBAL_FLAGS,
            fail_secure_unknown_options=True,
        ),
        executable_matcher(
            "gcloud",
            "storage",
            "rsync",
            required_flags=frozenset({"--delete-unmatched-destination-objects"}),
            global_options_with_values=_GCLOUD_GLOBAL_OPTIONS,
            global_flags=_GCLOUD_GLOBAL_FLAGS,
            fail_secure_unknown_options=True,
        ),
        executable_matcher("gsutil", "rm", allow_leading_options=True, leading_options_with_values=frozenset({"-o"})),
        executable_matcher(
            "gsutil",
            "rsync",
            required_flags=frozenset({"-d"}),
            allow_leading_options=True,
            leading_options_with_values=frozenset({"-o"}),
        ),
    )
)
_GCLOUD_RSYNC_DELETE = AnyMatcher(
    matchers=(
        executable_matcher(
            "gcloud",
            "storage",
            "rsync",
            required_flags=frozenset({"--delete-unmatched-destination-objects"}),
            global_options_with_values=_GCLOUD_GLOBAL_OPTIONS,
            global_flags=_GCLOUD_GLOBAL_FLAGS,
            fail_secure_unknown_options=True,
        ),
    )
)
_GSUTIL_RSYNC_DELETE = AnyMatcher(
    matchers=(
        executable_matcher(
            "gsutil",
            "rsync",
            required_flags=frozenset({"-d"}),
            allow_leading_options=True,
            leading_options_with_values=frozenset({"-o"}),
        ),
    )
)
_AZURE_STORAGE_DELETE = AnyMatcher(
    matchers=(
        executable_matcher(
            "az",
            "storage",
            "blob",
            "delete",
            global_options_with_values=_AZURE_GLOBAL_OPTIONS,
            global_flags=_AZURE_GLOBAL_FLAGS,
            fail_secure_unknown_options=True,
        ),
        executable_matcher(
            "az",
            "storage",
            "blob",
            "delete-batch",
            global_options_with_values=_AZURE_GLOBAL_OPTIONS,
            global_flags=_AZURE_GLOBAL_FLAGS,
            fail_secure_unknown_options=True,
        ),
        executable_matcher(
            "az",
            "storage",
            "container",
            "delete",
            global_options_with_values=_AZURE_GLOBAL_OPTIONS,
            global_flags=_AZURE_GLOBAL_FLAGS,
            fail_secure_unknown_options=True,
        ),
    )
)
_AZURE_BATCH_DELETE = AnyMatcher(
    matchers=(
        executable_matcher(
            "az",
            "storage",
            "blob",
            "delete-batch",
            global_options_with_values=_AZURE_GLOBAL_OPTIONS,
            global_flags=_AZURE_GLOBAL_FLAGS,
            fail_secure_unknown_options=True,
        ),
    )
)
_MINIO_STORAGE_DELETE = AnyMatcher(
    matchers=(
        executable_matcher(
            "mc", "rm", global_options_with_values=_MINIO_GLOBAL_OPTIONS, global_flags=_MINIO_GLOBAL_FLAGS
        ),
        executable_matcher(
            "mc", "rb", global_options_with_values=_MINIO_GLOBAL_OPTIONS, global_flags=_MINIO_GLOBAL_FLAGS
        ),
        executable_matcher(
            "mc",
            "mirror",
            required_flags=frozenset({"--remove"}),
            global_options_with_values=_MINIO_GLOBAL_OPTIONS,
            global_flags=_MINIO_GLOBAL_FLAGS,
        ),
    )
)


def _storage_rule(
    *,
    rule_id: str,
    title: str,
    description: str,
    matcher: AnyMatcher,
    action_class: str,
    safe_variants: tuple[CommandSafeVariant, ...],
) -> CommandSafetyRule:
    return CommandSafetyRule(
        rule_id=rule_id,
        title=title,
        description=description,
        severity="critical",
        risk_classes=("destructive_shell", "network_egress"),
        action_classes=(action_class,),
        safer_alternatives=("List the exact objects and confirm retention or recovery controls before deletion.",),
        matcher=matcher,
        safe_variants=safe_variants,
    )


STORAGE_COMMAND_RULES = (
    _storage_rule(
        rule_id="command.storage.aws-s3.deletion",
        title="Amazon S3 deletion",
        description="Identifies object, bucket, and delete-enabled synchronization operations through AWS CLI.",
        matcher=_AWS_STORAGE_DELETE,
        action_class="AWS storage destructive command",
        safe_variants=(
            safe_flag_variant(_AWS_STORAGE_DELETE, variant_id="help", title="AWS storage command help", flag="--help"),
            safe_flag_variant(_AWS_STORAGE_DRY_RUN, variant_id="dry-run", title="AWS S3 dry run", flag="--dryrun"),
        ),
    ),
    _storage_rule(
        rule_id="command.storage.google-cloud.deletion",
        title="Google Cloud Storage deletion",
        description="Identifies object, bucket, and delete-enabled synchronization operations through Google CLIs.",
        matcher=_GCS_STORAGE_DELETE,
        action_class="Google storage destructive command",
        safe_variants=(
            safe_flag_variant(
                _GCS_STORAGE_DELETE, variant_id="help", title="Google storage command help", flag="--help"
            ),
            safe_flag_variant(
                _GCLOUD_RSYNC_DELETE,
                variant_id="dry-run",
                title="Google storage sync dry run",
                flag="--dry-run",
            ),
            safe_flag_variant(_GSUTIL_RSYNC_DELETE, variant_id="no-act", title="gsutil sync no-act", flag="-n"),
        ),
    ),
    _storage_rule(
        rule_id="command.storage.azure-blob.deletion",
        title="Azure Blob Storage deletion",
        description="Identifies blob, batch, and container deletion operations through Azure CLI.",
        matcher=_AZURE_STORAGE_DELETE,
        action_class="Azure storage destructive command",
        safe_variants=(
            safe_flag_variant(
                _AZURE_STORAGE_DELETE, variant_id="help", title="Azure storage command help", flag="--help"
            ),
            safe_flag_variant(
                _AZURE_BATCH_DELETE, variant_id="dry-run", title="Azure blob batch dry run", flag="--dryrun"
            ),
        ),
    ),
    _storage_rule(
        rule_id="command.storage.minio.deletion",
        title="MinIO object deletion",
        description="Identifies object, bucket, and remove-enabled mirror operations through MinIO Client.",
        matcher=_MINIO_STORAGE_DELETE,
        action_class="MinIO storage destructive command",
        safe_variants=(
            safe_flag_variant(_MINIO_STORAGE_DELETE, variant_id="help", title="MinIO command help", flag="--help"),
        ),
    ),
)


STORAGE_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.storage.aws-s3",
        name="Amazon S3 command protection",
        description="Reviews AWS CLI operations that delete objects or buckets.",
        action_classes=("AWS storage destructive command",),
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternatives=("List matching objects and inspect bucket recovery controls before deletion.",),
        reference_urls=(
            "https://docs.aws.amazon.com/cli/latest/reference/s3/rm.html",
            "https://docs.aws.amazon.com/cli/latest/reference/s3/sync.html",
            "https://docs.aws.amazon.com/cli/latest/reference/s3api/delete-objects.html",
        ),
    ),
    CommandExtensionSpec(
        extension_id="command.storage.google-cloud",
        name="Google Cloud Storage command protection",
        description="Reviews Google CLI operations that delete objects or buckets.",
        action_classes=("Google storage destructive command",),
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternatives=("List matching objects and inspect retention controls before deletion.",),
        reference_urls=(
            "https://cloud.google.com/sdk/gcloud/reference/storage/rm",
            "https://cloud.google.com/sdk/gcloud/reference/storage/rsync",
        ),
    ),
    CommandExtensionSpec(
        extension_id="command.storage.azure-blob",
        name="Azure Blob Storage command protection",
        description="Reviews Azure CLI operations that delete blobs or containers.",
        action_classes=("Azure storage destructive command",),
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternatives=("List matching blobs and inspect soft-delete controls before deletion.",),
        reference_urls=("https://learn.microsoft.com/cli/azure/storage/blob",),
    ),
    CommandExtensionSpec(
        extension_id="command.storage.minio",
        name="MinIO command protection",
        description="Reviews MinIO Client operations that delete objects or buckets.",
        action_classes=("MinIO storage destructive command",),
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternatives=("List matching objects and confirm versioning or recovery controls before deletion.",),
        reference_urls=(
            "https://docs.min.io/community/minio-object-store/reference/minio-mc/mc-rm.html",
            "https://docs.min.io/community/minio-object-store/reference/minio-mc/mc-mirror.html",
        ),
    ),
)

"""Structured rules and metadata for object-storage command extensions."""

from __future__ import annotations

from .command_extension_matchers import executable_matcher, safe_flag_variant, safe_option_variant
from .command_extension_specs import CommandExtensionSpec
from .command_rules import AnyMatcher, CommandRuleMode, CommandRuleSeverity, CommandSafetyRule, CommandSafeVariant

_AWS_OPT = frozenset(
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
_AWS_FLAGS = frozenset(
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
_GCLOUD_OPT = frozenset(
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
_GCLOUD_FLAGS = frozenset(
    {"--help", "--log-http", "--no-log-http", "--no-user-output-enabled", "--quiet", "--user-output-enabled", "-q"}
)
_AZ_OPT = frozenset({"--output", "-o", "--query", "--subscription"})
_AZ_FLAGS = frozenset({"--debug", "--only-show-errors", "--verbose"})
_MC_OPT = frozenset({"--config-dir", "-C", "--custom-header", "-H", "--resolve"})
_MC_FLAGS = frozenset(
    {"--debug", "--disable-pager", "--dp", "--dtrace", "--insecure", "--json", "--no-color", "--quiet"}
)
_NONE: frozenset[str] = frozenset()
_AWS_SKELETON_VALUES = frozenset({"input", "output", "yaml-input"})
_WRITE = "Inspect the destination and confirm overwrite or versioning controls first."
_READ = "Listing or reading objects does not change stored data."
_DELETE = "List the exact objects and confirm retention or recovery controls before deletion."


def _exe(
    name: str,
    *subs: str,
    required: frozenset[str] = _NONE,
    forbidden: frozenset[str] = _NONE,
    options: frozenset[str],
    flags: frozenset[str],
    fail_secure: bool = True,
    leading: frozenset[str] | None = None,
) -> AnyMatcher:
    return AnyMatcher(
        matchers=(
            executable_matcher(
                name,
                *subs,
                required_flags=required,
                forbidden_flags=forbidden,
                global_options_with_values=options,
                global_flags=flags,
                fail_secure_unknown_options=fail_secure,
                allow_leading_options=leading is not None,
                leading_options_with_values=leading or _NONE,
            ),
        )
    )


def _aws(*subs: str, required: frozenset[str] = _NONE, forbidden: frozenset[str] = _NONE) -> AnyMatcher:
    return _exe("aws", *subs, required=required, forbidden=forbidden, options=_AWS_OPT, flags=_AWS_FLAGS)


def _gcloud(*subs: str, required: frozenset[str] = _NONE, forbidden: frozenset[str] = _NONE) -> AnyMatcher:
    return _exe("gcloud", *subs, required=required, forbidden=forbidden, options=_GCLOUD_OPT, flags=_GCLOUD_FLAGS)


def _az(*subs: str) -> AnyMatcher:
    return _exe("az", *subs, options=_AZ_OPT, flags=_AZ_FLAGS)


def _mc(*subs: str, required: frozenset[str] = _NONE, forbidden: frozenset[str] = _NONE) -> AnyMatcher:
    return _exe(
        "mc", *subs, required=required, forbidden=forbidden, options=_MC_OPT, flags=_MC_FLAGS, fail_secure=False
    )


def _gsutil(*subs: str, required: frozenset[str] = _NONE) -> AnyMatcher:
    return _exe(
        "gsutil", *subs, required=required, options=_NONE, flags=_NONE, fail_secure=False, leading=frozenset({"-o"})
    )


def _join(*groups: AnyMatcher) -> AnyMatcher:
    return AnyMatcher(matchers=tuple(child for group in groups for child in group.matchers))


def _s3api(*operations: str) -> AnyMatcher:
    return _join(*(_aws("s3api", operation) for operation in operations))


_AWS_DELETE = _join(
    _aws("s3", "rm"),
    _aws("s3", "rb"),
    _aws("s3", "sync", required=frozenset({"--delete"})),
    _s3api(
        "abort-multipart-upload",
        "delete-bucket",
        "delete-bucket-analytics-configuration",
        "delete-bucket-cors",
        "delete-bucket-encryption",
        "delete-bucket-intelligent-tiering-configuration",
        "delete-bucket-inventory-configuration",
        "delete-bucket-lifecycle",
        "delete-bucket-metadata-configuration",
        "delete-bucket-metadata-table-configuration",
        "delete-bucket-metrics-configuration",
        "delete-bucket-ownership-controls",
        "delete-bucket-policy",
        "delete-bucket-replication",
        "delete-bucket-tagging",
        "delete-bucket-website",
        "delete-object",
        "delete-object-annotation",
        "delete-object-tagging",
        "delete-objects",
        "delete-public-access-block",
    ),
)
_AWS_DRY = _join(_aws("s3", "rm"), _aws("s3", "sync", required=frozenset({"--delete"})))
_AWS_OBJECT_WRITE = _s3api(
    "complete-multipart-upload",
    "copy-object",
    "create-multipart-upload",
    "put-object",
    "rename-object",
    "restore-object",
    "update-object-encryption",
    "upload-part",
    "upload-part-copy",
    "write-get-object-response",
)
_AWS_ACCESS_CONTROL = _s3api(
    "put-bucket-abac",
    "put-bucket-acl",
    "put-bucket-policy",
    "put-object-acl",
    "put-object-legal-hold",
    "put-object-lock-configuration",
    "put-object-retention",
    "put-public-access-block",
)
_AWS_BUCKET_CONFIG = _s3api(
    "create-bucket-metadata-configuration",
    "create-bucket-metadata-table-configuration",
    "put-bucket-accelerate-configuration",
    "put-bucket-analytics-configuration",
    "put-bucket-cors",
    "put-bucket-encryption",
    "put-bucket-intelligent-tiering-configuration",
    "put-bucket-inventory-configuration",
    "put-bucket-lifecycle",
    "put-bucket-lifecycle-configuration",
    "put-bucket-logging",
    "put-bucket-metrics-configuration",
    "put-bucket-notification-configuration",
    "put-bucket-ownership-controls",
    "put-bucket-replication",
    "put-bucket-request-payment",
    "put-bucket-tagging",
    "put-bucket-versioning",
    "put-bucket-website",
    "update-bucket-metadata-inventory-table-configuration",
    "update-bucket-metadata-journal-table-configuration",
)
_AWS_OBJECT_TAGGING = _s3api("put-object-annotation", "put-object-tagging")
_AWS_LIST = _join(
    _aws("s3", "ls"),
    _s3api(
        "list-buckets",
        "list-directory-buckets",
        "list-multipart-uploads",
        "list-object-versions",
        "list-objects",
        "list-objects-v2",
        "list-parts",
    ),
)
_AWS_GET = _s3api(
    "get-bucket-acl",
    "get-bucket-policy",
    "get-object",
    "get-object-acl",
    "get-public-access-block",
    "head-bucket",
    "head-object",
)
_GCS_DELETE = _join(
    _gcloud("storage", "rm"),
    _gcloud("storage", "buckets", "delete"),
    _gcloud("storage", "rsync", required=frozenset({"--delete-unmatched-destination-objects"})),
    _gsutil("rm"),
    _gsutil("rsync", required=frozenset({"-d"})),
)
_GCS_RSYNC_DEL = _gcloud("storage", "rsync", required=frozenset({"--delete-unmatched-destination-objects"}))
_GSUTIL_RSYNC_DEL = _gsutil("rsync", required=frozenset({"-d"}))
_AZ_DELETE = _join(
    _az("storage", "blob", "delete"),
    _az("storage", "blob", "delete-batch"),
    _az("storage", "container", "delete"),
)
_AZ_BATCH = _az("storage", "blob", "delete-batch")
_MC_DELETE = _join(_mc("rm"), _mc("rb"), _mc("mirror", required=frozenset({"--remove"})))


def _rule(
    rule_id: str,
    title: str,
    matcher: AnyMatcher | None,
    action: str,
    family: str,
    *,
    mode: CommandRuleMode = "review",
    severity: CommandRuleSeverity = "high",
    safer: str = _WRITE,
    extra_safe: tuple[CommandSafeVariant, ...] = (),
    dry: tuple[AnyMatcher, str, str | None] | None = None,
    example: str | None = None,
) -> CommandSafetyRule:
    variants: list[CommandSafeVariant] = []
    if matcher is not None:
        variants.append(safe_flag_variant(matcher, variant_id="help", title=f"{title} help", flag="--help"))
        if dry is not None:
            dry_matcher, flag, inverse = dry
            variants.append(
                safe_flag_variant(
                    dry_matcher, variant_id="dry-run", title=f"{title} dry run", flag=flag, inverse_flag=inverse
                )
            )
        if family == "aws-s3":
            variants.append(
                safe_option_variant(
                    matcher,
                    variant_id="generate-cli-skeleton",
                    title=f"{title} request skeleton",
                    option="--generate-cli-skeleton",
                    allowed_values=_AWS_SKELETON_VALUES,
                )
            )
        variants.extend(extra_safe)
    return CommandSafetyRule(
        rule_id=rule_id,
        title=title,
        description=f"Identifies {title.lower()} operations.",
        severity=severity,
        risk_classes=("network_egress",) if mode == "disabled" else ("destructive_shell", "network_egress"),
        action_classes=(action,),
        safer_alternatives=(safer,),
        matcher=matcher,
        default_mode=mode,
        family=family,
        example_command=example,
        safe_variants=tuple(variants),
    )


_AWS = "command.storage.aws-s3"
_GCS = "command.storage.google-cloud"
_AZURE = "command.storage.azure-blob"
_MINIO = "command.storage.minio"
_AWS_ACT = "AWS storage destructive command"
_GCS_ACT = "Google storage destructive command"
_AZ_ACT = "Azure storage destructive command"
_MC_ACT = "MinIO storage destructive command"

_AWS_SYNC = _aws("s3", "sync", forbidden=frozenset({"--delete"}))
_GCS_RSYNC = _gcloud("storage", "rsync", forbidden=frozenset({"--delete-unmatched-destination-objects"}))
_GCS_FAMILY = "google-cloud-storage"

STORAGE_COMMAND_RULES = (
    _rule(
        f"{_AWS}.deletion",
        "Amazon S3 deletion",
        _AWS_DELETE,
        _AWS_ACT,
        "aws-s3",
        severity="critical",
        safer=_DELETE,
        dry=(_AWS_DRY, "--dryrun", "--no-dryrun"),
    ),
    _rule(
        f"{_AWS}.cp",
        "Amazon S3 copy",
        _aws("s3", "cp"),
        _AWS_ACT,
        "aws-s3",
        dry=(_aws("s3", "cp"), "--dryrun", "--no-dryrun"),
    ),
    _rule(
        f"{_AWS}.ls",
        "Amazon S3 list",
        _AWS_LIST,
        _AWS_ACT,
        "aws-s3",
        mode="disabled",
        severity="low",
        safer=_READ,
        example="aws s3 ls",
    ),
    _rule(
        f"{_AWS}.mb",
        "Amazon S3 make bucket",
        _join(_aws("s3", "mb"), _aws("s3api", "create-bucket")),
        _AWS_ACT,
        "aws-s3",
    ),
    _rule(
        f"{_AWS}.mv",
        "Amazon S3 move",
        _aws("s3", "mv"),
        _AWS_ACT,
        "aws-s3",
        dry=(_aws("s3", "mv"), "--dryrun", "--no-dryrun"),
    ),
    _rule(
        f"{_AWS}.presign",
        "Amazon S3 presign",
        _aws("s3", "presign"),
        _AWS_ACT,
        "aws-s3",
        safer="Inspect the object and expiry before sharing a pre-signed URL.",
    ),
    _rule(f"{_AWS}.sync", "Amazon S3 sync", _AWS_SYNC, _AWS_ACT, "aws-s3", dry=(_AWS_SYNC, "--dryrun", "--no-dryrun")),
    _rule(f"{_AWS}.website", "Amazon S3 website", _aws("s3", "website"), _AWS_ACT, "aws-s3"),
    _rule(
        f"{_AWS}.object-write",
        "Amazon S3 object write",
        _AWS_OBJECT_WRITE,
        _AWS_ACT,
        "aws-s3",
        example="aws s3api put-object",
    ),
    _rule(
        f"{_AWS}.access-control",
        "Amazon S3 access control",
        _AWS_ACCESS_CONTROL,
        _AWS_ACT,
        "aws-s3",
        severity="critical",
        safer="Inspect the bucket policy, ACL, and public-access block before changing access.",
        example="aws s3api put-bucket-policy",
    ),
    _rule(
        f"{_AWS}.bucket-configuration",
        "Amazon S3 bucket configuration",
        _AWS_BUCKET_CONFIG,
        _AWS_ACT,
        "aws-s3",
        example="aws s3api put-bucket-versioning",
    ),
    _rule(
        f"{_AWS}.object-tagging",
        "Amazon S3 object tagging",
        _AWS_OBJECT_TAGGING,
        _AWS_ACT,
        "aws-s3",
        example="aws s3api put-object-tagging",
    ),
    _rule(
        f"{_AWS}.get",
        "Amazon S3 object and bucket reads",
        _AWS_GET,
        _AWS_ACT,
        "aws-s3",
        mode="disabled",
        severity="low",
        safer=_READ,
        example="aws s3api get-object",
    ),
    _rule(
        f"{_GCS}.deletion",
        "Google Cloud Storage deletion",
        _GCS_DELETE,
        _GCS_ACT,
        _GCS_FAMILY,
        severity="critical",
        safer=_DELETE,
        extra_safe=(
            safe_flag_variant(
                _GCS_RSYNC_DEL, variant_id="dry-run", title="Google storage sync dry run", flag="--dry-run"
            ),
            safe_flag_variant(_GSUTIL_RSYNC_DEL, variant_id="no-act", title="gsutil sync no-act", flag="-n"),
        ),
    ),
    _rule(f"{_GCS}.cp", "Google Cloud Storage copy", _gcloud("storage", "cp"), _GCS_ACT, _GCS_FAMILY),
    _rule(
        f"{_GCS}.ls",
        "Google Cloud Storage list",
        _gcloud("storage", "ls"),
        _GCS_ACT,
        _GCS_FAMILY,
        mode="disabled",
        severity="low",
        safer=_READ,
        example="gcloud storage ls",
    ),
    _rule(f"{_GCS}.mv", "Google Cloud Storage move", _gcloud("storage", "mv"), _GCS_ACT, _GCS_FAMILY),
    _rule(
        f"{_GCS}.cat",
        "Google Cloud Storage cat",
        _gcloud("storage", "cat"),
        _GCS_ACT,
        _GCS_FAMILY,
        mode="disabled",
        severity="low",
        safer=_READ,
        example="gcloud storage cat",
    ),
    _rule(f"{_GCS}.rsync", "Google Cloud Storage sync", _GCS_RSYNC, _GCS_ACT, _GCS_FAMILY),
    _rule(
        f"{_GCS}.buckets-create",
        "Google Cloud Storage bucket create",
        _gcloud("storage", "buckets", "create"),
        _GCS_ACT,
        _GCS_FAMILY,
    ),
    _rule(
        f"{_AZURE}.deletion",
        "Azure Blob Storage deletion",
        _AZ_DELETE,
        _AZ_ACT,
        "azure-blob",
        severity="critical",
        safer=_DELETE,
        dry=(_AZ_BATCH, "--dryrun", None),
    ),
    _rule(f"{_AZURE}.upload", "Azure blob upload", _az("storage", "blob", "upload"), _AZ_ACT, "azure-blob"),
    _rule(f"{_AZURE}.download", "Azure blob download", _az("storage", "blob", "download"), _AZ_ACT, "azure-blob"),
    _rule(
        f"{_AZURE}.list",
        "Azure blob list",
        _az("storage", "blob", "list"),
        _AZ_ACT,
        "azure-blob",
        mode="disabled",
        severity="low",
        safer=_READ,
        example="az storage blob list",
    ),
    _rule(f"{_AZURE}.copy", "Azure blob copy", _az("storage", "blob", "copy", "start"), _AZ_ACT, "azure-blob"),
    _rule(
        f"{_AZURE}.container-create",
        "Azure container create",
        _az("storage", "container", "create"),
        _AZ_ACT,
        "azure-blob",
    ),
    _rule(
        f"{_MINIO}.deletion",
        "MinIO object deletion",
        _MC_DELETE,
        _MC_ACT,
        "minio",
        severity="critical",
        safer=_DELETE,
    ),
    _rule(f"{_MINIO}.cp", "MinIO copy", _mc("cp"), _MC_ACT, "minio"),
    _rule(
        f"{_MINIO}.ls",
        "MinIO list",
        _mc("ls"),
        _MC_ACT,
        "minio",
        mode="disabled",
        severity="low",
        safer=_READ,
        example="mc ls",
    ),
    _rule(f"{_MINIO}.mb", "MinIO make bucket", _mc("mb"), _MC_ACT, "minio"),
    _rule(f"{_MINIO}.mv", "MinIO move", _mc("mv"), _MC_ACT, "minio"),
    _rule(
        f"{_MINIO}.cat",
        "MinIO cat",
        _mc("cat"),
        _MC_ACT,
        "minio",
        mode="disabled",
        severity="low",
        safer=_READ,
        example="mc cat",
    ),
    _rule(f"{_MINIO}.mirror", "MinIO mirror", _mc("mirror", forbidden=frozenset({"--remove"})), _MC_ACT, "minio"),
)


STORAGE_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id=_AWS,
        name="Amazon S3 command protection",
        description=(
            "Reviews AWS CLI high-level S3 commands and S3 API object, bucket, access-control, "
            "and configuration operations including copy, list, sync, website, and deletion."
        ),
        action_classes=(_AWS_ACT,),
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternatives=("List matching objects and inspect bucket recovery controls before deletion.",),
        reference_urls=(
            "https://docs.aws.amazon.com/cli/latest/reference/s3/index.html",
            "https://docs.aws.amazon.com/cli/latest/reference/s3/rm.html",
            "https://docs.aws.amazon.com/cli/latest/reference/s3/sync.html",
            "https://docs.aws.amazon.com/cli/latest/reference/s3api/index.html",
            "https://docs.aws.amazon.com/cli/latest/reference/s3api/delete-objects.html",
            "https://docs.aws.amazon.com/cli/latest/reference/s3api/put-object.html",
            "https://docs.aws.amazon.com/cli/latest/reference/s3api/put-bucket-policy.html",
        ),
    ),
    CommandExtensionSpec(
        extension_id=_GCS,
        name="Google Cloud Storage command protection",
        description="Reviews Google CLI storage commands including copy, list, sync, and deletion.",
        action_classes=(_GCS_ACT,),
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternatives=("List matching objects and inspect retention controls before deletion.",),
        reference_urls=(
            "https://cloud.google.com/sdk/gcloud/reference/storage",
            "https://cloud.google.com/sdk/gcloud/reference/storage/rm",
            "https://cloud.google.com/sdk/gcloud/reference/storage/rsync",
        ),
    ),
    CommandExtensionSpec(
        extension_id=_AZURE,
        name="Azure Blob Storage command protection",
        description="Reviews Azure CLI storage commands including upload, list, copy, and deletion.",
        action_classes=(_AZ_ACT,),
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternatives=("List matching blobs and inspect soft-delete controls before deletion.",),
        reference_urls=("https://learn.microsoft.com/cli/azure/storage/blob",),
    ),
    CommandExtensionSpec(
        extension_id=_MINIO,
        name="MinIO command protection",
        description="Reviews MinIO Client commands including copy, list, mirror, and deletion.",
        action_classes=(_MC_ACT,),
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternatives=("List matching objects and confirm versioning or recovery controls before deletion.",),
        reference_urls=(
            "https://docs.min.io/community/minio-object-store/reference/minio-mc.html",
            "https://docs.min.io/community/minio-object-store/reference/minio-mc/mc-rm.html",
            "https://docs.min.io/community/minio-object-store/reference/minio-mc/mc-mirror.html",
        ),
    ),
)

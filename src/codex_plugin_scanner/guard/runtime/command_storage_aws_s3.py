"""Amazon S3 command matchers, rules, and catalog metadata."""

from __future__ import annotations

from .command_extension_specs import CommandExtensionSpec
from .command_storage_common import _DELETE, _READ, _WRITE, _aws, _join, _rule, _s3api

_AWS = "command.storage.aws-s3"
_AWS_ACT = "AWS storage destructive command"
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
    "put-object-annotation",
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
    "update-bucket-metadata-annotation-table-configuration",
    "update-bucket-metadata-inventory-table-configuration",
    "update-bucket-metadata-journal-table-configuration",
)
_AWS_OBJECT_TAGGING = _s3api("put-object-tagging")
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
    "get-object-acl",
    "get-public-access-block",
    "head-bucket",
    "head-object",
)
_AWS_DOWNLOAD = _s3api("get-object")
_AWS_SYNC = _aws("s3", "sync", forbidden=frozenset({"--delete"}))

AWS_S3_COMMAND_RULES = (
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
        f"{_AWS}.download",
        "Amazon S3 object download",
        _AWS_DOWNLOAD,
        _AWS_ACT,
        "aws-s3",
        safer=_WRITE,
        example="aws s3api get-object",
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
        example="aws s3api head-object",
    ),
)

AWS_S3_COMMAND_EXTENSION_SPECS = (
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
)

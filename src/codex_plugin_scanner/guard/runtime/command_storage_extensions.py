"""Structured rules and metadata for object-storage command extensions."""

from __future__ import annotations

from .command_extension_matchers import safe_flag_variant
from .command_extension_specs import CommandExtensionSpec
from .command_storage_aws_s3 import AWS_S3_COMMAND_EXTENSION_SPECS, AWS_S3_COMMAND_RULES
from .command_storage_common import _DELETE, _READ, _az, _gcloud, _gsutil, _join, _mc, _rule

_GCS = "command.storage.google-cloud"
_AZURE = "command.storage.azure-blob"
_MINIO = "command.storage.minio"
_GCS_ACT = "Google storage destructive command"
_AZ_ACT = "Azure storage destructive command"
_MC_ACT = "MinIO storage destructive command"
_GCS_FAMILY = "google-cloud-storage"
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
_GCS_RSYNC = _gcloud("storage", "rsync", forbidden=frozenset({"--delete-unmatched-destination-objects"}))

STORAGE_COMMAND_RULES = (
    *AWS_S3_COMMAND_RULES,
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
    *AWS_S3_COMMAND_EXTENSION_SPECS,
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

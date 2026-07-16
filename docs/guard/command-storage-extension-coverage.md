# Storage Command Extension Coverage

Guard evaluates object-storage operations from the canonical parsed command model. Global provider options, native Windows launchers, compound commands, and documented preview flags use the same structured matcher path as other command extensions.

## Extensions

| Extension | Reviewed operations | Safe counterparts |
| --- | --- | --- |
| `command.storage.aws-s3` | S3 object and bucket removal, delete-enabled sync, S3 API object and bucket deletion | Help; documented high-level S3 dry run |
| `command.storage.google-cloud` | Google Cloud object and bucket removal, delete-enabled `gcloud` and `gsutil` sync | Help; `gcloud --dry-run`; `gsutil -n` |
| `command.storage.azure-blob` | Blob, batch, and container deletion | Help; blob batch `--dryrun` |
| `command.storage.minio` | Object and bucket removal, remove-enabled mirror | Help and listing operations |

Interactive confirmation is not treated as side-effect-free. A preview suppresses review only for the exact command family that officially documents that preview flag.

## References

- [AWS S3 rm](https://docs.aws.amazon.com/cli/latest/reference/s3/rm.html)
- [AWS S3 sync](https://docs.aws.amazon.com/cli/latest/reference/s3/sync.html)
- [AWS S3 delete-objects](https://docs.aws.amazon.com/cli/latest/reference/s3api/delete-objects.html)
- [Google Cloud storage rm](https://cloud.google.com/sdk/gcloud/reference/storage/rm)
- [Google Cloud storage rsync](https://cloud.google.com/sdk/gcloud/reference/storage/rsync)
- [Azure storage blob](https://learn.microsoft.com/cli/azure/storage/blob)
- [MinIO Client rm](https://docs.min.io/community/minio-object-store/reference/minio-mc/mc-rm.html)
- [MinIO Client mirror](https://docs.min.io/community/minio-object-store/reference/minio-mc/mc-mirror.html)

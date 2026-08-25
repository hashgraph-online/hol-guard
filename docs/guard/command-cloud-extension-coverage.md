# Cloud Command Extension Coverage

Guard evaluates cloud CLI operations from the canonical parsed command model. Rules match executable and subcommand structure, remain independent of shell text examples, and feed the existing policy, approval, memory, receipt, and sync pipeline.

## Matrix coverage

| Extension | Matrix-reviewed operations | Existing focused operations | Safe counterparts |
| --- | ---: | --- | --- |
| `command.cloud.aws` | 200 | EC2 instance termination, RDS instance or cluster deletion, and EKS cluster deletion | Help, request skeleton generation, EC2 permission-only dry run, and describe operations |
| `command.cloud.gcp` | 100 | Compute Engine instance deletion and Cloud SQL instance deletion | Help and describe operations |
| `command.cloud.azure` | 100 | Resource management, identity, network, compute, application, data, messaging, observability, AI, and virtual machine deletion | Long and short help forms plus show operations |

The AWS matrix is delivered as two non-overlapping 100-operation batches. Google Cloud and Azure each contribute one 100-operation batch.

The four reviewed batches cover 400 operation tasks across AWS, Google Cloud, and Azure. The operation matrices are declarative, typed, count-checked, and uniqueness-checked. They preserve the existing provider rule IDs and action classes, so policy, approval, receipt, memory, and synchronization contracts remain stable.

Global account, project, subscription, profile, region, output, query, configuration, impersonation, filtering, pagination, and verbosity options are normalized wherever the CLI accepts them. Reordered operation flags do not change the result. Native Windows launcher suffixes are recognized. Unknown future global options fail secure when a destructive path remains recognizable.

## Security and usability boundaries

- Rules match canonical command structure rather than raw words such as `delete`, `destroy`, or `terminate`.
- Quoted examples, printed commands, and source-search patterns remain data.
- A help or preview form suppresses only its owning rule and command segment.
- AWS request skeletons remain safe only for documented values.
- EC2 dry-run safety remains scoped to EC2 termination.
- Azure `--help` and `-h` forms remain safe.
- Compound commands retain later destructive matches even when an earlier segment is safe.
- Every matrix entry is exercised through command inspection and runtime tool-action extraction.
- Read-only neighboring AWS operations remain unclassified by the destructive matrix.

## Primary references

- [AWS CLI command reference](https://docs.aws.amazon.com/cli/latest/reference/)
- [Google Cloud CLI reference](https://cloud.google.com/sdk/gcloud/reference)
- [Azure CLI reference](https://learn.microsoft.com/cli/azure/reference-index)

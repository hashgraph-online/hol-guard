# Cloud Command Extension Coverage

Guard evaluates cloud CLI operations from the canonical parsed command model. Rules match executable and subcommand structure, remain independent of shell text examples, and feed the existing policy, approval, memory, receipt, and sync pipeline.

## Matrix coverage

| Extension | Matrix-reviewed operations | Existing focused operations | Safe counterparts |
| --- | ---: | --- | --- |
| `command.cloud.aws` | 300 | EC2 instance termination, RDS instance or cluster deletion, and EKS cluster deletion | Help, request skeleton generation, EC2 permission-only dry run, and describe operations |
| `command.cloud.gcp` | 100 | Compute Engine instance deletion and Cloud SQL instance deletion | Help and describe operations |
| `command.cloud.azure` | 100 | Resource management, identity, network, compute, application, data, messaging, observability, AI, and virtual machine deletion | Long and short help forms plus show operations |
| `command.cloud.digitalocean` | 147 | Resource deletion, disruptive operations, access changes, credential exposure, remote execution, and inline access tokens | Long and short help forms; `list` and `get` reads are allowed silently by Guard's read proof |

The AWS matrix is delivered as three non-overlapping 100-operation batches. Google Cloud and Azure each contribute one 100-operation batch.

The reviewed batches cover 500 operation tasks across AWS, Google Cloud, and Azure. The operation matrices are declarative, typed, count-checked, and uniqueness-checked. They preserve the existing provider rule IDs and action classes, so policy, approval, receipt, memory, and synchronization contracts remain stable.

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

## DigitalOcean read proof

Guard allows `doctl version`, help, and the `list` and `get` style reads of account, apps, billing, compute, Kubernetes, registry, project, VPC, network, monitoring, and NFS resources without a prompt. Some reads stay on review even though they change nothing, because they print or store credentials: `auth token`, `registry login`, `registry docker-config`, `kubernetes cluster kubeconfig`, and every `databases` read, since connection details include passwords. A read also stays on review when it passes `--access-token` or `-t`, which puts a token on the command line, `--api-url` or `-u`, which sends the stored token to another endpoint, or `--trace`, which prints each API request with its authorization header. Reads with `--config` or `--show` skip the quiet read path and fall back to the extension's ordinary rules.

## Primary references

- [AWS CLI command reference](https://docs.aws.amazon.com/cli/latest/reference/)
- [Google Cloud CLI reference](https://cloud.google.com/sdk/gcloud/reference)
- [Azure CLI reference](https://learn.microsoft.com/cli/azure/reference-index)
- [doctl command reference](https://docs.digitalocean.com/reference/doctl/)

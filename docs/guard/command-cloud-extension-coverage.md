# Cloud Command Extension Coverage

Guard evaluates cloud CLI operations from the canonical parsed command model. Rules match executable and subcommand structure, remain independent of shell text examples, and feed the existing policy, approval, memory, receipt, and sync pipeline.

## Extensions

| Extension | Reviewed operations | Safe counterparts |
| --- | --- | --- |
| `command.cloud.aws` | EC2 instance termination, RDS instance or cluster deletion, EKS cluster deletion | Help, request skeleton generation, EC2 permission-only dry run, describe operations |
| `command.cloud.gcp` | Compute Engine instance deletion, including alpha, beta, and preview tracks; Cloud SQL instance deletion, including alpha and beta tracks | Help and describe operations |
| `command.cloud.azure` | Virtual machine deletion | Help and show operations |

Global account, project, subscription, profile, region, output, and query options are normalized wherever the CLI accepts them. Reordered operation flags do not change the result. Native Windows launcher suffixes are recognized.

## References

- [AWS EC2 terminate-instances](https://docs.aws.amazon.com/cli/latest/reference/ec2/terminate-instances.html)
- [AWS RDS delete-db-instance](https://docs.aws.amazon.com/cli/latest/reference/rds/delete-db-instance.html)
- [AWS RDS delete-db-cluster](https://docs.aws.amazon.com/cli/latest/reference/rds/delete-db-cluster.html)
- [AWS EKS delete-cluster](https://docs.aws.amazon.com/cli/latest/reference/eks/delete-cluster.html)
- [Google Cloud compute instances delete](https://cloud.google.com/sdk/gcloud/reference/compute/instances/delete)
- [Google Cloud SQL instances delete](https://cloud.google.com/sdk/gcloud/reference/sql/instances/delete)
- [Azure vm delete](https://learn.microsoft.com/cli/azure/vm#az-vm-delete)

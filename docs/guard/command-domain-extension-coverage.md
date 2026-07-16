# Infrastructure command extension coverage

Guard's domain command extensions use the shared canonical parser, structured matchers, extension registry, and
composite evaluation path. They add rule-level evidence to the same runtime artifacts, approvals, memory, receipts,
and sync behavior used by existing command protection.

## Initial coverage matrix

| Extension | Reviewed operations | Safe forms |
| --- | --- | --- |
| `command.container-runtime` | Broad system prune, forced container removal, privileged container launch | Command help |
| `command.kubernetes-secrets` | Secret reads through supported cluster clients | Existing metadata-only and non-secret reads |
| `command.kubernetes-operations` | Resource deletion, node drain, Helm release removal | Help and documented dry-run forms |
| `command.infrastructure-as-code` | Terraform/OpenTofu destroy, destroy-mode apply, Pulumi destroy | Plan and preview commands |

Global command options such as Docker contexts, cluster contexts and namespaces, Terraform/OpenTofu working
directories, and Pulumi stacks are normalized before matching. A safe variant suppresses only its owning rule and
cannot hide an unrelated match in another command segment.

## Primary command references

- Container cleanup and privilege boundaries: [Docker system prune](https://docs.docker.com/reference/cli/docker/system/prune/),
  [container removal](https://docs.docker.com/reference/cli/docker/container/rm/), and
  [privileged container execution](https://docs.docker.com/reference/cli/docker/container/run/).
- Cluster mutations: [kubectl delete](https://kubernetes.io/docs/reference/kubectl/generated/kubectl_delete/),
  [kubectl drain](https://kubernetes.io/docs/reference/kubectl/generated/kubectl_drain/), and
  [Helm uninstall](https://helm.sh/docs/helm/helm_uninstall/).
- Infrastructure teardown: [Terraform destroy](https://developer.hashicorp.com/terraform/cli/commands/destroy),
  [OpenTofu destroy](https://opentofu.org/docs/cli/commands/destroy/), and
  [Pulumi destroy](https://www.pulumi.com/docs/iac/cli/commands/pulumi_destroy/).

## Security and usability boundaries

- Rules match canonical executable and argument structures, not raw command substrings.
- Quoted examples and source-search commands remain data and do not trigger execution rules.
- Destructive operations produce one composite decision even when compatibility and structured rules both match.
- Help, plan, preview, and supported dry-run forms remain side-effect-free inspection paths.
- Primary references and positive and safe fixtures are required when expanding the catalog.

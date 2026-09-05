# Infrastructure command extension coverage

Guard's domain command extensions use the shared canonical parser, structured matchers, extension registry, and
composite evaluation path. They add rule-level evidence to the same runtime artifacts, approvals, memory, receipts,
and sync behavior used by existing command protection.

## Coverage matrix

| Extension | Reviewed operations | Safe forms |
| --- | --- | --- |
| `command.container-runtime` | System/container/image/volume/network/build-cache prune, container/image/volume/network/Buildx/Swarm removal, container stop/kill, privileged run, container exec, privileged exec, Compose volume/image cleanup | Command help where argument boundaries are unambiguous; ordinary local Compose teardown without explicit volume/image deletion remains unchanged |
| `command.kubernetes-secrets` | Secret reads through supported cluster clients | Existing metadata-only and non-secret reads |
| `command.kubernetes-operations` | Delete, drain, apply, create, replace/force-replace, patch, edit, scale/autoscale, expose, run, annotate, label, taint, cordon/uncordon, set, rollout restart/undo, exec, debug, port-forward, file copy, certificate approve/deny, Helm install/upgrade/rollback/uninstall aliases | Help, documented client/server dry-run forms, local-only rendering where supported, and Helm dry-run forms |
| `command.infrastructure-as-code` | Terraform/OpenTofu destroy and destroy-mode apply, Pulumi destroy | Plan and preview commands |

Global command options such as Docker contexts, Compose project/file selectors, cluster contexts and namespaces,
Terraform/OpenTofu working directories, and Pulumi stacks are normalized before matching. Docker, kubectl, and Helm
Windows executable forms are covered alongside Unix launchers. A safe variant suppresses only its owning rule and
cannot hide an unrelated match in another command segment.

The Docker extension preserves Guard's established low-friction boundary for routine local Compose workflows. Plain
`docker compose down` and `docker compose rm -f` remain unreviewed; explicit volume or image deletion is reviewed.
Free-form remote execution and copy commands do not use a generic `--help` escape, so a payload token named
`--help` cannot suppress the owning rule.

## Primary command references

- Docker lifecycle and cleanup: [system prune](https://docs.docker.com/reference/cli/docker/system/prune/),
  [container remove](https://docs.docker.com/reference/cli/docker/container/rm/),
  [container exec](https://docs.docker.com/reference/cli/docker/container/exec/),
  [image remove](https://docs.docker.com/reference/cli/docker/image/rm/),
  [volume remove](https://docs.docker.com/reference/cli/docker/volume/rm/),
  [network remove](https://docs.docker.com/reference/cli/docker/network/rm/), and
  [Compose down](https://docs.docker.com/reference/cli/docker/compose/down/).
- Kubernetes mutations and sessions: [kubectl apply](https://kubernetes.io/docs/reference/kubectl/generated/kubectl_apply/),
  [delete](https://kubernetes.io/docs/reference/kubectl/generated/kubectl_delete/),
  [drain](https://kubernetes.io/docs/reference/kubectl/generated/kubectl_drain/),
  [exec](https://kubernetes.io/docs/reference/kubectl/generated/kubectl_exec/), and
  [port-forward](https://kubernetes.io/docs/reference/kubectl/generated/kubectl_port-forward/).
- Helm lifecycle: [install](https://helm.sh/docs/helm/helm_install/),
  [upgrade](https://helm.sh/docs/helm/helm_upgrade/), and
  [uninstall](https://helm.sh/docs/helm/helm_uninstall/).
- Infrastructure teardown: [Terraform destroy](https://developer.hashicorp.com/terraform/cli/commands/destroy),
  [OpenTofu destroy](https://opentofu.org/docs/cli/commands/destroy/), and
  [Pulumi destroy](https://www.pulumi.com/docs/iac/cli/commands/pulumi_destroy/).

## Security and usability boundaries

- Rules match canonical executable and argument structures, not raw command substrings.
- Quoted examples and source-search commands remain data and do not trigger execution rules.
- Destructive operations produce one composite decision even when compatibility and structured rules both match.
- Help, preview, local-only, and supported dry-run forms remain side-effect-free inspection paths.
- False or overridden safe flags such as `--dry-run=none`, `--dry-run=false`, and `--local=false` remain live execution.
- Safe variants are rule-local, so a preview in one shell segment cannot hide a destructive command in another.
- Primary references plus positive, safe, Windows-launcher, global-option, compound-command, and quoted-data fixtures are
  required when expanding the catalog.

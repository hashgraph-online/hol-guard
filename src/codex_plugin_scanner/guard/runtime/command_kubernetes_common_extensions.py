"""Structured coverage for common Kubernetes and Helm mutation commands."""

from __future__ import annotations

from .command_common_extension_helpers import (
    executable_matcher,
    flag_variant,
    help_variant,
    kubernetes_dry_run_variant,
    rule,
)
from .command_rules import AnyMatcher, CommandSafeVariant, ExecutableMatcher

_KUBECTL = frozenset({"kubectl", "kubectl.exe"})
_HELM = frozenset({"helm", "helm.exe"})
_KUBECTL_GLOBAL_OPTIONS = frozenset(
    {
        "--as",
        "--as-group",
        "--cache-dir",
        "--certificate-authority",
        "--client-certificate",
        "--client-key",
        "--cluster",
        "--context",
        "--kubeconfig",
        "--namespace",
        "-n",
        "--password",
        "--profile-output",
        "--request-timeout",
        "--server",
        "-s",
        "--tls-server-name",
        "--token",
        "--user",
        "--username",
    }
)
_KUBECTL_GLOBAL_FLAGS = frozenset(
    {
        "--disable-compression",
        "--insecure-skip-tls-verify",
        "--match-server-version",
        "--warnings-as-errors",
    }
)
_HELM_GLOBAL_OPTIONS = frozenset(
    {
        "--burst-limit",
        "--kube-apiserver",
        "--kube-as-group",
        "--kube-as-user",
        "--kube-ca-file",
        "--kube-context",
        "--kube-token",
        "--kubeconfig",
        "--namespace",
        "-n",
        "--qps",
        "--registry-config",
        "--repository-cache",
        "--repository-config",
    }
)
_HELM_GLOBAL_FLAGS = frozenset({"--debug", "--kube-insecure-skip-tls-verify"})
_EMPTY: frozenset[str] = frozenset()


def _kubectl(
    *subcommands: str,
    required_flags: frozenset[str] = _EMPTY,
    forbidden_flags: frozenset[str] = _EMPTY,
) -> ExecutableMatcher:
    return executable_matcher(
        _KUBECTL,
        *subcommands,
        required_flags=required_flags,
        forbidden_flags=forbidden_flags,
        leading_options_with_values=_KUBECTL_GLOBAL_OPTIONS,
        interspersed_flags=_KUBECTL_GLOBAL_FLAGS,
    )


def _helm(*subcommands: str) -> ExecutableMatcher:
    return executable_matcher(
        _HELM,
        *subcommands,
        leading_options_with_values=_HELM_GLOBAL_OPTIONS,
        interspersed_flags=_HELM_GLOBAL_FLAGS,
    )


def _kube_mutation_variants(
    matcher: ExecutableMatcher | AnyMatcher,
    title: str,
    *,
    local: bool = False,
) -> tuple[CommandSafeVariant, ...]:
    variants = [help_variant(matcher), kubernetes_dry_run_variant(matcher, title)]
    if local:
        variants.append(
            flag_variant(
                matcher,
                variant_id="local",
                title="Local-only rendering",
                required_flags=frozenset({"--local"}),
            )
        )
    return tuple(variants)


def _helm_dry_run_variant(matcher: ExecutableMatcher | AnyMatcher, title: str) -> CommandSafeVariant:
    return flag_variant(
        matcher,
        variant_id="dry-run",
        title=title,
        required_flags=frozenset({"--dry-run"}),
    )


_APPLY = _kubectl("apply")
_CREATE = _kubectl("create")
_REPLACE = _kubectl("replace", forbidden_flags=frozenset({"--force"}))
_FORCE_REPLACE = _kubectl("replace", required_flags=frozenset({"--force"}))
_PATCH = _kubectl("patch")
_EDIT = _kubectl("edit")
_SCALE = _kubectl("scale")
_AUTOSCALE = _kubectl("autoscale")
_EXPOSE = _kubectl("expose")
_RUN = _kubectl("run")
_ANNOTATE = _kubectl("annotate")
_LABEL = _kubectl("label")
_TAINT = _kubectl("taint")
_NODE_SCHEDULING = AnyMatcher(matchers=(_kubectl("cordon"), _kubectl("uncordon")))
_SET = _kubectl("set")
_ROLLOUT_RESTART = _kubectl("rollout", "restart")
_ROLLOUT_UNDO = _kubectl("rollout", "undo")
_EXEC = _kubectl("exec")
_DEBUG = _kubectl("debug")
_PORT_FORWARD = _kubectl("port-forward")
_COPY = _kubectl("cp")
_CERTIFICATE_DECISION = AnyMatcher(
    matchers=(_kubectl("certificate", "approve"), _kubectl("certificate", "deny"))
)
_HELM_INSTALL = _helm("install")
_HELM_UPGRADE = _helm("upgrade")
_HELM_ROLLBACK = _helm("rollback")
_HELM_REMOVE_ALIASES = AnyMatcher(matchers=(_helm("delete"), _helm("del"), _helm("un")))


KUBERNETES_COMMON_COMMAND_RULES = (
    rule(
        rule_id="command.kubernetes-operations.apply-resources",
        title="Kubernetes apply",
        description="Identifies declarative create or update operations against cluster resources.",
        matcher=_APPLY,
        action_class="Kubernetes destructive command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Render a client-side dry run and review the exact namespace and diff before applying.",
        example_command="kubectl apply -f deployment.yaml",
        safe_variants=_kube_mutation_variants(_APPLY, "Kubernetes apply preview"),
    ),
    rule(
        rule_id="command.kubernetes-operations.create-resources",
        title="Kubernetes create",
        description="Identifies imperative creation of cluster resources and generated resource requests.",
        matcher=_CREATE,
        action_class="Kubernetes destructive command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Use a client-side dry run and review the generated resource before creation.",
        example_command="kubectl create -f service.yaml",
        safe_variants=_kube_mutation_variants(_CREATE, "Kubernetes create preview"),
    ),
    rule(
        rule_id="command.kubernetes-operations.replace-resources",
        title="Kubernetes replace",
        description="Identifies replacement of live cluster resources without forced deletion.",
        matcher=_REPLACE,
        action_class="Kubernetes destructive command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Use a dry run and compare the full replacement object with the live resource first.",
        example_command="kubectl replace -f deployment.yaml",
        safe_variants=_kube_mutation_variants(_REPLACE, "Kubernetes replace preview"),
    ),
    rule(
        rule_id="command.kubernetes-operations.force-replace-resources",
        title="Forced Kubernetes replace",
        description="Identifies forced replacement that deletes and recreates a resource without graceful handoff.",
        matcher=_FORCE_REPLACE,
        action_class="Kubernetes destructive command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Use ordinary replace or apply after reviewing a dry run instead of forced recreation.",
        example_command="kubectl replace --force -f deployment.yaml",
        severity="critical",
        safe_variants=_kube_mutation_variants(_FORCE_REPLACE, "Forced replace preview"),
    ),
    rule(
        rule_id="command.kubernetes-operations.patch-resources",
        title="Kubernetes patch",
        description="Identifies partial mutation of live cluster resources.",
        matcher=_PATCH,
        action_class="Kubernetes destructive command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Use --local or a dry run and inspect the resulting object before patching the cluster.",
        example_command="kubectl patch deployment api -p '{\"spec\":{\"replicas\":2}}'",
        safe_variants=_kube_mutation_variants(_PATCH, "Kubernetes patch preview", local=True),
    ),
    rule(
        rule_id="command.kubernetes-operations.edit-resources",
        title="Kubernetes edit",
        description="Identifies interactive editing that writes modified resources back to the cluster.",
        matcher=_EDIT,
        action_class="Kubernetes destructive command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Export the resource, review a diff, and apply a reviewed manifest instead of editing live state.",
        example_command="kubectl edit deployment api",
        safe_variants=(help_variant(_EDIT),),
    ),
    rule(
        rule_id="command.kubernetes-operations.scale-resources",
        title="Kubernetes scale",
        description="Identifies replica-count changes that can add or remove live workload instances.",
        matcher=_SCALE,
        action_class="Kubernetes destructive command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Use a dry run and verify workload capacity and disruption constraints before scaling.",
        example_command="kubectl scale deployment api --replicas=0",
        safe_variants=_kube_mutation_variants(_SCALE, "Kubernetes scale preview"),
    ),
    rule(
        rule_id="command.kubernetes-operations.autoscale-resources",
        title="Kubernetes autoscale",
        description="Identifies creation or mutation of autoscaling behavior for workloads.",
        matcher=_AUTOSCALE,
        action_class="Kubernetes destructive command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Use a dry run and review minimum, maximum, and target utilization before enabling autoscaling.",
        example_command="kubectl autoscale deployment api --min=2 --max=10 --cpu-percent=80",
        safe_variants=_kube_mutation_variants(_AUTOSCALE, "Kubernetes autoscale preview"),
    ),
    rule(
        rule_id="command.kubernetes-operations.expose-resources",
        title="Kubernetes expose",
        description="Identifies creation of Services that expose workloads on cluster networking.",
        matcher=_EXPOSE,
        action_class="Kubernetes destructive command",
        risk_classes=("network_egress",),
        safer_alternative="Use a client-side dry run and review service type, ports, selectors, and namespace first.",
        example_command="kubectl expose deployment api --port=80 --type=LoadBalancer",
        safe_variants=_kube_mutation_variants(_EXPOSE, "Kubernetes expose preview"),
    ),
    rule(
        rule_id="command.kubernetes-operations.run-pod",
        title="Kubernetes run",
        description="Identifies creation and execution of a new Pod from a container image.",
        matcher=_RUN,
        action_class="Kubernetes destructive command",
        risk_classes=("execution", "network_egress"),
        safer_alternative="Use a client-side dry run and review image, service account, environment, and command first.",
        example_command="kubectl run debug --image=alpine -- sh",
        safe_variants=_kube_mutation_variants(_RUN, "Kubernetes run preview"),
    ),
    rule(
        rule_id="command.kubernetes-operations.annotate-resources",
        title="Kubernetes annotate",
        description="Identifies annotation mutations on cluster resources.",
        matcher=_ANNOTATE,
        action_class="Kubernetes destructive command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Use --local or a dry run and review the exact annotation keys and resource scope first.",
        example_command="kubectl annotate deployment api owner=platform --overwrite",
        safe_variants=_kube_mutation_variants(_ANNOTATE, "Kubernetes annotate preview", local=True),
    ),
    rule(
        rule_id="command.kubernetes-operations.label-resources",
        title="Kubernetes label",
        description="Identifies label mutations that can change selectors, policy scope, or automation behavior.",
        matcher=_LABEL,
        action_class="Kubernetes destructive command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Use --local or a dry run and review selector and policy effects before changing labels.",
        example_command="kubectl label namespace prod environment=restricted --overwrite",
        safe_variants=_kube_mutation_variants(_LABEL, "Kubernetes label preview", local=True),
    ),
    rule(
        rule_id="command.kubernetes-operations.taint-nodes",
        title="Kubernetes node taint",
        description="Identifies node taint changes that can alter workload placement or trigger evictions.",
        matcher=_TAINT,
        action_class="Kubernetes destructive command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Use a dry run and verify affected nodes, tolerations, and eviction consequences first.",
        example_command="kubectl taint nodes node-a dedicated=ops:NoExecute",
        safe_variants=_kube_mutation_variants(_TAINT, "Kubernetes taint preview"),
    ),
    rule(
        rule_id="command.kubernetes-operations.node-scheduling",
        title="Kubernetes node scheduling change",
        description="Identifies cordon and uncordon operations that change whether a node accepts new workloads.",
        matcher=_NODE_SCHEDULING,
        action_class="Kubernetes destructive command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Use a dry run and verify the exact node and scheduling impact first.",
        example_command="kubectl cordon node-a",
        safe_variants=_kube_mutation_variants(_NODE_SCHEDULING, "Kubernetes scheduling preview"),
    ),
    rule(
        rule_id="command.kubernetes-operations.set-resources",
        title="Kubernetes set",
        description=(
            "Identifies declarative set operations that mutate image, environment, resources, selectors, or identity."
        ),
        matcher=_SET,
        action_class="Kubernetes destructive command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Use --local or a dry run and review the generated resource changes before applying them.",
        example_command="kubectl set image deployment/api api=registry.example.com/api:v2",
        safe_variants=_kube_mutation_variants(_SET, "Kubernetes set preview", local=True),
    ),
    rule(
        rule_id="command.kubernetes-operations.rollout-restart",
        title="Kubernetes rollout restart",
        description="Identifies workload restarts that replace running Pods.",
        matcher=_ROLLOUT_RESTART,
        action_class="Kubernetes destructive command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Review rollout status, disruption budgets, and workload health before restarting.",
        example_command="kubectl rollout restart deployment/api",
        safe_variants=(help_variant(_ROLLOUT_RESTART),),
    ),
    rule(
        rule_id="command.kubernetes-operations.rollout-undo",
        title="Kubernetes rollout undo",
        description="Identifies rollback of a workload to a previous rollout revision.",
        matcher=_ROLLOUT_UNDO,
        action_class="Kubernetes destructive command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Inspect rollout history and use a dry run before selecting the revision to restore.",
        example_command="kubectl rollout undo deployment/api --to-revision=2",
        safe_variants=_kube_mutation_variants(_ROLLOUT_UNDO, "Kubernetes rollout undo preview"),
    ),
    rule(
        rule_id="command.kubernetes-operations.exec",
        title="Kubernetes remote execution",
        description="Identifies arbitrary command execution inside a running container.",
        matcher=_EXEC,
        action_class="Kubernetes remote execution command",
        risk_classes=("execution", "network_egress"),
        safer_alternative="Prefer read-only inspection and avoid exposing secrets or host-mounted paths to the session.",
        example_command="kubectl exec deployment/api -- sh -lc 'id'",
        severity="critical",
    ),
    rule(
        rule_id="command.kubernetes-operations.debug",
        title="Kubernetes debug session",
        description="Identifies debug operations that can add ephemeral containers, copy Pods, or enter node namespaces.",
        matcher=_DEBUG,
        action_class="Kubernetes remote execution command",
        risk_classes=("execution", "network_egress", "destructive_shell"),
        safer_alternative="Use the narrowest debug target and profile, and avoid host namespace access unless required.",
        example_command="kubectl debug node/node-a -it --image=busybox",
        severity="critical",
    ),
    rule(
        rule_id="command.kubernetes-operations.port-forward",
        title="Kubernetes port forward",
        description="Identifies local network tunnels to Pods, Services, or other cluster resources.",
        matcher=_PORT_FORWARD,
        action_class="Kubernetes network tunnel command",
        risk_classes=("network_egress",),
        safer_alternative="Bind only to loopback, forward the minimum required port, and verify the exact target first.",
        example_command="kubectl port-forward service/api 8080:80",
    ),
    rule(
        rule_id="command.kubernetes-operations.copy-files",
        title="Kubernetes file copy",
        description="Identifies file transfer between the local machine and a container.",
        matcher=_COPY,
        action_class="Kubernetes remote file transfer command",
        risk_classes=("network_egress", "local_secret_read"),
        safer_alternative="Copy only an explicitly reviewed non-secret path and verify the source and destination Pod.",
        example_command="kubectl cp ./config.json default/api:/tmp/config.json",
    ),
    rule(
        rule_id="command.kubernetes-operations.certificate-decision",
        title="Kubernetes certificate request decision",
        description="Identifies approval or denial of certificate signing requests that affect cluster identities.",
        matcher=_CERTIFICATE_DECISION,
        action_class="Kubernetes security administration command",
        risk_classes=("network_egress", "destructive_shell"),
        safer_alternative="Inspect the CSR signer, usages, subject, and requester identity before making a decision.",
        example_command="kubectl certificate approve agent-access",
        severity="critical",
        safe_variants=(help_variant(_CERTIFICATE_DECISION),),
    ),
    rule(
        rule_id="command.kubernetes-operations.helm-install",
        title="Helm release install",
        description="Identifies installation of a chart and its rendered resources into a cluster.",
        matcher=_HELM_INSTALL,
        action_class="Kubernetes destructive command",
        risk_classes=("execution", "network_egress", "destructive_shell"),
        safer_alternative="Render or dry-run the chart and review values, hooks, images, and namespace before install.",
        example_command="helm install api ./chart --namespace prod",
        safe_variants=(
            help_variant(_HELM_INSTALL),
            _helm_dry_run_variant(_HELM_INSTALL, "Helm install preview"),
        ),
    ),
    rule(
        rule_id="command.kubernetes-operations.helm-upgrade",
        title="Helm release upgrade",
        description="Identifies upgrades that replace or mutate resources owned by an existing release.",
        matcher=_HELM_UPGRADE,
        action_class="Kubernetes destructive command",
        risk_classes=("execution", "network_egress", "destructive_shell"),
        safer_alternative="Dry-run the upgrade and review rendered manifests, hooks, values, and rollback readiness first.",
        example_command="helm upgrade api ./chart --namespace prod",
        safe_variants=(
            help_variant(_HELM_UPGRADE),
            _helm_dry_run_variant(_HELM_UPGRADE, "Helm upgrade preview"),
        ),
    ),
    rule(
        rule_id="command.kubernetes-operations.helm-rollback",
        title="Helm release rollback",
        description="Identifies rollback of a release to a previous revision.",
        matcher=_HELM_ROLLBACK,
        action_class="Kubernetes destructive command",
        risk_classes=("network_egress", "destructive_shell"),
        safer_alternative="Inspect release history and dry-run the rollback before changing live resources.",
        example_command="helm rollback api 2 --namespace prod",
        safe_variants=(
            help_variant(_HELM_ROLLBACK),
            _helm_dry_run_variant(_HELM_ROLLBACK, "Helm rollback preview"),
        ),
    ),
    rule(
        rule_id="command.kubernetes-operations.helm-uninstall-alias",
        title="Helm release removal alias",
        description="Identifies common Helm aliases that uninstall a release and its managed resources.",
        matcher=_HELM_REMOVE_ALIASES,
        action_class="Kubernetes destructive command",
        risk_classes=("network_egress", "destructive_shell"),
        safer_alternative="Dry-run the uninstall where supported and confirm the exact release and namespace first.",
        example_command="helm delete api --namespace prod",
        safe_variants=(
            help_variant(_HELM_REMOVE_ALIASES),
            _helm_dry_run_variant(_HELM_REMOVE_ALIASES, "Helm uninstall preview"),
        ),
    ),
)

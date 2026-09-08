"""Structured rules and metadata for infrastructure command extensions."""

from __future__ import annotations

from .command_extension_matchers import executable_matcher, safe_flag_variant, safe_option_variant
from .command_extension_specs import CommandExtensionSpec
from .command_rules import AnyMatcher, CommandRuleSeverity, CommandSafetyRule, CommandSafeVariant

_CONTAINER_GLOBAL_OPTIONS = frozenset({"--config", "--context", "--host", "-H", "--log-level"})
_KUBE_GLOBAL_OPTIONS = frozenset(
    {"--as", "--as-group", "--cluster", "--context", "--kubeconfig", "--namespace", "-n", "--server", "--user"}
)
_HELM_GLOBAL_OPTIONS = frozenset({"--kube-context", "--kubeconfig", "--namespace", "-n", "--registry-config"})
_TERRAFORM_GLOBAL_OPTIONS = frozenset({"-chdir"})
_PULUMI_GLOBAL_OPTIONS = frozenset({"--cwd", "-c", "--stack", "-s"})
_CDK_GLOBAL_OPTIONS = frozenset({"--app", "-a", "--context", "-c", "--profile", "--region"})
_SAM_GLOBAL_OPTIONS = frozenset({"--config-env", "--config-file", "--profile", "--region"})
_SERVERLESS_GLOBAL_OPTIONS = frozenset({"--config", "--region", "--stage", "--org", "--app"})
_COMMON_FLAGS = frozenset({"--help", "-h", "--verbose"})


def _any(*matchers) -> AnyMatcher:
    return AnyMatcher(matchers=tuple(matchers))


def _rule(
    *,
    rule_id: str,
    title: str,
    description: str,
    matcher: AnyMatcher,
    action_class: str,
    risk_classes: tuple[str, ...],
    safer_alternative: str,
    severity: CommandRuleSeverity = "high",
    safe_variants: tuple[CommandSafeVariant, ...] = (),
) -> CommandSafetyRule:
    return CommandSafetyRule(
        rule_id=rule_id,
        title=title,
        description=description,
        severity=severity,
        risk_classes=risk_classes,
        action_classes=(action_class,),
        safer_alternatives=(safer_alternative,),
        matcher=matcher,
        safe_variants=safe_variants,
    )


def _container(*subcommands: str, required_flags: frozenset[str] = frozenset()) -> AnyMatcher:
    return _any(
        *(
            executable_matcher(
                executable,
                *subcommands,
                required_flags=required_flags,
                global_options_with_values=_CONTAINER_GLOBAL_OPTIONS,
                global_flags=_COMMON_FLAGS,
            )
            for executable in ("docker", "podman", "nerdctl")
        )
    )


def _kube(*subcommands: str) -> AnyMatcher:
    return _any(
        *(
            executable_matcher(
                executable,
                *subcommands,
                global_options_with_values=_KUBE_GLOBAL_OPTIONS,
                global_flags=_COMMON_FLAGS,
            )
            for executable in ("kubectl", "oc")
        )
    )


_CONTAINER_PRUNE = _container("system", "prune")
_CONTAINER_FORCE_REMOVE = _any(
    *_container("rm", required_flags=frozenset({"--force"})).matchers,
    *_container("rm", required_flags=frozenset({"-f"})).matchers,
    *_container("container", "rm", required_flags=frozenset({"--force"})).matchers,
    *_container("container", "rm", required_flags=frozenset({"-f"})).matchers,
)
_CONTAINER_PRIVILEGED = _any(
    *_container("run", required_flags=frozenset({"--privileged"})).matchers,
    *_container("container", "run", required_flags=frozenset({"--privileged"})).matchers,
)
_KUBE_DELETE = _kube("delete")
_KUBE_DRAIN = _any(*_kube("drain").matchers, executable_matcher("oc", "adm", "drain", global_options_with_values=_KUBE_GLOBAL_OPTIONS, global_flags=_COMMON_FLAGS))
_OC_MUTATION = _any(
    *(executable_matcher("oc", *path, global_options_with_values=_KUBE_GLOBAL_OPTIONS, global_flags=_COMMON_FLAGS) for path in (
        ("apply",),
        ("patch",),
        ("scale",),
        ("rollout", "restart"),
        ("project",),
        ("adm", "cordon"),
        ("adm", "uncordon"),
    ))
)
_HELM_UNINSTALL = _any(executable_matcher("helm", "uninstall", global_options_with_values=_HELM_GLOBAL_OPTIONS, global_flags=_COMMON_FLAGS))
_TERRAFORM_DESTROY = _any(
    executable_matcher("terraform", "destroy", global_options_with_values=_TERRAFORM_GLOBAL_OPTIONS, global_flags=_COMMON_FLAGS),
    executable_matcher("tofu", "destroy", global_options_with_values=_TERRAFORM_GLOBAL_OPTIONS, global_flags=_COMMON_FLAGS),
    executable_matcher("terraform", "apply", required_flags=frozenset({"-destroy"}), global_options_with_values=_TERRAFORM_GLOBAL_OPTIONS, global_flags=_COMMON_FLAGS),
    executable_matcher("tofu", "apply", required_flags=frozenset({"-destroy"}), global_options_with_values=_TERRAFORM_GLOBAL_OPTIONS, global_flags=_COMMON_FLAGS),
    executable_matcher("pulumi", "destroy", global_options_with_values=_PULUMI_GLOBAL_OPTIONS, global_flags=_COMMON_FLAGS),
    executable_matcher("cdk", "destroy", global_options_with_values=_CDK_GLOBAL_OPTIONS, global_flags=_COMMON_FLAGS),
    executable_matcher("sam", "delete", global_options_with_values=_SAM_GLOBAL_OPTIONS, global_flags=_COMMON_FLAGS),
    executable_matcher("serverless", "remove", global_options_with_values=_SERVERLESS_GLOBAL_OPTIONS, global_flags=_COMMON_FLAGS),
    executable_matcher("sls", "remove", global_options_with_values=_SERVERLESS_GLOBAL_OPTIONS, global_flags=_COMMON_FLAGS),
)
_IAC_PRODUCTION_CHANGE = _any(
    executable_matcher("cdk", "deploy", global_options_with_values=_CDK_GLOBAL_OPTIONS, global_flags=_COMMON_FLAGS),
    executable_matcher("sam", "deploy", global_options_with_values=_SAM_GLOBAL_OPTIONS, global_flags=_COMMON_FLAGS),
    executable_matcher("serverless", "deploy", global_options_with_values=_SERVERLESS_GLOBAL_OPTIONS, global_flags=_COMMON_FLAGS),
    executable_matcher("sls", "deploy", global_options_with_values=_SERVERLESS_GLOBAL_OPTIONS, global_flags=_COMMON_FLAGS),
)

DOMAIN_COMMAND_RULES = (
    _rule(
        rule_id="command.container-runtime.system-prune",
        title="Container system prune",
        description="Identifies broad cleanup of unused container runtime state.",
        matcher=_CONTAINER_PRUNE,
        action_class="docker-sensitive command",
        risk_classes=("destructive_shell",),
        safer_alternative="List targeted containers, images, networks, volumes, and build cache before pruning.",
        safe_variants=(safe_flag_variant(_CONTAINER_PRUNE, variant_id="help", title="Command help", flag="--help"),),
    ),
    _rule(
        rule_id="command.container-runtime.forced-container-removal",
        title="Forced container removal",
        description="Identifies forced Docker, Podman, or nerdctl container removal.",
        matcher=_CONTAINER_FORCE_REMOVE,
        action_class="docker-sensitive command",
        risk_classes=("destructive_shell",),
        safer_alternative="Stop the named container gracefully, inspect it, then remove that exact container.",
        safe_variants=(safe_flag_variant(_CONTAINER_FORCE_REMOVE, variant_id="help", title="Command help", flag="--help"),),
    ),
    _rule(
        rule_id="command.container-runtime.privileged-run",
        title="Privileged container execution",
        description="Identifies Docker, Podman, or nerdctl containers launched with broad host privileges.",
        matcher=_CONTAINER_PRIVILEGED,
        action_class="docker-sensitive command",
        risk_classes=("destructive_shell", "network_egress", "execution"),
        safer_alternative="Grant only required capabilities and keep host devices and filesystems isolated.",
        severity="critical",
        safe_variants=(safe_flag_variant(_CONTAINER_PRIVILEGED, variant_id="help", title="Command help", flag="--help"),),
    ),
    _rule(
        rule_id="command.kubernetes-operations.delete-resources",
        title="Kubernetes resource deletion",
        description="Identifies kubectl or OpenShift oc deletion of live cluster resources.",
        matcher=_KUBE_DELETE,
        action_class="Kubernetes destructive command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Run a client-side dry run and review exact resource names and namespace first.",
        safe_variants=(
            safe_flag_variant(_KUBE_DELETE, variant_id="help", title="Command help", flag="--help"),
            safe_option_variant(_KUBE_DELETE, variant_id="dry-run", title="Kubernetes deletion preview", option="--dry-run", allowed_values=frozenset({"client", "server"})),
        ),
    ),
    _rule(
        rule_id="command.kubernetes-operations.drain-node",
        title="Kubernetes node drain",
        description="Identifies kubectl or OpenShift node drains that evict workloads.",
        matcher=_KUBE_DRAIN,
        action_class="Kubernetes destructive command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Preview the drain and verify disruption budgets, node identity, and workload scope first.",
        safe_variants=(
            safe_flag_variant(_KUBE_DRAIN, variant_id="help", title="Command help", flag="--help"),
            safe_option_variant(_KUBE_DRAIN, variant_id="dry-run", title="Kubernetes drain preview", option="--dry-run", allowed_values=frozenset({"client", "server"})),
        ),
    ),
    _rule(
        rule_id="command.kubernetes-operations.openshift-mutation",
        title="OpenShift cluster mutation",
        description="Identifies OpenShift oc apply, patch, scale, rollout, project, cordon, and uncordon operations.",
        matcher=_OC_MUTATION,
        action_class="Kubernetes destructive command",
        risk_classes=("destructive_shell", "network_egress", "execution"),
        safer_alternative="Inspect the exact resource, namespace, and current rollout or node state before mutation.",
        safe_variants=(safe_flag_variant(_OC_MUTATION, variant_id="help", title="Command help", flag="--help"),),
    ),
    _rule(
        rule_id="command.kubernetes-operations.helm-uninstall",
        title="Helm release removal",
        description="Identifies Helm uninstall operations that remove a release and managed resources.",
        matcher=_HELM_UNINSTALL,
        action_class="Kubernetes destructive command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Run Helm uninstall with dry-run and confirm release and namespace first.",
        safe_variants=(
            safe_flag_variant(_HELM_UNINSTALL, variant_id="help", title="Command help", flag="--help"),
            safe_flag_variant(_HELM_UNINSTALL, variant_id="dry-run", title="Helm uninstall preview", flag="--dry-run"),
        ),
    ),
    _rule(
        rule_id="command.infrastructure-as-code.destroy",
        title="Infrastructure teardown",
        description="Identifies Terraform, OpenTofu, Pulumi, AWS CDK/SAM, and Serverless teardown commands.",
        matcher=_TERRAFORM_DESTROY,
        action_class="infrastructure destructive command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Generate and inspect a plan, diff, or preview for the selected environment before teardown.",
        severity="critical",
        safe_variants=(
            safe_flag_variant(_TERRAFORM_DESTROY, variant_id="help", title="Command help", flag="--help"),
            CommandSafeVariant(
                variant_id="pulumi-preview-only",
                title="Pulumi destroy preview",
                matcher=executable_matcher("pulumi", "destroy", required_flags=frozenset({"--preview-only"}), global_options_with_values=_PULUMI_GLOBAL_OPTIONS, global_flags=_COMMON_FLAGS),
            ),
        ),
    ),
    _rule(
        rule_id="command.infrastructure-as-code.production-change",
        title="Infrastructure production deployment",
        description="Identifies AWS CDK, SAM, and Serverless Framework deployment operations.",
        matcher=_IAC_PRODUCTION_CHANGE,
        action_class="infrastructure destructive command",
        risk_classes=("destructive_shell", "network_egress", "execution"),
        safer_alternative="Inspect the generated change set, diff, or package before applying production infrastructure changes.",
        safe_variants=(safe_flag_variant(_IAC_PRODUCTION_CHANGE, variant_id="help", title="Command help", flag="--help"),),
    ),
)

DOMAIN_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.kubernetes-operations",
        name="Kubernetes operation protection",
        description="Reviews Kubernetes, OpenShift, and Helm cluster mutations and teardown operations.",
        action_classes=("Kubernetes destructive command",),
        risk_classes=("destructive_shell", "network_egress", "execution"),
        safer_alternatives=(
            "Use client-side dry runs and explicit namespaces before mutating cluster resources.",
            "Review disruption budgets and exact workload scope before draining nodes.",
        ),
        reference_urls=(
            "https://kubernetes.io/docs/reference/kubectl/",
            "https://docs.redhat.com/en/documentation/openshift_container_platform/",
            "https://helm.sh/docs/helm/helm_uninstall/",
        ),
    ),
    CommandExtensionSpec(
        extension_id="command.infrastructure-as-code",
        name="Infrastructure-as-code protection",
        description="Reviews teardown and high-impact deployment through Terraform, OpenTofu, Pulumi, AWS CDK/SAM, and Serverless Framework.",
        action_classes=("infrastructure destructive command",),
        risk_classes=("destructive_shell", "network_egress", "execution"),
        safer_alternatives=(
            "Create and inspect a saved plan, diff, change set, or preview before applying destructive changes.",
            "Confirm the selected workspace, stack, account, stage, and region before mutation.",
        ),
        reference_urls=(
            "https://developer.hashicorp.com/terraform/cli/commands/destroy",
            "https://opentofu.org/docs/cli/commands/destroy/",
            "https://www.pulumi.com/docs/iac/cli/commands/pulumi_destroy/",
            "https://docs.aws.amazon.com/cdk/v2/guide/ref-cli-cmd-destroy.html",
            "https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-cli-command-reference-sam-delete.html",
            "https://www.serverless.com/framework/docs/providers/aws/cli-reference/remove",
        ),
    ),
)

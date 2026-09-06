"""Structured rules and metadata for infrastructure command extensions."""

from __future__ import annotations

from .command_common_extension_helpers import (
    executable_matcher as _executable_matcher,
    flag_variant,
    help_variant as _help_variant,
    kubernetes_dry_run_variant,
    rule as _rule,
)
from .command_container_common_extensions import CONTAINER_COMMON_COMMAND_RULES
from .command_domain_extension_specs import DOMAIN_COMMAND_EXTENSION_SPECS as DOMAIN_COMMAND_EXTENSION_SPECS
from .command_kubernetes_common_extensions import KUBERNETES_COMMON_COMMAND_RULES
from .command_rules import AnyMatcher

_DOCKER_EXECUTABLES = frozenset({"docker", "docker.exe"})
_KUBECTL_EXECUTABLES = frozenset({"kubectl", "kubectl.exe"})
_HELM_EXECUTABLES = frozenset({"helm", "helm.exe"})
_DOCKER_GLOBAL_OPTIONS = frozenset(
    {
        "--config",
        "--context",
        "-c",
        "--host",
        "-H",
        "--log-level",
        "-l",
        "--tlscacert",
        "--tlscert",
        "--tlskey",
    }
)
_DOCKER_GLOBAL_FLAGS = frozenset({"--debug", "-D", "--tls", "--tlsverify"})
_KUBECTL_GLOBAL_OPTIONS = frozenset(
    {
        "--as",
        "--as-group",
        "--as-uid",
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
        "-v",
        "--v",
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
        "--kube-tls-server-name",
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
_TERRAFORM_GLOBAL_OPTIONS = frozenset({"-chdir"})
_PULUMI_GLOBAL_OPTIONS = frozenset({"--cwd", "-c", "--stack", "-s"})

_DOCKER_SYSTEM_PRUNE = _executable_matcher(
    _DOCKER_EXECUTABLES,
    "system",
    "prune",
    leading_options_with_values=_DOCKER_GLOBAL_OPTIONS,
    interspersed_flags=_DOCKER_GLOBAL_FLAGS,
)
_DOCKER_FORCE_REMOVE = AnyMatcher(
    matchers=tuple(
        _executable_matcher(
            _DOCKER_EXECUTABLES,
            *subcommands,
            required_flags=frozenset({flag}),
            leading_options_with_values=_DOCKER_GLOBAL_OPTIONS,
            interspersed_flags=_DOCKER_GLOBAL_FLAGS,
        )
        for subcommands in (("rm",), ("container", "rm"))
        for flag in ("--force", "-f")
    )
)
_DOCKER_PRIVILEGED_RUN = AnyMatcher(
    matchers=(
        _executable_matcher(
            _DOCKER_EXECUTABLES,
            "run",
            required_flags=frozenset({"--privileged"}),
            leading_options_with_values=_DOCKER_GLOBAL_OPTIONS,
            interspersed_flags=_DOCKER_GLOBAL_FLAGS,
        ),
        _executable_matcher(
            _DOCKER_EXECUTABLES,
            "container",
            "run",
            required_flags=frozenset({"--privileged"}),
            leading_options_with_values=_DOCKER_GLOBAL_OPTIONS,
            interspersed_flags=_DOCKER_GLOBAL_FLAGS,
        ),
    )
)
_KUBECTL_DELETE = _executable_matcher(
    _KUBECTL_EXECUTABLES,
    "delete",
    leading_options_with_values=_KUBECTL_GLOBAL_OPTIONS,
    interspersed_flags=_KUBECTL_GLOBAL_FLAGS,
)
_KUBECTL_DRAIN = _executable_matcher(
    _KUBECTL_EXECUTABLES,
    "drain",
    leading_options_with_values=_KUBECTL_GLOBAL_OPTIONS,
    interspersed_flags=_KUBECTL_GLOBAL_FLAGS,
)
_HELM_UNINSTALL = _executable_matcher(
    _HELM_EXECUTABLES,
    "uninstall",
    leading_options_with_values=_HELM_GLOBAL_OPTIONS,
    interspersed_flags=_HELM_GLOBAL_FLAGS,
)
_TERRAFORM_DESTROY = _executable_matcher(
    frozenset({"terraform", "tofu"}),
    "destroy",
    leading_options_with_values=_TERRAFORM_GLOBAL_OPTIONS,
)
_TERRAFORM_APPLY_DESTROY = _executable_matcher(
    frozenset({"terraform", "tofu"}),
    "apply",
    required_flags=frozenset({"-destroy"}),
    leading_options_with_values=_TERRAFORM_GLOBAL_OPTIONS,
)
_PULUMI_DESTROY = _executable_matcher(
    frozenset({"pulumi"}),
    "destroy",
    leading_options_with_values=_PULUMI_GLOBAL_OPTIONS,
)
_INFRASTRUCTURE_DESTROY = AnyMatcher(
    matchers=(_TERRAFORM_DESTROY, _TERRAFORM_APPLY_DESTROY, _PULUMI_DESTROY)
)


DOMAIN_COMMAND_RULES = (
    _rule(
        rule_id="command.container-runtime.system-prune",
        title="Container system prune",
        description=(
            "Identifies broad cleanup of unused containers, networks, images, build cache, and optional volumes."
        ),
        matcher=_DOCKER_SYSTEM_PRUNE,
        action_class="docker-sensitive command",
        risk_classes=("destructive_shell",),
        safer_alternative="List the targeted container resources and prune one resource class at a time.",
        safe_variants=(_help_variant(_DOCKER_SYSTEM_PRUNE),),
    ),
    _rule(
        rule_id="command.container-runtime.forced-container-removal",
        title="Forced container removal",
        description="Identifies forced removal that can terminate a running container without a graceful stop.",
        matcher=_DOCKER_FORCE_REMOVE,
        action_class="docker-sensitive command",
        risk_classes=("destructive_shell",),
        safer_alternative="Stop the named container gracefully, inspect it, then remove that exact container.",
        safe_variants=(_help_variant(_DOCKER_FORCE_REMOVE),),
    ),
    _rule(
        rule_id="command.container-runtime.privileged-run",
        title="Privileged container execution",
        description="Identifies containers launched with broad host-level privileges.",
        matcher=_DOCKER_PRIVILEGED_RUN,
        action_class="docker-sensitive command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Grant only the required capabilities and keep host devices and filesystems isolated.",
        severity="critical",
        safe_variants=(_help_variant(_DOCKER_PRIVILEGED_RUN),),
    ),
    _rule(
        rule_id="command.kubernetes-operations.delete-resources",
        title="Kubernetes resource deletion",
        description="Identifies deletion of live cluster resources.",
        matcher=_KUBECTL_DELETE,
        action_class="Kubernetes destructive command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Run a client-side dry run and review the exact resource names and namespace first.",
        safe_variants=(
            _help_variant(_KUBECTL_DELETE),
            kubernetes_dry_run_variant(_KUBECTL_DELETE, "Kubernetes delete preview"),
        ),
    ),
    _rule(
        rule_id="command.kubernetes-operations.drain-node",
        title="Kubernetes node drain",
        description="Identifies node drains that evict workloads and make a node unschedulable.",
        matcher=_KUBECTL_DRAIN,
        action_class="Kubernetes destructive command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Preview the drain and verify disruption budgets, node identity, and workload scope first.",
        safe_variants=(
            _help_variant(_KUBECTL_DRAIN),
            kubernetes_dry_run_variant(_KUBECTL_DRAIN, "Kubernetes drain preview"),
        ),
    ),
    _rule(
        rule_id="command.kubernetes-operations.helm-uninstall",
        title="Helm release removal",
        description="Identifies uninstall operations that remove a release and its managed cluster resources.",
        matcher=_HELM_UNINSTALL,
        action_class="Kubernetes destructive command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Run Helm uninstall with dry-run and confirm the release and namespace first.",
        safe_variants=(
            _help_variant(_HELM_UNINSTALL),
            flag_variant(
                _HELM_UNINSTALL,
                variant_id="dry-run",
                title="Helm uninstall preview",
                required_flags=frozenset({"--dry-run"}),
                required_flags_in_all_arguments=True,
                fail_secure_unknown_options=True,
            ),
        ),
    ),
    _rule(
        rule_id="command.infrastructure-as-code.destroy",
        title="Infrastructure teardown",
        description="Identifies infrastructure-as-code commands that destroy managed resources.",
        matcher=_INFRASTRUCTURE_DESTROY,
        action_class="infrastructure destructive command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Generate and review a destroy preview for the selected workspace or stack first.",
        severity="critical",
        safe_variants=(
            _help_variant(_INFRASTRUCTURE_DESTROY),
            flag_variant(
                _PULUMI_DESTROY,
                variant_id="preview-only",
                title="Pulumi destroy preview",
                required_flags=frozenset({"--preview-only"}),
            ),
        ),
    ),
    *CONTAINER_COMMON_COMMAND_RULES,
    *KUBERNETES_COMMON_COMMAND_RULES,
)

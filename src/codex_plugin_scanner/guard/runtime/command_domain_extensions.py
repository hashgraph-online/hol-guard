"""Structured rules and metadata for infrastructure command extensions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TypedDict

from .command_rules import (
    AnyMatcher,
    CommandRuleSeverity,
    CommandSafetyRule,
    CommandSafeVariant,
    ExecutableMatcher,
)


@dataclass(frozen=True, slots=True)
class DomainCommandExtensionSpec:
    """Static metadata for a directly enforced command domain."""

    extension_id: str
    name: str
    description: str
    action_classes: tuple[str, ...]
    risk_classes: tuple[str, ...]
    safer_alternatives: tuple[str, ...]
    reference_urls: tuple[str, ...]


class DomainCommandExtensionValues(TypedDict):
    """Constructor values for one domain command extension."""

    extension_id: str
    version: str
    name: str
    description: str
    action_classes: tuple[str, ...]
    risk_classes: tuple[str, ...]
    safer_alternatives: tuple[str, ...]
    rules: tuple[CommandSafetyRule, ...]
    reference_urls: tuple[str, ...]


_DOCKER_GLOBAL_OPTIONS = frozenset({"--config", "--context", "--host", "-h", "--log-level"})
_KUBECTL_GLOBAL_OPTIONS = frozenset(
    {"--as", "--as-group", "--cluster", "--context", "--kubeconfig", "--namespace", "-n", "--server", "--user"}
)
_HELM_GLOBAL_OPTIONS = frozenset({"--kube-context", "--kubeconfig", "--namespace", "-n", "--registry-config"})
_TERRAFORM_GLOBAL_OPTIONS = frozenset({"-chdir"})
_PULUMI_GLOBAL_OPTIONS = frozenset({"--cwd", "-c", "--stack", "-s"})
_EMPTY_STRING_SET: frozenset[str] = frozenset()


def _executable_matcher(
    executables: frozenset[str],
    *subcommands: str,
    required_flags: frozenset[str] = _EMPTY_STRING_SET,
    leading_options_with_values: frozenset[str] = _EMPTY_STRING_SET,
) -> ExecutableMatcher:
    return ExecutableMatcher(
        executables=executables,
        subcommands=subcommands,
        required_flags=required_flags,
        allow_leading_options=bool(leading_options_with_values),
        leading_options_with_values=leading_options_with_values,
    )


def _flag_variants(
    executables: frozenset[str],
    *subcommands: str,
    flags: frozenset[str],
    leading_options_with_values: frozenset[str] = _EMPTY_STRING_SET,
) -> tuple[ExecutableMatcher, ...]:
    return tuple(
        _executable_matcher(
            executables,
            *subcommands,
            required_flags=frozenset({flag}),
            leading_options_with_values=leading_options_with_values,
        )
        for flag in sorted(flags)
    )


def _help_variant(matcher: ExecutableMatcher) -> CommandSafeVariant:
    return CommandSafeVariant(
        variant_id="help",
        title="Command help",
        matcher=ExecutableMatcher(
            executables=matcher.executables,
            subcommands=matcher.subcommands,
            required_flags=frozenset({"--help"}),
            allow_leading_options=matcher.allow_leading_options,
            leading_options_with_values=matcher.leading_options_with_values,
        ),
    )


def _help_variant_for_any(matcher: AnyMatcher) -> CommandSafeVariant:
    help_matchers = tuple(
        ExecutableMatcher(
            executables=child.executables,
            subcommands=child.subcommands,
            required_flags=frozenset({"--help"}),
            allow_leading_options=child.allow_leading_options,
            leading_options_with_values=child.leading_options_with_values,
        )
        for child in matcher.matchers
        if isinstance(child, ExecutableMatcher)
    )
    if len(help_matchers) != len(matcher.matchers):
        raise ValueError("Help variants require executable matchers")
    return CommandSafeVariant(
        variant_id="help",
        title="Command help",
        matcher=AnyMatcher(matchers=help_matchers),
    )


def _kubernetes_dry_run_variant(subcommand: str) -> CommandSafeVariant:
    return CommandSafeVariant(
        variant_id="dry-run",
        title=f"Kubernetes {subcommand} preview",
        matcher=AnyMatcher(
            matchers=tuple(
                _executable_matcher(
                    frozenset({"kubectl"}),
                    subcommand,
                    required_flags=frozenset({f"--dry-run={mode}"}),
                    leading_options_with_values=_KUBECTL_GLOBAL_OPTIONS,
                )
                for mode in ("client", "server")
            )
        ),
    )


def _rule(
    *,
    rule_id: str,
    title: str,
    description: str,
    matcher: ExecutableMatcher | AnyMatcher,
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


_DOCKER_SYSTEM_PRUNE = _executable_matcher(
    frozenset({"docker"}),
    "system",
    "prune",
    leading_options_with_values=_DOCKER_GLOBAL_OPTIONS,
)
_DOCKER_FORCE_REMOVE = AnyMatcher(
    matchers=(
        *_flag_variants(
            frozenset({"docker"}),
            "rm",
            flags=frozenset({"--force", "-f"}),
            leading_options_with_values=_DOCKER_GLOBAL_OPTIONS,
        ),
        *_flag_variants(
            frozenset({"docker"}),
            "container",
            "rm",
            flags=frozenset({"--force", "-f"}),
            leading_options_with_values=_DOCKER_GLOBAL_OPTIONS,
        ),
    )
)
_DOCKER_PRIVILEGED_RUN = AnyMatcher(
    matchers=(
        _executable_matcher(
            frozenset({"docker"}),
            "run",
            required_flags=frozenset({"--privileged"}),
            leading_options_with_values=_DOCKER_GLOBAL_OPTIONS,
        ),
        _executable_matcher(
            frozenset({"docker"}),
            "container",
            "run",
            required_flags=frozenset({"--privileged"}),
            leading_options_with_values=_DOCKER_GLOBAL_OPTIONS,
        ),
    )
)
_KUBECTL_DELETE = _executable_matcher(
    frozenset({"kubectl"}),
    "delete",
    leading_options_with_values=_KUBECTL_GLOBAL_OPTIONS,
)
_KUBECTL_DRAIN = _executable_matcher(
    frozenset({"kubectl"}),
    "drain",
    leading_options_with_values=_KUBECTL_GLOBAL_OPTIONS,
)
_HELM_UNINSTALL = _executable_matcher(
    frozenset({"helm"}),
    "uninstall",
    leading_options_with_values=_HELM_GLOBAL_OPTIONS,
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
        safe_variants=(_help_variant_for_any(_DOCKER_FORCE_REMOVE),),
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
        safe_variants=(_help_variant_for_any(_DOCKER_PRIVILEGED_RUN),),
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
            _kubernetes_dry_run_variant("delete"),
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
            _kubernetes_dry_run_variant("drain"),
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
            CommandSafeVariant(
                variant_id="dry-run",
                title="Helm uninstall preview",
                matcher=_executable_matcher(
                    frozenset({"helm"}),
                    "uninstall",
                    required_flags=frozenset({"--dry-run"}),
                    leading_options_with_values=_HELM_GLOBAL_OPTIONS,
                ),
            ),
        ),
    ),
    _rule(
        rule_id="command.infrastructure-as-code.destroy",
        title="Infrastructure teardown",
        description="Identifies infrastructure-as-code commands that destroy managed resources.",
        matcher=AnyMatcher(matchers=(_TERRAFORM_DESTROY, _TERRAFORM_APPLY_DESTROY, _PULUMI_DESTROY)),
        action_class="infrastructure destructive command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Generate and review a destroy preview for the selected workspace or stack first.",
        severity="critical",
        safe_variants=(
            CommandSafeVariant(
                variant_id="help",
                title="Command help",
                matcher=AnyMatcher(
                    matchers=(
                        _executable_matcher(
                            frozenset({"terraform", "tofu"}),
                            "destroy",
                            required_flags=frozenset({"--help"}),
                            leading_options_with_values=_TERRAFORM_GLOBAL_OPTIONS,
                        ),
                        _executable_matcher(
                            frozenset({"terraform", "tofu"}),
                            "apply",
                            required_flags=frozenset({"--help"}),
                            leading_options_with_values=_TERRAFORM_GLOBAL_OPTIONS,
                        ),
                        _executable_matcher(
                            frozenset({"pulumi"}),
                            "destroy",
                            required_flags=frozenset({"--help"}),
                            leading_options_with_values=_PULUMI_GLOBAL_OPTIONS,
                        ),
                    )
                ),
            ),
            CommandSafeVariant(
                variant_id="preview-only",
                title="Pulumi destroy preview",
                matcher=_executable_matcher(
                    frozenset({"pulumi"}),
                    "destroy",
                    required_flags=frozenset({"--preview-only"}),
                    leading_options_with_values=_PULUMI_GLOBAL_OPTIONS,
                ),
            ),
        ),
    ),
)


DOMAIN_COMMAND_EXTENSION_SPECS = (
    DomainCommandExtensionSpec(
        extension_id="command.kubernetes-operations",
        name="Kubernetes operation protection",
        description="Reviews cluster operations that delete resources, evict workloads, or remove releases.",
        action_classes=("Kubernetes destructive command",),
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternatives=(
            "Use client-side dry runs and explicit namespaces before mutating cluster resources.",
            "Review disruption budgets and exact workload scope before draining nodes.",
        ),
        reference_urls=(
            "https://kubernetes.io/docs/reference/kubectl/generated/kubectl_delete/",
            "https://kubernetes.io/docs/reference/kubectl/generated/kubectl_drain/",
            "https://helm.sh/docs/helm/helm_uninstall/",
        ),
    ),
    DomainCommandExtensionSpec(
        extension_id="command.infrastructure-as-code",
        name="Infrastructure-as-code protection",
        description="Reviews infrastructure teardown through Terraform, OpenTofu, and Pulumi.",
        action_classes=("infrastructure destructive command",),
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternatives=(
            "Create and inspect a saved plan or preview before applying destructive changes.",
            "Confirm the selected workspace, stack, account, and region before teardown.",
        ),
        reference_urls=(
            "https://developer.hashicorp.com/terraform/cli/commands/destroy",
            "https://opentofu.org/docs/cli/commands/destroy/",
            "https://www.pulumi.com/docs/iac/cli/commands/pulumi_destroy/",
        ),
    ),
)


def domain_command_extension_values(spec: DomainCommandExtensionSpec) -> DomainCommandExtensionValues:
    """Return typed registry constructor values for one domain spec."""

    rules = tuple(rule for rule in DOMAIN_COMMAND_RULES if rule.rule_id.startswith(f"{spec.extension_id}."))
    return {
        "extension_id": spec.extension_id,
        "version": "1.0.0",
        "name": spec.name,
        "description": spec.description,
        "action_classes": spec.action_classes,
        "risk_classes": spec.risk_classes,
        "safer_alternatives": spec.safer_alternatives,
        "rules": rules,
        "reference_urls": spec.reference_urls,
    }

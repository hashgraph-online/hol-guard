"""Metadata contracts for infrastructure command extensions."""

from __future__ import annotations

from .command_extension_specs import CommandExtensionSpec

DOMAIN_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.kubernetes-operations",
        name="Kubernetes operation protection",
        description=(
            "Reviews cluster mutations, remote execution, file transfer, tunnels, certificate decisions, "
            "and Helm lifecycle operations."
        ),
        action_classes=(
            "Kubernetes destructive command",
            "Kubernetes remote execution command",
            "Kubernetes network tunnel command",
            "Kubernetes remote file transfer command",
            "Kubernetes security administration command",
        ),
        risk_classes=("destructive_shell", "network_egress", "execution", "local_secret_read"),
        safer_alternatives=(
            "Use client-side dry runs and explicit namespaces before mutating cluster resources.",
            "Review disruption budgets and exact workload scope before draining nodes.",
            "Use the narrowest remote session, file path, and network binding required for operational work.",
        ),
        reference_urls=(
            "https://kubernetes.io/docs/reference/kubectl/generated/kubectl_apply/",
            "https://kubernetes.io/docs/reference/kubectl/generated/kubectl_delete/",
            "https://kubernetes.io/docs/reference/kubectl/generated/kubectl_drain/",
            "https://kubernetes.io/docs/reference/kubectl/generated/kubectl_exec/",
            "https://kubernetes.io/docs/reference/kubectl/generated/kubectl_port-forward/",
            "https://helm.sh/docs/helm/helm_install/",
            "https://helm.sh/docs/helm/helm_upgrade/",
            "https://helm.sh/docs/helm/helm_uninstall/",
        ),
    ),
    CommandExtensionSpec(
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

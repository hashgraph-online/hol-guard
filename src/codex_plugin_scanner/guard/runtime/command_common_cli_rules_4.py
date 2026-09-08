"""Common CLI command rules, batch 4."""

from __future__ import annotations

from .command_common_cli_matchers import (
    _ALT_CONTAINER_PRIVILEGED,
    _IAC_EXPANSION,
    _OC_DESTRUCTIVE,
    _OC_EXECUTION,
    _OC_FLAGS,
    _OC_OPTIONS,
    _OC_TRANSFER,
    _OC_TUNNEL,
)
from .command_common_cli_matchers_extra import MYSQL_MUTATION, PSQL_MUTATION
from .command_common_cli_rule_support import help_variants, rule
from .command_common_cli_support import _path_bundle
from .command_extension_matchers import safe_option_variant
from .command_rules import CommandSafetyRule

_OC_DELETE_PREVIEW = _path_bundle(
    ("oc",),
    (("delete",),),
    options=_OC_OPTIONS,
    flags=_OC_FLAGS,
)

COMMON_CLI_COMMAND_RULES_4: tuple[CommandSafetyRule, ...] = (
    rule(
        extension_id="command.container-runtime",
        suffix="alternate-runtime-privileged-run",
        title="Alternate container privileged execution",
        description="Identifies Podman or nerdctl containers launched with broad host privileges.",
        matcher=_ALT_CONTAINER_PRIVILEGED,
        action_class="docker-sensitive command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Grant only required capabilities and keep host devices and filesystems isolated.",
        severity="critical",
        safe_variants=help_variants(_ALT_CONTAINER_PRIVILEGED),
        example_command="podman run --privileged alpine",
    ),
    rule(
        extension_id="command.kubernetes-operations",
        suffix="openshift-destructive",
        title="OpenShift destructive operation",
        description="Identifies resource deletion and node drains through oc.",
        matcher=_OC_DESTRUCTIVE,
        action_class="Kubernetes destructive command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Review the exact project, resource, or node before destructive operations.",
        severity="critical",
        safe_variants=(
            *help_variants(_OC_DESTRUCTIVE, short=True),
            safe_option_variant(
                _OC_DELETE_PREVIEW,
                variant_id="dry-run",
                title="OpenShift delete preview",
                option="--dry-run",
                allowed_values=frozenset({"client", "server"}),
            ),
        ),
        example_command="oc delete deployment api",
    ),
    rule(
        extension_id="command.kubernetes-operations",
        suffix="openshift-remote-execution",
        title="OpenShift remote execution",
        description="Identifies remote command execution through oc exec or oc rsh.",
        matcher=_OC_EXECUTION,
        action_class="Kubernetes remote execution command",
        risk_classes=("execution", "network_egress"),
        safer_alternative="Use the narrowest pod, container, and remote command required for diagnostics.",
        safe_variants=help_variants(_OC_EXECUTION, short=True),
        example_command="oc exec deployment/api -- sh",
    ),
    rule(
        extension_id="command.kubernetes-operations",
        suffix="openshift-port-forward",
        title="OpenShift network tunnel",
        description="Identifies local-to-cluster network tunnels created through oc port-forward.",
        matcher=_OC_TUNNEL,
        action_class="Kubernetes network tunnel command",
        risk_classes=("network_egress",),
        safer_alternative="Bind only the required local interface and port for the shortest duration.",
        safe_variants=help_variants(_OC_TUNNEL, short=True),
        example_command="oc port-forward service/api 8080:80",
    ),
    rule(
        extension_id="command.kubernetes-operations",
        suffix="openshift-file-transfer",
        title="OpenShift remote file transfer",
        description="Identifies file synchronization between local and cluster filesystems through oc rsync.",
        matcher=_OC_TRANSFER,
        action_class="Kubernetes remote file transfer command",
        risk_classes=("network_egress",),
        safer_alternative="Transfer only reviewed paths and confirm direction and destination first.",
        safe_variants=help_variants(_OC_TRANSFER, short=True),
        example_command="oc rsync ./out pod:/tmp/out",
    ),
    rule(
        extension_id="command.infrastructure-as-code",
        suffix="additional-teardown",
        title="Additional infrastructure teardown",
        description="Identifies AWS CDK, SAM, and Serverless Framework teardown commands.",
        matcher=_IAC_EXPANSION,
        action_class="infrastructure destructive command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Review the exact stack, stage, account, and region before teardown.",
        severity="critical",
        safe_variants=help_variants(_IAC_EXPANSION),
        example_command="npx cdk destroy",
    ),
    rule(
        extension_id="command.database.postgresql",
        suffix="direct-drop",
        title="PostgreSQL direct destructive SQL",
        description="Identifies destructive SQL supplied through psql -c/--command, including attached values.",
        matcher=PSQL_MUTATION,
        action_class="PostgreSQL destructive command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Inspect the target object and current backup before destructive SQL through psql.",
        severity="critical",
        example_command='psql -c "DROP DATABASE production"',
    ),
    rule(
        extension_id="command.database.mysql",
        suffix="direct-drop",
        title="MySQL direct destructive SQL",
        description="Identifies destructive SQL supplied through mysql -e/--execute, including attached values.",
        matcher=MYSQL_MUTATION,
        action_class="MySQL destructive command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Inspect the target object and current backup before destructive SQL through mysql.",
        severity="critical",
        example_command='mysql -e "DROP DATABASE production"',
    ),
)

"""Common CLI command rules, batch 3."""

from __future__ import annotations

from .command_common_cli_matchers import (
    _ALT_CONTAINER_CLEANUP,
    _ANSIBLE_VAULT,
    _CLOUD_CREDENTIAL_MUTATION,
    _CLOUD_SECRET_READ,
    _DOCTL_DELETE,
    _OP_DELETE,
    _OP_INJECT,
    _OP_READ,
    _PACKAGE_PUBLISH,
    _RAILWAY_CHANGE,
)
from .command_common_cli_matchers_extra import ANSIBLE_EXECUTION_REFINED
from .command_common_cli_rule_support import help_variants, rule
from .command_rules import AnyMatcher, CommandSafetyRule, ExecutableMatcher

_CLOUD_CREDENTIAL_MUTATION_REFINED = AnyMatcher(
    matchers=tuple(
        matcher
        for matcher in _CLOUD_CREDENTIAL_MUTATION.matchers
        if not (
            isinstance(matcher, ExecutableMatcher)
            and "gcloud" in matcher.executables
            and matcher.subcommands == ("iam", "service-accounts", "keys", "delete")
        )
    )
)

COMMON_CLI_COMMAND_RULES_3: tuple[CommandSafetyRule, ...] = (
    rule(
        extension_id="command.platform.railway",
        suffix="remote-change",
        title="Railway deployment, variable, or shell operation",
        description="Identifies deploys, variable mutation, and secret-populated shells through Railway CLI.",
        matcher=_RAILWAY_CHANGE,
        action_class="Railway production command",
        risk_classes=("execution", "network_egress", "local_secret_read"),
        safer_alternative="Confirm the exact project, service, environment, and variable scope first.",
        safe_variants=help_variants(_RAILWAY_CHANGE, short=True),
        example_command="railway up",
    ),
    rule(
        extension_id="command.configuration-management.ansible",
        suffix="remote-execution",
        title="Ansible remote execution",
        description="Identifies ad-hoc, playbook, or pull-based Ansible execution while excluding read-only modes.",
        matcher=ANSIBLE_EXECUTION_REFINED,
        action_class="Ansible remote execution command",
        risk_classes=("execution", "network_egress", "destructive_shell"),
        safer_alternative="Limit inventory and hosts and inspect playbook changes before execution.",
        example_command="ansible-playbook -i production site.yml",
    ),
    rule(
        extension_id="command.configuration-management.ansible",
        suffix="vault-secret",
        title="Ansible Vault secret access",
        description="Identifies decrypting, viewing, editing, or rekeying encrypted Ansible Vault data.",
        matcher=_ANSIBLE_VAULT,
        action_class="Ansible Vault secret command",
        risk_classes=("local_secret_read", "destructive_shell"),
        safer_alternative="Decrypt only the required file in a controlled context and avoid persisting plaintext.",
        safe_variants=help_variants(_ANSIBLE_VAULT, short=True),
        example_command="ansible-vault view group_vars/prod.yml",
    ),
    rule(
        extension_id="command.cloud.digitalocean",
        suffix="resource-deletion",
        title="DigitalOcean resource deletion",
        description="Identifies deletion of compute, Kubernetes, database, network, storage, and app resources.",
        matcher=_DOCTL_DELETE,
        action_class="DigitalOcean destructive command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Inspect the exact context, resource, dependent data, and backups before deletion.",
        severity="critical",
        safe_variants=help_variants(_DOCTL_DELETE, short=True),
        example_command="doctl compute droplet delete 123456",
    ),
    rule(
        extension_id="command.secrets.1password",
        suffix="secret-read",
        title="1Password secret read",
        description="Identifies reads that can return item or document secret material through op.",
        matcher=_OP_READ,
        action_class="1Password secret read command",
        risk_classes=("local_secret_read", "network_egress"),
        safer_alternative="Read only the required field or secret reference rather than the full item.",
        safe_variants=help_variants(_OP_READ, short=True),
        example_command="op read op://Production/API/token",
    ),
    rule(
        extension_id="command.secrets.1password",
        suffix="secret-injection",
        title="1Password secret injection",
        description="Identifies injecting secrets into subprocesses or rendered configuration.",
        matcher=_OP_INJECT,
        action_class="1Password secret injection command",
        risk_classes=("local_secret_read", "execution"),
        safer_alternative="Inject only required references into the narrowest subprocess or destination.",
        safe_variants=help_variants(_OP_INJECT, short=True),
        example_command="op run -- env",
    ),
    rule(
        extension_id="command.secrets.1password",
        suffix="destructive",
        title="1Password destructive operation",
        description="Identifies deletion of items, documents, or vaults through op.",
        matcher=_OP_DELETE,
        action_class="1Password destructive command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Inspect the exact object and recovery options before deleting it.",
        severity="critical",
        safe_variants=help_variants(_OP_DELETE, short=True),
        example_command="op item delete credential-id",
    ),
    rule(
        extension_id="command.package-publication",
        suffix="publish-or-yank",
        title="Package registry publication mutation",
        description="Identifies package publish, unpublish, yank, and upload operations across common registries.",
        matcher=_PACKAGE_PUBLISH,
        action_class="package publication command",
        risk_classes=("supply_chain", "network_egress", "destructive_shell"),
        safer_alternative="Verify package identity, version, registry, provenance, and signing before publication.",
        severity="critical",
        safe_variants=help_variants(_PACKAGE_PUBLISH),
        example_command="npm publish",
    ),
    rule(
        extension_id="command.cloud-secrets",
        suffix="secret-read",
        title="Cloud secret read",
        description="Identifies secret retrieval through AWS, Google Cloud, or Azure CLIs.",
        matcher=_CLOUD_SECRET_READ,
        action_class="cloud secret read command",
        risk_classes=("local_secret_read", "network_egress"),
        safer_alternative="Request only the exact secret or decrypted parameter required for the operation.",
        safe_variants=help_variants(_CLOUD_SECRET_READ),
        example_command="aws secretsmanager get-secret-value --secret-id production/api",
    ),
    rule(
        extension_id="command.cloud-secrets",
        suffix="credential-mutation",
        title="Cloud credential mutation",
        description=(
            "Identifies access-key or service-account credential creation, deletion, or reset without stealing "
            "provider-owned deletion operations."
        ),
        matcher=_CLOUD_CREDENTIAL_MUTATION_REFINED,
        action_class="cloud credential mutation command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Confirm principal scope, active credentials, and rotation plan before mutation.",
        severity="critical",
        safe_variants=help_variants(_CLOUD_CREDENTIAL_MUTATION_REFINED),
        example_command="aws iam create-access-key --user-name deployer",
    ),
    rule(
        extension_id="command.container-runtime",
        suffix="alternate-runtime-cleanup",
        title="Alternate container runtime cleanup",
        description="Identifies broad Podman and nerdctl prune operations.",
        matcher=_ALT_CONTAINER_CLEANUP,
        action_class="docker-sensitive command",
        risk_classes=("destructive_shell",),
        safer_alternative="List exact resources and prune the narrowest resource class first.",
        severity="critical",
        safe_variants=help_variants(_ALT_CONTAINER_CLEANUP),
        example_command="podman system prune",
    ),
)

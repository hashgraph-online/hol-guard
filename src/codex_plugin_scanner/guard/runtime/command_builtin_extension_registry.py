"""Typed assembly values for Guard's built-in command extension registry."""

from __future__ import annotations

from typing import Final

from .command_builtin_extension_catalog import DIRECT_COMMAND_EXTENSION_VALUES
from .command_builtin_rules import rules_for_extension
from .command_extension_specs import CommandExtensionSpec, CommandExtensionValues, command_extension_values
from .command_package_extensions import PACKAGE_COMMAND_EXTENSION_SPECS, PackageCommandExtensionSpec


def _core_values(spec: CommandExtensionSpec) -> CommandExtensionValues:
    return command_extension_values(spec, rules_for_extension(spec.extension_id))


def _package_values(spec: PackageCommandExtensionSpec) -> CommandExtensionValues:
    return command_extension_values(
        CommandExtensionSpec(
            extension_id=spec.extension_id,
            name=spec.name,
            description=spec.description,
            action_classes=(),
            risk_classes=("supply_chain",),
            safer_alternatives=(
                "Use the existing project manifest and lockfile instead of an unpinned package source.",
                "Review package provenance and advisory evidence before installation or one-shot execution.",
            ),
            reference_urls=spec.reference_urls,
            delegated_protection="package-firewall",
            ecosystem_ids=spec.ecosystem_ids,
            executables=spec.executables,
            project_markers=spec.project_markers,
        ),
        (),
    )


_CORE_COMMAND_EXTENSION_SPECS: Final[tuple[CommandExtensionSpec, ...]] = (
    CommandExtensionSpec(
        extension_id="command.filesystem",
        name="Filesystem protection",
        description="Reviews recursive deletion and access-control changes across filesystem trees.",
        action_classes=("filesystem destructive command",),
        risk_classes=("destructive_shell",),
        safer_alternatives=(
            "List and review exact target paths before recursive mutation.",
            "Limit permission and ownership changes to the narrowest path.",
        ),
        reference_urls=(),
        required=True,
    ),
    CommandExtensionSpec(
        extension_id="command.git",
        name="Git protection",
        description="Reviews local and remote Git operations that can discard work or replace history.",
        action_classes=("git destructive command",),
        risk_classes=("destructive_shell",),
        safer_alternatives=(
            "Preview affected files and refs before destructive repository operations.",
            "Create a temporary branch or stash before discarding local work.",
        ),
        reference_urls=(),
        required=True,
    ),
    CommandExtensionSpec(
        extension_id="command.system",
        name="System protection",
        description="Reviews storage formatting and operating-system power-state mutations.",
        action_classes=("system destructive command",),
        risk_classes=("destructive_shell",),
        safer_alternatives=("Inspect the exact device or host state with a read-only command first.",),
        reference_urls=(),
        required=True,
    ),
    CommandExtensionSpec(
        extension_id="command.windows",
        name="Windows protection",
        description="Reviews destructive Windows storage and operating-system commands.",
        action_classes=("windows destructive command",),
        risk_classes=("destructive_shell",),
        safer_alternatives=("Use read-only PowerShell inventory commands to verify exact targets first.",),
        reference_urls=(),
        required=True,
    ),
    CommandExtensionSpec(
        extension_id="command.container-runtime",
        name="Container runtime protection",
        description="Reviews container operations that can expose credentials, publish data, or mutate host state.",
        action_classes=("docker-sensitive command", "Docker client config access"),
        risk_classes=("network_egress", "destructive_shell", "local_secret_read"),
        safer_alternatives=(
            "Use a pinned image and a read-only container filesystem where possible.",
            "Pass only the specific secret or file required by the container.",
        ),
        reference_urls=(
            "https://docs.docker.com/reference/cli/docker/system/prune/",
            "https://docs.docker.com/reference/cli/docker/container/rm/",
            "https://docs.docker.com/reference/cli/docker/container/run/",
        ),
    ),
    CommandExtensionSpec(
        extension_id="command.data-protection",
        name="Command data protection",
        description="Detects shell flows that can send credentials or local file contents to a network destination.",
        action_classes=("credential exfiltration shell command", "shell file upload command"),
        risk_classes=("data_flow_exfiltration", "credential_exfiltration", "network_egress"),
        safer_alternatives=(
            "Send an explicit non-secret value instead of piping local files or environment output.",
            "Use a destination allowlist and review the exact payload before transmission.",
        ),
        reference_urls=(),
    ),
    CommandExtensionSpec(
        extension_id="command.encoded-execution",
        name="Encoded execution protection",
        description=(
            "Reviews decode-and-execute flows whose effective program is hidden from normal command inspection."
        ),
        action_classes=("encoded or encrypted shell command",),
        risk_classes=("encoded_execution",),
        safer_alternatives=("Decode the payload to a file, inspect it, then invoke the reviewed file directly.",),
        reference_urls=(),
    ),
    CommandExtensionSpec(
        extension_id="command.guard-self-protection",
        name="Guard self-protection",
        description="Prevents commands from authorizing their own Guard approval or weakening protected Guard state.",
        action_classes=("Guard approval self-authorization command",),
        risk_classes=("policy_bypass",),
        safer_alternatives=("Approve the pending request through Guard's authenticated approval surface.",),
        reference_urls=(),
        required=True,
    ),
    CommandExtensionSpec(
        extension_id="command.kubernetes-secrets",
        name="Kubernetes secret protection",
        description="Reviews Kubernetes CLI operations that can reveal cluster or application secrets.",
        action_classes=("Kubernetes secret read command",),
        risk_classes=("local_secret_read",),
        safer_alternatives=("Request only the required non-secret field or metadata instead of the Secret payload.",),
        reference_urls=("https://kubernetes.io/docs/reference/kubectl/generated/kubectl_get/",),
    ),
    CommandExtensionSpec(
        extension_id="command.shell-mutations",
        name="Shell, Git, and filesystem protection",
        description="Reviews destructive shell, Git, filesystem, redirection, and protected configuration mutations.",
        action_classes=(
            "destructive shell command",
            "guard-managed config write",
            "sensitive local file write",
            "GitHub PR body shell substitution",
        ),
        risk_classes=("destructive_shell", "local_secret_read", "execution"),
        safer_alternatives=(
            "Use a dry run or preview mode before a destructive operation.",
            "Narrow the target path or Git ref and avoid recursive or forced mutation.",
            "Use a literal body file instead of shell substitution in command arguments.",
        ),
        reference_urls=(),
    ),
)

BUILT_IN_COMMAND_EXTENSION_VALUES: Final[tuple[CommandExtensionValues, ...]] = (
    *(_core_values(spec) for spec in _CORE_COMMAND_EXTENSION_SPECS),
    *DIRECT_COMMAND_EXTENSION_VALUES,
    *(_package_values(spec) for spec in PACKAGE_COMMAND_EXTENSION_SPECS),
)

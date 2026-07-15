"""Versioned metadata for Guard's built-in command safety extensions."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import final

COMMAND_EXTENSION_SCHEMA_VERSION = 1
_VERSION_PATTERN = re.compile(r"^[1-9][0-9]*\.[0-9]+\.[0-9]+$")

_ACTION_RISK_CLASSES: dict[str, tuple[str, ...]] = {
    "credential exfiltration shell command": (
        "data_flow_exfiltration",
        "credential_exfiltration",
        "network_egress",
    ),
    "guard-managed config write": ("destructive_shell",),
    "docker-sensitive command": ("network_egress", "destructive_shell"),
    "docker client config access": ("local_secret_read",),
    "encoded or encrypted shell command": ("encoded_execution",),
    "kubernetes secret read command": ("local_secret_read",),
    "shell file upload command": ("credential_exfiltration", "network_egress"),
    "sensitive local file write": ("destructive_shell", "local_secret_read"),
    "destructive shell command": ("destructive_shell",),
    "guard approval self-authorization command": ("policy_bypass",),
    "github pr body shell substitution": ("execution",),
}


def risk_classes_for_command_action(action_class: str) -> tuple[str, ...]:
    """Return the existing runtime risk classes for a command action class."""

    return _ACTION_RISK_CLASSES.get(action_class.strip().lower(), ())


@dataclass(frozen=True, slots=True)
class CommandSafetyExtension:
    """An inspectable capability boundary over existing command detection."""

    extension_id: str
    version: str
    name: str
    description: str
    action_classes: tuple[str, ...]
    risk_classes: tuple[str, ...]
    safer_alternatives: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": COMMAND_EXTENSION_SCHEMA_VERSION,
            "extension_id": self.extension_id,
            "version": self.version,
            "name": self.name,
            "description": self.description,
            "enabled": True,
            "source": "built-in",
            "action_classes": list(self.action_classes),
            "risk_classes": list(self.risk_classes),
            "safer_alternatives": list(self.safer_alternatives),
        }


@final
class CommandSafetyExtensionRegistry:
    """Validated, deterministic registry of command safety extensions."""

    def __init__(self, extensions: tuple[CommandSafetyExtension, ...]) -> None:
        ordered = tuple(sorted(extensions, key=lambda extension: extension.extension_id))
        by_id: dict[str, CommandSafetyExtension] = {}
        by_action_class: dict[str, CommandSafetyExtension] = {}
        for extension in ordered:
            _validate_extension(extension)
            if extension.extension_id in by_id:
                raise ValueError(f"Duplicate command safety extension ID: {extension.extension_id}")
            by_id[extension.extension_id] = extension
            for action_class in extension.action_classes:
                normalized_action_class = action_class.strip().lower()
                owner = by_action_class.get(normalized_action_class)
                if owner is not None:
                    ownership = f"{owner.extension_id} and {extension.extension_id}"
                    raise ValueError(f"Command action class {action_class!r} is owned by both {ownership}")
                by_action_class[normalized_action_class] = extension
                undeclared_risk_classes = set(risk_classes_for_command_action(action_class)).difference(
                    extension.risk_classes
                )
                if undeclared_risk_classes:
                    undeclared = ", ".join(sorted(undeclared_risk_classes))
                    message = " ".join(
                        (
                            f"Command safety extension {extension.extension_id} does not declare runtime",
                            f"risk classes for {action_class!r}: {undeclared}",
                        )
                    )
                    raise ValueError(message)
        self._extensions = ordered
        self._by_id = by_id
        self._by_action_class = by_action_class

    @property
    def extensions(self) -> tuple[CommandSafetyExtension, ...]:
        return self._extensions

    def get(self, extension_id: str) -> CommandSafetyExtension | None:
        return self._by_id.get(extension_id.strip().lower())

    def for_action_class(self, action_class: str) -> CommandSafetyExtension | None:
        return self._by_action_class.get(action_class.strip().lower())


def _validate_extension(extension: CommandSafetyExtension) -> None:
    if not extension.extension_id.startswith("command."):
        raise ValueError("Command safety extension IDs must start with 'command.'")
    if extension.extension_id != extension.extension_id.lower():
        raise ValueError("Command safety extension IDs must be lowercase")
    if not _VERSION_PATTERN.fullmatch(extension.version):
        raise ValueError(f"Invalid command safety extension version: {extension.version}")
    if not extension.name.strip() or not extension.description.strip():
        raise ValueError(f"Command safety extension {extension.extension_id} requires a name and description")
    if not extension.action_classes:
        raise ValueError(f"Command safety extension {extension.extension_id} must own an action class")
    if len(set(extension.action_classes)) != len(extension.action_classes):
        raise ValueError(f"Command safety extension {extension.extension_id} has duplicate action classes")
    if not extension.risk_classes:
        raise ValueError(f"Command safety extension {extension.extension_id} must declare a risk class")
    if len(set(extension.risk_classes)) != len(extension.risk_classes):
        raise ValueError(f"Command safety extension {extension.extension_id} has duplicate risk classes")
    if not extension.safer_alternatives:
        raise ValueError(f"Command safety extension {extension.extension_id} requires safer alternatives")


_BUILT_IN_EXTENSIONS = (
    CommandSafetyExtension(
        extension_id="command.container-runtime",
        version="1.0.0",
        name="Container runtime protection",
        description="Reviews container operations that can expose credentials, publish data, or mutate host state.",
        action_classes=("docker-sensitive command", "Docker client config access"),
        risk_classes=("network_egress", "destructive_shell", "local_secret_read"),
        safer_alternatives=(
            "Use a pinned image and a read-only container filesystem where possible.",
            "Pass only the specific secret or file required by the container.",
        ),
    ),
    CommandSafetyExtension(
        extension_id="command.data-protection",
        version="1.0.0",
        name="Command data protection",
        description="Detects shell flows that can send credentials or local file contents to a network destination.",
        action_classes=("credential exfiltration shell command", "shell file upload command"),
        risk_classes=("data_flow_exfiltration", "credential_exfiltration", "network_egress"),
        safer_alternatives=(
            "Send an explicit non-secret value instead of piping local files or environment output.",
            "Use a destination allowlist and review the exact payload before transmission.",
        ),
    ),
    CommandSafetyExtension(
        extension_id="command.encoded-execution",
        version="1.0.0",
        name="Encoded execution protection",
        description=(
            "Reviews decode-and-execute flows whose effective program is hidden from normal command inspection."
        ),
        action_classes=("encoded or encrypted shell command",),
        risk_classes=("encoded_execution",),
        safer_alternatives=("Decode the payload to a file, inspect it, then invoke the reviewed file directly.",),
    ),
    CommandSafetyExtension(
        extension_id="command.guard-self-protection",
        version="1.0.0",
        name="Guard self-protection",
        description="Prevents commands from authorizing their own Guard approval or weakening protected Guard state.",
        action_classes=("Guard approval self-authorization command",),
        risk_classes=("policy_bypass",),
        safer_alternatives=("Approve the pending request through Guard's authenticated approval surface.",),
    ),
    CommandSafetyExtension(
        extension_id="command.kubernetes-secrets",
        version="1.0.0",
        name="Kubernetes secret protection",
        description="Reviews Kubernetes CLI operations that can reveal cluster or application secrets.",
        action_classes=("Kubernetes secret read command",),
        risk_classes=("local_secret_read",),
        safer_alternatives=("Request only the required non-secret field or metadata instead of the Secret payload.",),
    ),
    CommandSafetyExtension(
        extension_id="command.shell-mutations",
        version="1.0.0",
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
    ),
)

BUILT_IN_COMMAND_EXTENSION_REGISTRY = CommandSafetyExtensionRegistry(_BUILT_IN_EXTENSIONS)

"""Versioned metadata for Guard's built-in command safety extensions."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import final

from .command_builtin_rules import COMMAND_ACTION_RISK_CLASSES, rules_for_extension
from .command_model import CanonicalCommand
from .command_rules import CommandSafetyRule, MatcherEvidence

COMMAND_EXTENSION_SCHEMA_VERSION = 2
_VERSION_PATTERN = re.compile(r"^[1-9][0-9]*\.[0-9]+\.[0-9]+$")


def risk_classes_for_command_action(action_class: str) -> tuple[str, ...]:
    """Return the existing runtime risk classes for a command action class."""

    return COMMAND_ACTION_RISK_CLASSES.get(action_class.strip().lower(), ())


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
    rules: tuple[CommandSafetyRule, ...] = ()
    required: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": COMMAND_EXTENSION_SCHEMA_VERSION,
            "extension_id": self.extension_id,
            "version": self.version,
            "name": self.name,
            "description": self.description,
            "enabled": True,
            "required": self.required,
            "source": "built-in",
            "action_classes": list(self.action_classes),
            "risk_classes": list(self.risk_classes),
            "safer_alternatives": list(self.safer_alternatives),
            "rule_count": len(self.rules),
            "rules": [rule.to_dict() for rule in self.rules],
        }


@final
class CommandSafetyExtensionRegistry:
    """Validated, deterministic registry of command safety extensions."""

    def __init__(self, extensions: tuple[CommandSafetyExtension, ...]) -> None:
        ordered = tuple(sorted(extensions, key=lambda extension: extension.extension_id))
        by_id: dict[str, CommandSafetyExtension] = {}
        by_action_class: dict[str, CommandSafetyExtension] = {}
        by_action_rule: dict[str, CommandSafetyRule] = {}
        by_rule_id: dict[str, CommandSafetyRule] = {}
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
            for rule in extension.rules:
                if not rule.rule_id.startswith(f"{extension.extension_id}."):
                    raise ValueError(
                        f"Command safety rule {rule.rule_id} must use extension prefix {extension.extension_id}"
                    )
                if rule.rule_id in by_rule_id:
                    raise ValueError(f"Duplicate command safety rule ID: {rule.rule_id}")
                undeclared_rule_risks = set(rule.risk_classes).difference(extension.risk_classes)
                if undeclared_rule_risks:
                    undeclared = ", ".join(sorted(undeclared_rule_risks))
                    raise ValueError(
                        f"Command safety rule {rule.rule_id} declares risks outside its extension: {undeclared}"
                    )
                by_rule_id[rule.rule_id] = rule
                for action_class in rule.action_classes:
                    normalized_action_class = action_class.strip().lower()
                    if normalized_action_class not in {item.strip().lower() for item in extension.action_classes}:
                        raise ValueError(
                            f"Command safety rule {rule.rule_id} owns undeclared action class {action_class!r}"
                        )
                    if rule.compatibility_fallback:
                        _ = by_action_rule.setdefault(normalized_action_class, rule)
            if extension.rules:
                rule_actions = {
                    action_class.strip().lower() for rule in extension.rules for action_class in rule.action_classes
                }
                extension_actions = {action_class.strip().lower() for action_class in extension.action_classes}
                if rule_actions != extension_actions:
                    raise ValueError(
                        f"Command safety extension {extension.extension_id} rules must own every action class"
                    )
        self._extensions = ordered
        self._by_id = by_id
        self._by_action_class = by_action_class
        self._by_action_rule = by_action_rule
        self._by_rule_id = by_rule_id

    @property
    def extensions(self) -> tuple[CommandSafetyExtension, ...]:
        return self._extensions

    def get(self, extension_id: str) -> CommandSafetyExtension | None:
        return self._by_id.get(extension_id.strip().lower())

    def for_action_class(self, action_class: str) -> CommandSafetyExtension | None:
        return self._by_action_class.get(action_class.strip().lower())

    def get_rule(self, rule_id: str) -> CommandSafetyRule | None:
        return self._by_rule_id.get(rule_id.strip().lower())

    def rule_for_action_class(self, action_class: str) -> CommandSafetyRule | None:
        return self._by_action_rule.get(action_class.strip().lower())

    def matching_rules(
        self,
        command: CanonicalCommand,
    ) -> tuple[tuple[CommandSafetyExtension, CommandSafetyRule, tuple[MatcherEvidence, ...]], ...]:
        """Return every structured rule match in deterministic registry order."""

        matches: list[tuple[CommandSafetyExtension, CommandSafetyRule, tuple[MatcherEvidence, ...]]] = []
        for extension in self._extensions:
            for rule in extension.rules:
                if rule.matcher is None:
                    continue
                evidence = rule.matcher.match(command)
                if not evidence:
                    continue
                safe_segment_indexes = {
                    safe_evidence.segment_index
                    for variant in rule.safe_variants
                    for safe_evidence in variant.matcher.match(command)
                }
                effective_evidence = tuple(item for item in evidence if item.segment_index not in safe_segment_indexes)
                if not effective_evidence:
                    continue
                matches.append((extension, rule, effective_evidence))
        return tuple(matches)


def _validate_extension(extension: CommandSafetyExtension) -> None:
    if not extension.extension_id.startswith("command."):
        raise ValueError("Command safety extension IDs must start with 'command.'")
    if extension.extension_id != extension.extension_id.lower():
        raise ValueError("Command safety extension IDs must be lowercase")
    if not _VERSION_PATTERN.fullmatch(extension.version):
        raise ValueError(f"Invalid command safety extension version: {extension.version}")
    if not extension.name.strip() or not extension.description.strip():
        raise ValueError(f"Command safety extension {extension.extension_id} requires a name and description")
    if not extension.action_classes and not extension.rules:
        raise ValueError(f"Command safety extension {extension.extension_id} must own an action class or rule")
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
        extension_id="command.filesystem",
        version="1.0.0",
        name="Filesystem protection",
        description="Reviews recursive deletion and access-control changes across filesystem trees.",
        action_classes=("filesystem destructive command",),
        risk_classes=("destructive_shell",),
        safer_alternatives=(
            "List and review exact target paths before recursive mutation.",
            "Limit permission and ownership changes to the narrowest path.",
        ),
        rules=rules_for_extension("command.filesystem"),
        required=True,
    ),
    CommandSafetyExtension(
        extension_id="command.git",
        version="1.0.0",
        name="Git protection",
        description="Reviews local and remote Git operations that can discard work or replace history.",
        action_classes=("git destructive command",),
        risk_classes=("destructive_shell",),
        safer_alternatives=(
            "Preview affected files and refs before destructive repository operations.",
            "Create a temporary branch or stash before discarding local work.",
        ),
        rules=rules_for_extension("command.git"),
        required=True,
    ),
    CommandSafetyExtension(
        extension_id="command.system",
        version="1.0.0",
        name="System protection",
        description="Reviews storage formatting and operating-system power-state mutations.",
        action_classes=("system destructive command",),
        risk_classes=("destructive_shell",),
        safer_alternatives=("Inspect the exact device or host state with a read-only command first.",),
        rules=rules_for_extension("command.system"),
        required=True,
    ),
    CommandSafetyExtension(
        extension_id="command.windows",
        version="1.0.0",
        name="Windows protection",
        description="Reviews destructive Windows storage and operating-system commands.",
        action_classes=("windows destructive command",),
        risk_classes=("destructive_shell",),
        safer_alternatives=("Use read-only PowerShell inventory commands to verify exact targets first.",),
        rules=rules_for_extension("command.windows"),
        required=True,
    ),
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
        rules=rules_for_extension("command.container-runtime"),
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
        rules=rules_for_extension("command.data-protection"),
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
        rules=rules_for_extension("command.encoded-execution"),
    ),
    CommandSafetyExtension(
        extension_id="command.guard-self-protection",
        version="1.0.0",
        name="Guard self-protection",
        description="Prevents commands from authorizing their own Guard approval or weakening protected Guard state.",
        action_classes=("Guard approval self-authorization command",),
        risk_classes=("policy_bypass",),
        safer_alternatives=("Approve the pending request through Guard's authenticated approval surface.",),
        rules=rules_for_extension("command.guard-self-protection"),
        required=True,
    ),
    CommandSafetyExtension(
        extension_id="command.kubernetes-secrets",
        version="1.0.0",
        name="Kubernetes secret protection",
        description="Reviews Kubernetes CLI operations that can reveal cluster or application secrets.",
        action_classes=("Kubernetes secret read command",),
        risk_classes=("local_secret_read",),
        safer_alternatives=("Request only the required non-secret field or metadata instead of the Secret payload.",),
        rules=rules_for_extension("command.kubernetes-secrets"),
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
        rules=rules_for_extension("command.shell-mutations"),
    ),
)

BUILT_IN_COMMAND_EXTENSION_REGISTRY = CommandSafetyExtensionRegistry(_BUILT_IN_EXTENSIONS)

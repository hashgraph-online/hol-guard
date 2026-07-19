"""Versioned metadata for Guard's built-in command safety extensions."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Literal, final

from .command_builtin_extension_catalog import DIRECT_COMMAND_EXTENSION_VALUES
from .command_builtin_rules import COMMAND_ACTION_RISK_CLASSES, rules_for_extension
from .command_matcher_contracts import MatcherEvidence
from .command_model import CanonicalCommand
from .command_package_extensions import PACKAGE_COMMAND_EXTENSION_SPECS, PackageCommandExtensionSpec
from .command_rules import CommandSafetyRule, matcher_index_hints

COMMAND_EXTENSION_SCHEMA_VERSION = 2
_VERSION_PATTERN = re.compile(r"^[1-9][0-9]*\.[0-9]+\.[0-9]+$")
_EXTENSION_ID_PATTERN = re.compile(r"^command\.[a-z0-9]+(?:[.-][a-z0-9]+)*$")

CommandExtensionSource = Literal["built-in", "local-admin", "signed-cloud"]
CommandExtensionDelegate = Literal["package-firewall"]
_VALID_EXTENSION_SOURCES = frozenset({"built-in", "local-admin", "signed-cloud"})
_VALID_EXTENSION_DELEGATES = frozenset({"package-firewall"})


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
    source: CommandExtensionSource = "built-in"
    aliases: tuple[str, ...] = ()
    dependencies: tuple[str, ...] = ()
    conflicts: tuple[str, ...] = ()
    delegated_protection: CommandExtensionDelegate | None = None
    ecosystem_ids: tuple[str, ...] = ()
    executables: tuple[str, ...] = ()
    project_markers: tuple[str, ...] = ()
    reference_urls: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": COMMAND_EXTENSION_SCHEMA_VERSION,
            "extension_id": self.extension_id,
            "version": self.version,
            "name": self.name,
            "description": self.description,
            "enabled": True,
            "required": self.required,
            "source": self.source,
            "aliases": list(self.aliases),
            "dependencies": list(self.dependencies),
            "conflicts": list(self.conflicts),
            "delegated_protection": self.delegated_protection,
            "ecosystem_ids": list(self.ecosystem_ids),
            "executables": list(self.executables),
            "project_markers": list(self.project_markers),
            "reference_urls": list(self.reference_urls),
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
        aliases: dict[str, str] = {}
        rule_records: list[tuple[CommandSafetyExtension, CommandSafetyRule]] = []
        executable_index: dict[str, set[str]] = {}
        keyword_index: dict[str, set[str]] = {}
        unindexed_rule_ids: set[str] = set()
        for extension in ordered:
            _validate_extension(extension)
            if extension.extension_id in by_id:
                raise ValueError(f"Duplicate command safety extension ID: {extension.extension_id}")
            by_id[extension.extension_id] = extension
            for alias in extension.aliases:
                if alias in by_id or alias in aliases:
                    raise ValueError(f"Duplicate command safety extension alias: {alias}")
                aliases[alias] = extension.extension_id
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
                rule_records.append((extension, rule))
                if rule.matcher is not None:
                    hints = matcher_index_hints(rule.matcher)
                    if not hints.complete or (not hints.executables and not hints.keywords):
                        unindexed_rule_ids.add(rule.rule_id)
                    for executable in hints.executables:
                        executable_index.setdefault(executable, set()).add(rule.rule_id)
                    for keyword in hints.keywords:
                        keyword_index.setdefault(keyword, set()).add(rule.rule_id)
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
        _validate_registry_relationships(ordered, by_id=by_id, aliases=aliases)
        self._extensions = ordered
        self._by_id = by_id
        self._aliases = aliases
        self._by_action_class = by_action_class
        self._by_action_rule = by_action_rule
        self._by_rule_id = by_rule_id
        self._rule_records = tuple(rule_records)
        self._executable_index = {key: frozenset(value) for key, value in executable_index.items()}
        self._keyword_index = {key: frozenset(value) for key, value in keyword_index.items()}
        self._unindexed_rule_ids = frozenset(unindexed_rule_ids)

    @property
    def extensions(self) -> tuple[CommandSafetyExtension, ...]:
        return self._extensions

    def get(self, extension_id: str) -> CommandSafetyExtension | None:
        normalized = extension_id.strip().lower()
        return self._by_id.get(self._aliases.get(normalized, normalized))

    def for_action_class(self, action_class: str) -> CommandSafetyExtension | None:
        return self._by_action_class.get(action_class.strip().lower())

    def get_rule(self, rule_id: str) -> CommandSafetyRule | None:
        return self._by_rule_id.get(rule_id.strip().lower())

    def rule_for_action_class(self, action_class: str) -> CommandSafetyRule | None:
        return self._by_action_rule.get(action_class.strip().lower())

    def candidate_rule_ids(self, command: CanonicalCommand) -> tuple[str, ...]:
        """Return deterministic rule candidates from conservative registry indexes."""

        candidate_rule_ids = set(self._unindexed_rule_ids)
        command_executables = {
            segment.executable.replace("\\", "/").rsplit("/", 1)[-1].lower()
            for segment in command.segments
            if segment.executable is not None
        }
        command_keywords = {token.lower() for segment in command.segments for token in segment.tokens}
        for executable in command_executables:
            candidate_rule_ids.update(self._executable_index.get(executable, ()))
        for keyword in command_keywords:
            candidate_rule_ids.update(self._keyword_index.get(keyword, ()))
        return tuple(rule.rule_id for _extension, rule in self._rule_records if rule.rule_id in candidate_rule_ids)

    def matching_rules(
        self,
        command: CanonicalCommand,
    ) -> tuple[tuple[CommandSafetyExtension, CommandSafetyRule, tuple[MatcherEvidence, ...]], ...]:
        """Return every structured rule match in deterministic registry order."""

        matches: list[tuple[CommandSafetyExtension, CommandSafetyRule, tuple[MatcherEvidence, ...]]] = []
        candidate_rule_ids = frozenset(self.candidate_rule_ids(command))
        for extension, rule in self._rule_records:
            if rule.matcher is None or rule.rule_id not in candidate_rule_ids:
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
    if not _EXTENSION_ID_PATTERN.fullmatch(extension.extension_id):
        raise ValueError("Command safety extension IDs must be lowercase and start with 'command.'")
    if not _VERSION_PATTERN.fullmatch(extension.version):
        raise ValueError(f"Invalid command safety extension version: {extension.version}")
    if not extension.name.strip() or not extension.description.strip():
        raise ValueError(f"Command safety extension {extension.extension_id} requires a name and description")
    if not extension.action_classes and not extension.rules and extension.delegated_protection is None:
        raise ValueError(
            f"Command safety extension {extension.extension_id} must own an action class, rule, or delegated protection"
        )
    if len(set(extension.action_classes)) != len(extension.action_classes):
        raise ValueError(f"Command safety extension {extension.extension_id} has duplicate action classes")
    if not extension.risk_classes:
        raise ValueError(f"Command safety extension {extension.extension_id} must declare a risk class")
    if len(set(extension.risk_classes)) != len(extension.risk_classes):
        raise ValueError(f"Command safety extension {extension.extension_id} has duplicate risk classes")
    if not extension.safer_alternatives:
        raise ValueError(f"Command safety extension {extension.extension_id} requires safer alternatives")
    if extension.source not in _VALID_EXTENSION_SOURCES:
        raise ValueError(f"Command safety extension {extension.extension_id} has invalid source")
    if extension.delegated_protection is not None:
        if extension.delegated_protection not in _VALID_EXTENSION_DELEGATES:
            raise ValueError(f"Command safety extension {extension.extension_id} has invalid delegated protection")
        if extension.action_classes or extension.rules:
            raise ValueError(f"Delegated command safety extension {extension.extension_id} cannot own command rules")
    if extension.required and extension.source != "built-in":
        raise ValueError(f"Required command safety extension {extension.extension_id} must be built-in")
    for field_name, values in (
        ("aliases", extension.aliases),
        ("dependencies", extension.dependencies),
        ("conflicts", extension.conflicts),
    ):
        if len(set(values)) != len(values) or any(not _EXTENSION_ID_PATTERN.fullmatch(value) for value in values):
            raise ValueError(f"Command safety extension {extension.extension_id} has invalid {field_name}")
    for field_name, values in (
        ("ecosystem IDs", extension.ecosystem_ids),
        ("executables", extension.executables),
        ("project markers", extension.project_markers),
        ("reference URLs", extension.reference_urls),
    ):
        if len(set(values)) != len(values) or any(not value or value != value.strip() for value in values):
            raise ValueError(f"Command safety extension {extension.extension_id} has invalid {field_name}")
    if extension.delegated_protection is not None and (not extension.ecosystem_ids or not extension.executables):
        raise ValueError(
            f"Delegated command safety extension {extension.extension_id} requires ecosystem and executable metadata"
        )
    if extension.delegated_protection is not None and (
        not extension.reference_urls or any(not value.startswith("https://") for value in extension.reference_urls)
    ):
        raise ValueError(f"Delegated command safety extension {extension.extension_id} requires HTTPS references")
    if any("/" in value or "\\" in value for value in extension.executables):
        raise ValueError(f"Command safety extension {extension.extension_id} executable metadata must use basenames")
    if any(not _safe_project_marker(value) for value in extension.project_markers):
        raise ValueError(f"Command safety extension {extension.extension_id} has unsafe project marker metadata")


def _safe_project_marker(value: str) -> bool:
    marker = PurePosixPath(value)
    return not marker.is_absolute() and ".." not in marker.parts and "\\" not in value


def _validate_registry_relationships(
    extensions: tuple[CommandSafetyExtension, ...],
    *,
    by_id: dict[str, CommandSafetyExtension],
    aliases: dict[str, str],
) -> None:
    for alias in aliases:
        if alias in by_id:
            raise ValueError(f"Command safety extension alias shadows an extension ID: {alias}")
    for extension in extensions:
        for dependency in extension.dependencies:
            if dependency not in by_id:
                raise ValueError(
                    f"Command safety extension {extension.extension_id} has unknown dependency {dependency}"
                )
        for conflict in extension.conflicts:
            if conflict == extension.extension_id or conflict in by_id:
                raise ValueError(f"Command safety extension {extension.extension_id} conflicts with {conflict}")

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(extension_id: str) -> None:
        if extension_id in visiting:
            raise ValueError(f"Command safety extension dependency cycle includes {extension_id}")
        if extension_id in visited:
            return
        visiting.add(extension_id)
        for dependency in by_id[extension_id].dependencies:
            visit(dependency)
        visiting.remove(extension_id)
        visited.add(extension_id)

    for extension in extensions:
        visit(extension.extension_id)


def _package_command_extension(spec: PackageCommandExtensionSpec) -> CommandSafetyExtension:
    return CommandSafetyExtension(
        extension_id=spec.extension_id,
        version="1.0.0",
        name=spec.name,
        description=spec.description,
        action_classes=(),
        risk_classes=("supply_chain",),
        safer_alternatives=(
            "Use the existing project manifest and lockfile instead of an unpinned package source.",
            "Review package provenance and advisory evidence before installation or one-shot execution.",
        ),
        delegated_protection="package-firewall",
        ecosystem_ids=spec.ecosystem_ids,
        executables=spec.executables,
        project_markers=spec.project_markers,
        reference_urls=spec.reference_urls,
    )


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
        reference_urls=(
            "https://docs.docker.com/reference/cli/docker/system/prune/",
            "https://docs.docker.com/reference/cli/docker/container/rm/",
            "https://docs.docker.com/reference/cli/docker/container/run/",
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
        reference_urls=("https://kubernetes.io/docs/reference/kubectl/generated/kubectl_get/",),
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
    *(CommandSafetyExtension(**values) for values in DIRECT_COMMAND_EXTENSION_VALUES),
    *(_package_command_extension(spec) for spec in PACKAGE_COMMAND_EXTENSION_SPECS),
)

BUILT_IN_COMMAND_EXTENSION_REGISTRY = CommandSafetyExtensionRegistry(_BUILT_IN_EXTENSIONS)

"""Deterministic plain-language semantics for Guard action explanations.

This module is deliberately local and side-effect free. It consumes typed facts
from Core's canonical action pipeline and never executes commands, performs
network requests, or calls a model. UI surfaces consume the resulting versioned
contract instead of reinterpreting shell text independently.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
import hashlib
import json
import re
from typing import Iterable, Sequence

from codex_plugin_scanner.guard.redaction import redact_text

from .action_explanation_contract import (
    ACTION_EXPLANATION_REDACTION_VERSION,
    ACTION_EXPLANATION_RENDERER_VERSION,
    ACTION_EXPLANATION_SCHEMA_VERSION,
    ACTION_EXPLANATION_VERSION,
    ACTION_KINDS,
    GuardActionExplanationV1,
    parse_action_explanation,
)

_URL_RE = re.compile(r"(?i)https?://([^/\s?#]+)")
_DRIVE_RE = re.compile(r"^[A-Za-z]:[\\/]")
_ENV_FILE_RE = re.compile(r"^\.env(?:\.[A-Za-z0-9_.-]+)?$", re.IGNORECASE)
_PRIVATE_KEY_RE = re.compile(r"^id_(?:rsa|dsa|ecdsa|ed25519)(?!\.pub$)", re.IGNORECASE)
_SENSITIVE_FILENAMES = frozenset(
    {
        ".npmrc",
        ".pypirc",
        ".netrc",
        "credentials",
        "application_default_credentials.json",
        "login.keychain-db",
    }
)
_WINDOWS_SLASH_OPTIONS = frozenset(
    {
        "/s",
        "/q",
        "/f",
        "/a",
        "/p",
        "/c",
        "/t",
        "/l",
        "/grant",
        "/deny",
        "/remove",
        "/setowner",
        "/inheritance",
        "/reset",
        "/save",
        "/restore",
        "/verify",
        "/findsid",
    }
)


@dataclass(frozen=True, slots=True)
class CommandSemanticInput:
    """Typed facts supplied by Core's canonical command/action model."""

    action_identity: str
    canonical_identity: str | None
    actor_label: str
    executable: str | None
    arguments: tuple[str, ...] = ()
    operands: tuple[str, ...] = ()
    target_paths: tuple[str, ...] = ()
    network_hosts: tuple[str, ...] = ()
    package_names: tuple[str, ...] = ()
    remote_targets: tuple[str, ...] = ()
    command_display: str | None = None
    normalized_command_display: str | None = None
    dialect: str | None = None
    transport: str | None = None
    working_scope_display: str | None = None
    extension_ids: tuple[str, ...] = ()
    rule_ids: tuple[str, ...] = ()
    reason_codes: tuple[str, ...] = ()
    policy_source: str | None = None
    parse_confidence: str | None = None
    proof_level: str | None = None
    receipt_id: str | None = None
    catalog_digest: str | None = None
    exact_details_authorized: bool = False
    retained: bool = True


@dataclass(frozen=True, slots=True)
class SemanticRule:
    rule_id: str
    action_kind: str
    executables: frozenset[str]
    required_tokens: tuple[frozenset[str], ...] = ()
    forbidden_tokens: frozenset[str] = frozenset()
    headline: str = "Review an action"
    summary: str = "An AI app wants to perform an action."
    impact: str | None = None
    recommendation: str | None = None
    target_strategy: str = "generic"
    confidence: str = "derived"
    consequence_level: str = "medium"
    safer_alternatives: tuple[tuple[str, str], ...] = ()

    def matches(self, executable: str, tokens: frozenset[str]) -> bool:
        if executable not in self.executables:
            return False
        if self.forbidden_tokens & tokens:
            return False
        return all(group & tokens for group in self.required_tokens)


@dataclass(frozen=True, slots=True)
class SemanticMatch:
    rule: SemanticRule | None
    target_label: str
    target_kind: str
    target_sensitivity: str
    headline: str
    summary: str
    impact: str | None
    recommendation: str | None
    confidence: str
    consequence_level: str
    uncertainty_reasons: tuple[str, ...] = ()
    safer_alternatives: tuple[tuple[str, str], ...] = ()


_DELETE_EXECUTABLES = frozenset({"rm", "rmdir", "unlink", "del", "erase", "remove-item", "ri"})
_COPY_EXECUTABLES = frozenset({"cp", "copy", "copy-item", "cpi", "robocopy", "xcopy"})
_MOVE_EXECUTABLES = frozenset({"mv", "move", "move-item", "mi", "rename", "rename-item", "ren"})
_PERMISSION_EXECUTABLES = frozenset({"chmod", "chown", "chgrp", "icacls", "set-acl", "takeown"})
_READ_EXECUTABLES = frozenset({"cat", "type", "get-content", "gc", "more", "less", "head", "tail"})
_NETWORK_EXECUTABLES = frozenset(
    {"curl", "wget", "invoke-webrequest", "iwr", "invoke-restmethod", "irm", "http", "https"}
)
_REMOTE_COPY_EXECUTABLES = frozenset({"scp", "sftp", "rsync"})
_PACKAGE_EXECUTABLES = frozenset(
    {
        "npm",
        "pnpm",
        "yarn",
        "bun",
        "pip",
        "pip3",
        "uv",
        "poetry",
        "gem",
        "cargo",
        "go",
        "composer",
        "dotnet",
        "nuget",
        "winget",
        "choco",
        "brew",
        "apt",
        "apt-get",
        "dnf",
        "yum",
        "apk",
        "pacman",
    }
)


SEMANTIC_RULES: tuple[SemanticRule, ...] = (
    SemanticRule(
        rule_id="filesystem.delete.recursive",
        action_kind="file_delete",
        executables=_DELETE_EXECUTABLES,
        required_tokens=(frozenset({"-r", "-rf", "-fr", "--recursive", "/s", "-recurse"}),),
        headline="Delete a folder and everything inside it",
        summary="{actor} wants to permanently remove {target}, including files and subfolders.",
        impact="Files that are not backed up may be difficult or impossible to recover.",
        recommendation="Confirm that the folder is the intended one and that important work is backed up.",
        target_strategy="filesystem",
        confidence="exact",
        consequence_level="high",
        safer_alternatives=(("preview", "Preview the folder contents first."), ("backup", "Create a backup before deleting it.")),
    ),
    SemanticRule(
        rule_id="filesystem.delete",
        action_kind="file_delete",
        executables=_DELETE_EXECUTABLES,
        headline="Delete a file or folder",
        summary="{actor} wants to permanently remove {target}.",
        impact="The removed item may not be recoverable.",
        recommendation="Confirm the target and keep a backup of anything important.",
        target_strategy="filesystem",
        confidence="exact",
        consequence_level="high",
        safer_alternatives=(("preview", "Inspect the target first."), ("backup", "Create a backup before deleting it.")),
    ),
    SemanticRule(
        rule_id="filesystem.copy",
        action_kind="file_write",
        executables=_COPY_EXECUTABLES,
        headline="Copy files or folders",
        summary="{actor} wants to copy data involving {target}.",
        impact="Existing files at the destination may be replaced, and additional copies may contain sensitive information.",
        recommendation="Confirm the destination and whether replacing existing files is intended.",
        target_strategy="filesystem",
        confidence="derived",
        consequence_level="medium",
        safer_alternatives=(("preview", "Preview destination conflicts first."), ("backup", "Back up files that may be replaced.")),
    ),
    SemanticRule(
        rule_id="filesystem.move",
        action_kind="file_move",
        executables=_MOVE_EXECUTABLES,
        headline="Move or rename files",
        summary="{actor} wants to move or rename data involving {target}.",
        impact="Programs or links that expect the old location may stop working, and existing destination files may be replaced.",
        recommendation="Confirm both the source and destination before continuing.",
        target_strategy="filesystem",
        confidence="derived",
        consequence_level="medium",
        safer_alternatives=(("preview", "Preview destination conflicts first."), ("backup", "Back up files that may be replaced.")),
    ),
    SemanticRule(
        rule_id="filesystem.permissions",
        action_kind="permission_change",
        executables=_PERMISSION_EXECUTABLES,
        headline="Change who can access files",
        summary="{actor} wants to change ownership or access permissions for {target}.",
        impact="The change may expose private data or prevent you and your apps from opening the affected files.",
        recommendation="Use the narrowest permissions needed and verify the exact target.",
        target_strategy="filesystem",
        confidence="derived",
        consequence_level="high",
        safer_alternatives=(("preview", "Inspect current permissions first."), ("narrow", "Limit the change to the smallest required path and permission.")),
    ),
    SemanticRule(
        rule_id="credentials.read",
        action_kind="secret_read",
        executables=_READ_EXECUTABLES,
        headline="Read saved credentials",
        summary="{actor} wants to read {target}.",
        impact="The contents may include passwords, private keys, access tokens, or other secrets.",
        recommendation="Only continue when this app needs the credential and you trust where the data will be used.",
        target_strategy="sensitive",
        confidence="exact",
        consequence_level="high",
        safer_alternatives=(("narrow", "Use a credential helper or narrowly scoped environment variable instead."),),
    ),
    SemanticRule(
        rule_id="network.upload",
        action_kind="network_send",
        executables=_NETWORK_EXECUTABLES,
        required_tokens=(frozenset({"-d", "--data", "--data-binary", "--form", "--upload-file", "--body", "-infile"}),),
        headline="Send data to a website",
        summary="{actor} wants to send data to {target}.",
        impact="The destination may retain, process, or redistribute the sent information.",
        recommendation="Confirm the destination and make sure no private files or credentials are included.",
        target_strategy="network",
        confidence="derived",
        consequence_level="high",
        safer_alternatives=(("narrow", "Send only the minimum required data."), ("review", "Verify the destination before sending anything private.")),
    ),
    SemanticRule(
        rule_id="network.download",
        action_kind="download",
        executables=_NETWORK_EXECUTABLES,
        required_tokens=(frozenset({"-o", "--output", "-outfile", "--remote-name", "-o-"}),),
        headline="Download a file from the internet",
        summary="{actor} wants to download content from {target} and save it on this computer.",
        impact="Downloaded files can replace local data or contain unsafe software.",
        recommendation="Verify the source and inspect the downloaded file before opening or running it.",
        target_strategy="network",
        confidence="derived",
        consequence_level="medium",
        safer_alternatives=(("preview", "Download the file without running it automatically."), ("review", "Verify a checksum or signature when available.")),
    ),
    SemanticRule(
        rule_id="network.request",
        action_kind="network_read",
        executables=_NETWORK_EXECUTABLES,
        headline="Connect to a website or service",
        summary="{actor} wants to contact {target}.",
        impact="The destination can observe request details and may return untrusted content.",
        recommendation="Confirm that the destination is expected and trusted.",
        target_strategy="network",
        confidence="derived",
        consequence_level="medium",
        safer_alternatives=(("preview", "Use a read-only or preview request when available."),),
    ),
    SemanticRule(
        rule_id="network.remote-copy",
        action_kind="network_send",
        executables=_REMOTE_COPY_EXECUTABLES,
        headline="Transfer files to or from another computer",
        summary="{actor} wants to transfer data involving {target}.",
        impact="Files may leave this computer, arrive from an untrusted host, or replace existing data.",
        recommendation="Confirm the remote computer, direction, and exact files.",
        target_strategy="remote",
        confidence="derived",
        consequence_level="high",
        safer_alternatives=(("isolate", "Use a dedicated empty destination folder."), ("review", "Verify the remote host identity first.")),
    ),
    SemanticRule(
        rule_id="package.publish",
        action_kind="network_send",
        executables=_PACKAGE_EXECUTABLES,
        required_tokens=(frozenset({"publish", "upload", "push"}),),
        headline="Publish a software package",
        summary="{actor} wants to publish {target} to a package service.",
        impact="Published code or files may become available to other people and can be difficult to retract completely.",
        recommendation="Review the package contents, destination account, version, and included secrets before publishing.",
        target_strategy="package",
        confidence="exact",
        consequence_level="high",
        safer_alternatives=(("preview", "Run a package dry run or inspect the archive first."),),
    ),
    SemanticRule(
        rule_id="package.remove",
        action_kind="package_remove",
        executables=_PACKAGE_EXECUTABLES,
        required_tokens=(frozenset({"remove", "rm", "uninstall", "erase"}),),
        headline="Remove software packages",
        summary="{actor} wants to remove {target}.",
        impact="Apps, scripts, or project builds that depend on the package may stop working.",
        recommendation="Confirm the package and scope before removing it.",
        target_strategy="package",
        confidence="exact",
        consequence_level="medium",
        safer_alternatives=(("review", "Check which projects depend on the package first."),),
    ),
    SemanticRule(
        rule_id="package.install",
        action_kind="package_install",
        executables=_PACKAGE_EXECUTABLES,
        required_tokens=(frozenset({"install", "add", "i", "get"}),),
        headline="Install software packages",
        summary="{actor} wants to install {target}.",
        impact="Package installation can run third-party code and change project or system files.",
        recommendation="Confirm the package name, source, version, and whether installation is limited to this project.",
        target_strategy="package",
        confidence="exact",
        consequence_level="medium",
        safer_alternatives=(("narrow", "Pin an exact version."), ("isolate", "Install inside an isolated project environment.")),
    ),
)


def explain_command(input: CommandSemanticInput) -> GuardActionExplanationV1:
    """Build a validated ``guard.action-explanation.v1`` contract."""

    executable = _normalize_executable(input.executable)
    args = tuple(str(arg) for arg in input.arguments)
    tokens = frozenset(_normalized_tokens(args))
    rule = next((candidate for candidate in SEMANTIC_RULES if candidate.matches(executable, tokens)), None)
    if rule and rule.rule_id == "credentials.read" and not _has_sensitive_target(input, args):
        rule = None
    match = _render_match(rule, input, executable, args)
    technical_available = bool(input.retained and input.exact_details_authorized and input.command_display)
    command_display = _redact_technical_value(input.command_display) if technical_available else None
    normalized_display = _redact_technical_value(input.normalized_command_display) if technical_available else None
    arguments_display = (
        [_redact_technical_value(arg) or "[redacted]" for arg in args] if technical_available else None
    )
    action_kind = match.rule.action_kind if match.rule else "unknown_action"
    if action_kind not in ACTION_KINDS:
        action_kind = "unknown_action"

    omitted: list[str] = []
    if not technical_available:
        omitted.extend(["technical.command_display", "technical.arguments_display"])
    if input.working_scope_display and not input.exact_details_authorized:
        omitted.append("technical.working_scope_display")

    unavailable_reason: str | None
    if technical_available:
        unavailable_reason = None
    elif not input.retained:
        unavailable_reason = "not_retained"
    else:
        unavailable_reason = "not_authorized"

    rule_id = match.rule.rule_id if match.rule else "unknown"
    targets = [
        {
            "kind": match.target_kind,
            "label": _bounded(match.target_label, 240) or "the requested target",
            "scope": None,
            "sensitivity": match.target_sensitivity,
        }
    ]
    consequences: list[dict[str, object]] = []
    if match.impact:
        consequences.append(
            {
                "message_id": f"guard.everyday.{rule_id}.consequence",
                "message": _bounded(match.impact, 500) or "This action can have lasting effects.",
                "severity": match.consequence_level,
                "confirmed": False,
            }
        )
    alternatives = [
        {
            "message_id": f"guard.everyday.{rule_id}.alternative.{index}",
            "message": _bounded(message, 500) or "Review the action before continuing.",
            "kind": kind,
        }
        for index, (kind, message) in enumerate(match.safer_alternatives, start=1)
    ]

    payload: dict[str, object] = {
        "schema_version": ACTION_EXPLANATION_SCHEMA_VERSION,
        "explanation_version": ACTION_EXPLANATION_VERSION,
        "renderer_version": ACTION_EXPLANATION_RENDERER_VERSION,
        "action_identity": _bounded(input.action_identity, 256),
        "canonical_identity": _bounded(input.canonical_identity, 256),
        "catalog_digest": _bounded(input.catalog_digest or stable_semantic_catalog_digest(), 256),
        "locale": "en-US",
        "kind": action_kind,
        "confidence": match.confidence,
        "uncertainty_reasons": list(match.uncertainty_reasons),
        "everyday": {
            "headline_message_id": f"guard.everyday.{rule_id}.headline",
            "headline": _bounded(match.headline, 240),
            "summary_message_id": f"guard.everyday.{rule_id}.summary",
            "summary": _bounded(match.summary, 800),
            "impact_message_id": f"guard.everyday.{rule_id}.impact" if match.impact else None,
            "impact": _bounded(match.impact, 800),
            "why_guard_intervened_message_id": None,
            "why_guard_intervened": None,
            "recommendation_message_id": (
                f"guard.everyday.{rule_id}.recommendation" if match.recommendation else None
            ),
            "recommendation": _bounded(match.recommendation, 800),
            "actor_label": _bounded(_safe_actor(input.actor_label), 120),
            "targets": targets,
            "consequences": consequences,
            "safer_alternatives": alternatives,
        },
        "technical": {
            "available": technical_available,
            "unavailable_reason": unavailable_reason,
            "action_type": action_kind,
            "command_display": _bounded(command_display, 4096),
            "normalized_command_display": _bounded(normalized_display, 4096),
            "executable": _bounded(executable or None, 240),
            "arguments_display": (
                [_bounded(value, 240) or "" for value in arguments_display]
                if arguments_display is not None
                else None
            ),
            "dialect": _bounded(input.dialect, 64),
            "transport": _bounded(input.transport, 64),
            "working_scope_display": (
                _bounded(_safe_scope(input.working_scope_display), 500)
                if input.exact_details_authorized
                else None
            ),
            "wrappers": [],
            "segments": [],
            "extension_ids": [_bounded(value, 128) or "" for value in input.extension_ids[:64]],
            "rule_ids": [_bounded(value, 128) or "" for value in input.rule_ids[:64]],
            "reason_codes": [_bounded(value, 128) or "" for value in input.reason_codes[:64]],
            "policy_source": _bounded(input.policy_source, 128),
            "parse_confidence": _bounded(input.parse_confidence, 64),
            "proof_level": _bounded(input.proof_level, 64),
            "receipt_id": _bounded(input.receipt_id, 256),
            "action_id": _bounded(input.action_identity, 512),
        },
        "redaction": {
            "level": "none" if technical_available and not _secret_like_value_present((input.command_display or "", *args)) else "redacted",
            "policy_version": ACTION_EXPLANATION_REDACTION_VERSION,
            "omitted_fields": omitted,
            "truncated_fields": [],
            "secret_like_values_removed": _secret_like_value_present((input.command_display or "", *args)),
        },
    }
    return parse_action_explanation(payload)


def stable_semantic_catalog_digest(rules: Sequence[SemanticRule] = SEMANTIC_RULES) -> str:
    """Return a content address over every rule field that can affect rendering."""

    material: list[dict[str, object]] = []
    for rule in rules:
        item: dict[str, object] = {}
        for field in fields(SemanticRule):
            value = getattr(rule, field.name)
            item[field.name] = _canonical_digest_value(value)
        material.append(item)
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _canonical_digest_value(value: object) -> object:
    if isinstance(value, frozenset):
        return sorted(value)
    if isinstance(value, tuple):
        return [_canonical_digest_value(item) for item in value]
    return value


def _render_match(
    rule: SemanticRule | None,
    input: CommandSemanticInput,
    executable: str,
    args: Sequence[str],
) -> SemanticMatch:
    actor = _safe_actor(input.actor_label)
    if rule is None:
        return SemanticMatch(
            rule=None,
            target_label="the requested target",
            target_kind="unknown",
            target_sensitivity="unknown",
            headline="Review an action Guard could not fully explain",
            summary=(
                f"{actor} wants to perform an action, but Guard could not confirm the exact intent or target."
            ),
            impact=(
                "The action may change files, software, settings, or data outside the information Guard could verify."
            ),
            recommendation="Open the technical details when available and confirm the exact action before continuing.",
            confidence="limited",
            consequence_level="high",
            uncertainty_reasons=("semantic_rule_unavailable",),
            safer_alternatives=(("preview", "Ask the app to explain or preview the action without running it."),),
        )
    target, target_kind, sensitivity = _target_label(rule.target_strategy, input, executable, args)
    confidence = rule.confidence if rule.confidence in {"exact", "derived", "limited"} else "limited"
    return SemanticMatch(
        rule=rule,
        target_label=target,
        target_kind=target_kind,
        target_sensitivity=sensitivity,
        headline=rule.headline,
        summary=rule.summary.format(actor=actor, target=target),
        impact=rule.impact,
        recommendation=rule.recommendation,
        confidence=confidence,
        consequence_level=(
            rule.consequence_level
            if rule.consequence_level in {"info", "low", "medium", "high", "critical"}
            else "medium"
        ),
        safer_alternatives=rule.safer_alternatives,
    )


def _normalize_executable(value: str | None) -> str:
    if not value:
        return ""
    normalized = value.replace("\\", "/").rsplit("/", 1)[-1].casefold()
    for suffix in (".exe", ".cmd", ".bat", ".ps1"):
        if normalized.endswith(suffix):
            normalized = normalized[: -len(suffix)]
            break
    return normalized


def _normalized_tokens(arguments: Iterable[str]) -> Iterable[str]:
    for argument in arguments:
        value = argument.strip().casefold()
        if value:
            yield value
            if "=" in value:
                yield value.split("=", 1)[0]


def _target_label(
    strategy: str,
    input: CommandSemanticInput,
    executable: str,
    arguments: Sequence[str],
) -> tuple[str, str, str]:
    if strategy == "sensitive":
        safe_label = _safe_sensitive_target(input, arguments)
        return safe_label, "credential", "secret"
    if strategy == "network":
        host = _network_host(input, arguments)
        if host:
            return f"the service at {_bounded(host.casefold(), 253)}", "network_host", "normal"
        return "an external website or service", "network_host", "unknown"
    if strategy == "remote":
        remote = next((value for value in input.remote_targets if value.strip()), None)
        candidates = (remote,) if remote else arguments
        for argument in candidates:
            if argument and ":" in argument and not _DRIVE_RE.match(argument):
                host = argument.split(":", 1)[0].split("@")[-1]
                if host:
                    return f"another computer ({_bounded(host, 160)})", "remote_host", "normal"
        return "another computer", "remote_host", "unknown"
    if strategy == "package":
        packages = [value for value in input.package_names if value.strip()]
        if not packages:
            positional = _positionals(arguments)
            verbs = {
                "install",
                "add",
                "i",
                "get",
                "remove",
                "rm",
                "uninstall",
                "erase",
                "publish",
                "upload",
                "push",
            }
            packages = [value for value in positional if value.casefold() not in verbs]
        if packages:
            shown = ", ".join(_safe_basename(value) for value in packages[:3])
            suffix = "s" if len(packages) != 1 else ""
            return f"the software package{suffix} {shown}", "package", "normal"
        return "one or more software packages", "package", "unknown"
    if strategy == "filesystem":
        candidates = [value for value in input.target_paths if value.strip()]
        if not candidates:
            candidates = list(input.operands) or _filesystem_operands(executable, arguments)
        if candidates:
            selected = candidates[-1]
            if executable in {"del", "erase", "icacls", "takeown"}:
                selected = candidates[0]
            label = _safe_basename(selected)
            sensitivity = "secret" if _is_sensitive_path(selected) else "normal"
            return (
                f"the item named {label}" if label else "files or folders in the selected location",
                "filesystem_item",
                sensitivity,
            )
        return "files or folders in the selected location", "filesystem_item", "unknown"
    return "the requested target", "unknown", "unknown"


def _network_host(input: CommandSemanticInput, arguments: Sequence[str]) -> str | None:
    for value in input.network_hosts:
        host = value.strip().strip("[]")
        if host:
            return host
    for argument in arguments:
        match = _URL_RE.search(argument)
        if match:
            return match.group(1).strip("[]")
    return None


def _positionals(arguments: Sequence[str]) -> list[str]:
    return [value for value in arguments if value and not _is_option_token(value)]


def _filesystem_operands(executable: str, arguments: Sequence[str]) -> list[str]:
    if executable in {"icacls", "takeown"}:
        for value in arguments:
            if value and not _is_option_token(value):
                return [value]
        return []
    if executable in {"del", "erase"}:
        return [value for value in arguments if value and not _is_option_token(value)][:1]
    if executable in {"chmod", "chown", "chgrp"}:
        positional = _positionals(arguments)
        return positional[-1:] if positional else []
    return _positionals(arguments)


def _is_option_token(value: str) -> bool:
    if value.startswith("-"):
        return True
    folded = value.casefold()
    if folded in _WINDOWS_SLASH_OPTIONS:
        return True
    return any(folded.startswith(f"{prefix}:") for prefix in _WINDOWS_SLASH_OPTIONS)


def _safe_sensitive_target(input: CommandSemanticInput, arguments: Sequence[str]) -> str:
    candidates = [value for value in input.target_paths if value.strip()]
    if not candidates:
        candidates = _positionals(arguments)
    for candidate in candidates:
        if _is_sensitive_path(candidate):
            name = _safe_basename(candidate)
            return f"the saved credential file {name}" if name else "saved credentials"
    return "saved credentials or another sensitive item"


def _safe_basename(value: str) -> str:
    normalized = value.strip().rstrip("/\\").replace("\\", "/")
    if not normalized:
        return "the selected item"
    name = normalized.rsplit("/", 1)[-1]
    if _is_sensitive_path(normalized):
        if _ENV_FILE_RE.match(name):
            return ".env file"
        if _PRIVATE_KEY_RE.match(name):
            return "private key"
        if name.casefold() in _SENSITIVE_FILENAMES:
            return "credential file"
        return "sensitive item"
    redacted = _redact_technical_value(name) or "[redacted]"
    return _bounded(redacted, 120) or "the selected item"


def _is_sensitive_path(value: str) -> bool:
    normalized = value.strip().replace("\\", "/").casefold()
    if not normalized:
        return False
    name = normalized.rstrip("/").rsplit("/", 1)[-1]
    if name.endswith(".pub"):
        return False
    if _ENV_FILE_RE.match(name) or _PRIVATE_KEY_RE.match(name):
        return True
    if name in _SENSITIVE_FILENAMES:
        return True
    components = [part for part in normalized.split("/") if part]
    if ".gnupg" in components:
        return True
    if ".aws" in components and name == "credentials":
        return True
    if ".ssh" in components and _PRIVATE_KEY_RE.match(name):
        return True
    return False


def _has_sensitive_target(input: CommandSemanticInput, arguments: Sequence[str]) -> bool:
    return any(_is_sensitive_path(value) for value in (*input.target_paths, *input.operands, *arguments))


def _safe_actor(value: str) -> str:
    cleaned = _redact_technical_value(value.strip()) or ""
    return cleaned or "An AI app"


def _safe_scope(value: str | None) -> str | None:
    if not value:
        return None
    if _is_sensitive_path(value):
        return "[sensitive location]"
    return _redact_technical_value(value)


def _secret_like_value_present(values: Iterable[str]) -> bool:
    return any(redact_text(value or "").count > 0 for value in values)


def _redact_technical_value(value: str | None) -> str | None:
    if value is None:
        return None
    return redact_text(value).text


def _bounded(value: str | None, limit: int) -> str | None:
    if value is None or len(value) <= limit:
        return value
    return value[: max(0, limit - 1)] + "…"

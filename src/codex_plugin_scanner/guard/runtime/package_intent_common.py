"""Shared package intent models and artifact builders."""

from __future__ import annotations

import hashlib
import json
import re
import shlex
from dataclasses import asdict, dataclass, field
from pathlib import Path, PurePath
from typing import Literal

from ..models import GuardArtifact
from .mcp_protection import _split_package_token
from .npm_source_spec import NpmSourceSpec, parse_npm_source_spec
from .typescript_launch_evidence import TypeScriptLaunchEvidence
from .workspace_path_guard import existing_paths_within_workspace

IntentKind = Literal["install", "execute", "sync"]
EvidenceStatus = Literal["available", "missing", "not_regular", "unreadable", "unstable"]
_EXTRAS_RE = re.compile(r"^(?P<name>[A-Za-z0-9_.-]+)\[(?P<extras>[A-Za-z0-9_,.-]+)\]$")
_EGG_FRAGMENT_RE = re.compile(r"(?:^|[#&])egg=([^&#]+)")
_PYTHON_VERSION_RE = re.compile(r"(?P<name>[^<>=!~\s]+)(?P<op>===|==|~=|!=|<=|>=|<|>|=)?(?P<version>.*)")
_HTTP_SOURCE_IN_TOKEN_RE = re.compile(r"https?:", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class PackageIntentTarget:
    ecosystem: str
    package_name: str | None
    raw_spec: str = field(repr=False)
    requested_specifier: str | None
    source_url: str | None = field(default=None, repr=False)
    source_kind: str | None = None
    source_repository: str | None = None
    source_revision_kind: str | None = None
    source_identity: str | None = None
    source_invalid_reason: str | None = None
    alias: str | None = None
    dependency_group: str | None = None
    extras: tuple[str, ...] = ()
    editable: bool = False

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        payload["raw_spec"] = _sanitize_url(self.raw_spec)
        payload["raw_spec_hash"] = hashlib.sha256(self.raw_spec.encode("utf-8")).hexdigest()
        if self.source_url is not None:
            payload["source_url"] = _sanitize_url(self.source_url)
            payload["source_url_hash"] = hashlib.sha256(self.source_url.encode("utf-8")).hexdigest()
        return payload

    def to_execution_dict(self) -> dict[str, object]:
        """Return exact request values for ephemeral in-process enforcement."""

        return asdict(self)

    def to_fingerprint_dict(self) -> dict[str, object]:
        """Return approval identity fields with canonical Git source spelling."""

        payload = self.to_dict()
        if self.source_kind == "git" and self.source_identity is not None:
            for exact_field in ("raw_spec", "raw_spec_hash", "source_url", "source_url_hash"):
                _ = payload.pop(exact_field, None)
        return payload


@dataclass(frozen=True, slots=True)
class PackageExecutionFileEvidence:
    """Stable identity evidence for one execution-relevant file."""

    path: str
    resolved_path: str | None
    status: EvidenceStatus
    file_identity: str | None = None
    content_hash: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class LocalPackageExecutionEvidence:
    """Exact local package-runner context included in approval identity."""

    manager_name: str
    path_source: str
    effective_cwd: str
    cwd_source: str
    manager_is_guard_shim: bool
    local_only_requested: bool
    context_hash: str
    package_name: str | None
    executable_name: str | None
    declared_version: str | None
    manager: PackageExecutionFileEvidence | None
    local_executable: PackageExecutionFileEvidence | None
    manifests: tuple[PackageExecutionFileEvidence, ...] = ()
    lockfiles: tuple[PackageExecutionFileEvidence, ...] = ()
    typescript_launch: TypeScriptLaunchEvidence | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class PackageIntent:
    package_manager: str
    intent_kind: IntentKind
    command_tokens: tuple[str, ...] = field(repr=False)
    redacted_command: str
    targets: tuple[PackageIntentTarget, ...]
    manifest_paths: tuple[str, ...] = ()
    lockfile_paths: tuple[str, ...] = ()
    flags: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()
    local_executions: tuple[LocalPackageExecutionEvidence, ...] = ()
    execution_context_hashes: tuple[str, ...] = ()
    execution_context_cwds: tuple[str, ...] = ()
    execution_context_reason_codes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        payload["command_tokens"] = shlex.split(self.redacted_command)
        payload["targets"] = [target.to_dict() for target in self.targets]
        return payload


@dataclass(frozen=True, slots=True)
class ManifestDependencyChange:
    manifest_path: str
    package_name: str
    before: str | None
    after: str | None


@dataclass(frozen=True, slots=True)
class ManifestParseResult:
    changes: tuple[ManifestDependencyChange, ...]
    truncated: bool = False
    parse_errors: tuple[str, ...] = ()


def build_package_request_artifact(
    harness: str,
    intent: PackageIntent,
    *,
    config_path: str,
    source_scope: str,
) -> GuardArtifact:
    manifest_paths, lockfile_paths = _artifact_workspace_paths(intent)
    package_executable = (
        intent.command_tokens[0] if intent.command_tokens and ";" not in intent.command_tokens else None
    )
    fingerprint = hashlib.sha256(
        json.dumps(
            {
                "harness": harness,
                "package_manager": intent.package_manager,
                "intent_kind": intent.intent_kind,
                "redacted_command": _fingerprint_command_shape(intent),
                "targets": [target.to_fingerprint_dict() for target in intent.targets],
                "manifest_paths": list(manifest_paths),
                "lockfile_paths": list(lockfile_paths),
                "local_executions": [evidence.to_dict() for evidence in intent.local_executions],
                "execution_context_hashes": list(intent.execution_context_hashes),
                "execution_context_cwds": list(intent.execution_context_cwds),
                "execution_context_reason_codes": list(intent.execution_context_reason_codes),
            },
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    target_label = intent.targets[0].package_name if intent.targets else intent.package_manager
    return GuardArtifact(
        artifact_id=f"{harness}:{source_scope}:package-request:{fingerprint}",
        name=f"{intent.package_manager} {intent.intent_kind} {target_label}",
        harness=harness,
        artifact_type="package_request",
        source_scope=source_scope,
        config_path=config_path,
        metadata={
            "package_manager": intent.package_manager,
            "package_executable": package_executable,
            "intent_kind": intent.intent_kind,
            "targets": [target.to_dict() for target in intent.targets],
            "manifest_paths": list(manifest_paths),
            "lockfile_paths": list(lockfile_paths),
            "flags": list(intent.flags),
            "notes": list(intent.notes),
            "local_executions": [evidence.to_dict() for evidence in intent.local_executions],
            "shell_execution_context_hashes": list(intent.execution_context_hashes),
            "shell_execution_effective_cwds": list(intent.execution_context_cwds),
            "shell_execution_context_reason_codes": list(intent.execution_context_reason_codes),
            "shell_execution_context_complete": not intent.execution_context_reason_codes,
            "effective_cwd": intent.execution_context_cwds[-1] if intent.execution_context_cwds else None,
            "redacted_command": intent.redacted_command,
            "request_summary": package_request_summary(intent),
            "runtime_request_signals": [f"invokes a package {intent.intent_kind} request via {intent.package_manager}"],
            "runtime_request_summary": package_runtime_summary(intent),
            "runtime_request_reason": package_runtime_reason(intent),
            **_local_execution_runtime_metadata(intent),
        },
        runtime_private_metadata={
            "package_targets": [target.to_execution_dict() for target in intent.targets],
        },
    )


def _artifact_workspace_paths(intent: PackageIntent) -> tuple[tuple[str, ...], tuple[str, ...]]:
    if _is_global_package_install(intent):
        return (), ()
    return intent.manifest_paths, intent.lockfile_paths


def _is_global_package_install(intent: PackageIntent) -> bool:
    if intent.package_manager not in {"npm", "pnpm", "yarn"}:
        return False
    if "multiple-package-segments" in intent.notes:
        return _all_package_segments_are_global(intent)
    return any(_is_true_global_flag(flag) for flag in intent.flags)


def _all_package_segments_are_global(intent: PackageIntent) -> bool:
    segments = tuple(segment.strip() for segment in intent.redacted_command.split(" ; ") if segment.strip())
    if not segments:
        return False
    return all(_segment_has_global_flag(segment) for segment in segments)


def _segment_has_global_flag(segment: str) -> bool:
    try:
        tokens = shlex.split(segment)
    except ValueError:
        tokens = segment.split()
    return any(_is_true_global_flag(token) for token in tokens)


def _is_true_global_flag(flag: str) -> bool:
    normalized = flag.strip().lower()
    if normalized in {"-g", "--global"}:
        return True
    if normalized.startswith("--global="):
        return normalized.split("=", 1)[1] not in {"", "0", "false", "no", "off"}
    return normalized == "--location=global"


def package_request_summary(intent: PackageIntent) -> str:
    if intent.local_executions:
        execution = intent.local_executions[0]
        executable = execution.executable_name or "an unresolved executable"
        manager_path = (
            execution.manager.resolved_path
            if execution.manager is not None and execution.manager.resolved_path is not None
            else "unresolved from the command's effective PATH"
        )
        return (
            f"Requested local `{executable}` execution through `{execution.manager_name}`. Manager: `{manager_path}`."
        )
    if intent.targets:
        target_names = ", ".join(target.package_name or target.raw_spec for target in intent.targets[:3])
        return f"Requested `{intent.package_manager}` {intent.intent_kind} for {target_names}."
    if intent.lockfile_paths:
        return (
            f"Requested `{intent.package_manager}` {intent.intent_kind} using existing project "
            "manifest and lockfile context."
        )
    return f"Requested `{intent.package_manager}` {intent.intent_kind} using existing project manifest context."


def package_runtime_summary(intent: PackageIntent) -> str:
    if intent.local_executions:
        return f"Executes a project package through {intent.package_manager} using an exact local execution identity."
    if intent.intent_kind == "execute":
        return f"Executes a remote package through {intent.package_manager} before it is trusted locally."
    if intent.lockfile_paths:
        return (
            f"Mutates project dependencies through {intent.package_manager} using "
            "existing manifest and lockfile context."
        )
    return f"Mutates project dependencies through {intent.package_manager}."


def package_runtime_reason(intent: PackageIntent) -> str:
    if intent.local_executions:
        return (
            "Guard requires review for the first local package-runner execution and binds reuse to the exact "
            "manager, local executable, manifest, and lockfile evidence."
        )
    return (
        f"Guard parsed this command as a package {intent.intent_kind} request and "
        "kept only package metadata plus a redacted command shape."
    )


def _fingerprint_command_shape(intent: PackageIntent) -> str:
    if not any(target.source_kind == "git" for target in intent.targets):
        return intent.redacted_command
    tokens: list[str] = list(intent.command_tokens)
    for target in intent.targets:
        if target.source_kind != "git":
            continue
        for source_spelling in (target.raw_spec, target.source_url):
            if not source_spelling:
                continue
            tokens = [token.replace(source_spelling, "<canonical-git-source>") for token in tokens]
    return shlex.join(tokens)


def _local_execution_runtime_metadata(intent: PackageIntent) -> dict[str, object]:
    if not intent.local_executions:
        return {}
    return {
        "runtime_request_reason_code": "local_package_execution_review",
        "runtime_request_remediation_hint": (
            "Review the resolved manager and local executable once. Unchanged exact executions reuse that scoped "
            "approval; PATH, executable, manifest, or lockfile changes require review again."
        ),
    }


def redacted_command(tokens: tuple[str, ...]) -> str:
    redacted: list[str] = []
    skip_hash = False
    for token in tokens:
        if skip_hash:
            redacted.append("<hash>")
            skip_hash = False
            continue
        if token == "--hash":
            redacted.append(token)
            skip_hash = True
            continue
        if token.startswith("--hash="):
            redacted.append("--hash=<hash>")
            continue
        if _HTTP_SOURCE_IN_TOKEN_RE.search(token) is not None or token.startswith("git+"):
            redacted.append(_sanitize_url(token))
            continue
        redacted.append(token)
    return shlex.join(redacted)


def redact_package_request_token(value: str) -> str:
    """Return a persistence-safe package argv token without URL credentials."""

    return _sanitize_url(value)


def flag_tokens(tokens: tuple[str, ...]) -> tuple[str, ...]:
    flags: list[str] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token.startswith("-"):
            if token == "--location" and index + 1 < len(tokens) and not tokens[index + 1].startswith("-"):
                flags.append(f"--location={tokens[index + 1]}")
                index += 2
                continue
            if token.startswith(("--global=", "--location=")):
                flags.append(token)
            else:
                flags.append(token.split("=", 1)[0] if token.startswith("--") and "=" in token else token)
        index += 1
    return tuple(dict.fromkeys(flags))


def existing_relative_paths(workspace: Path | None, candidates: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    return existing_paths_within_workspace(workspace, candidates)


def first_positional(tokens: tuple[str, ...], *, skip_value_options: set[str]) -> str | None:
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token in skip_value_options and index + 1 < len(tokens):
            index += 2
            continue
        if token.startswith("-"):
            index += 1
            continue
        return token
    return None


def option_value(tokens: tuple[str, ...], option: str) -> str | None:
    for index, token in enumerate(tokens):
        if token == option and index + 1 < len(tokens):
            return tokens[index + 1]
        if token.startswith(f"{option}="):
            return token.partition("=")[2]
    return None


def property_value(tokens: tuple[str, ...], property_name: str) -> str | None:
    prefix = f"-D{property_name}="
    for token in tokens:
        if token.startswith(prefix):
            return token[len(prefix) :]
    return None


def js_target(spec: str) -> PackageIntentTarget:
    alias = None
    normalized_spec = spec
    if "@npm:" in spec and not spec.startswith("@npm:"):
        alias, _, normalized_spec = spec.partition("@npm:")
    parsed_source = parse_npm_source_spec(normalized_spec)
    if parsed_source is not None and _is_unnamed_js_source_spec(normalized_spec):
        return _js_source_target(spec, normalized_spec, parsed_source, alias=alias)
    named_source_package, source_url = _split_js_named_source_spec(normalized_spec)
    if source_url is not None:
        parsed_source = parse_npm_source_spec(source_url)
        assert parsed_source is not None
        return _js_source_target(spec, source_url, parsed_source, package_name=named_source_package, alias=alias)
    if parsed_source is not None:
        return _js_source_target(spec, normalized_spec, parsed_source, alias=alias)
    package_name, requested_specifier = _split_package_token(normalized_spec)
    parsed_source = parse_npm_source_spec(requested_specifier)
    if requested_specifier is not None and parsed_source is not None:
        return _js_source_target(spec, requested_specifier, parsed_source, package_name=package_name, alias=alias)
    return PackageIntentTarget("npm", package_name, spec, requested_specifier, alias=alias)


def _js_source_target(
    raw_spec: str,
    source_url: str,
    source: NpmSourceSpec,
    *,
    package_name: str | None = None,
    alias: str | None,
) -> PackageIntentTarget:
    return PackageIntentTarget(
        "npm",
        package_name or _source_url_package_name(source_url),
        raw_spec,
        None,
        source_url=source_url,
        source_kind=source.source_kind,
        source_repository=source.canonical_repository,
        source_revision_kind=source.revision_kind,
        source_identity=source.identity,
        source_invalid_reason=source.reason,
        alias=alias,
    )


def python_target(
    spec: str,
    *,
    editable: bool = False,
    dependency_group: str | None = None,
    extras: tuple[str, ...] = (),
) -> PackageIntentTarget:
    if " @ " in spec:
        package_name, _, source = spec.partition(" @ ")
        return PackageIntentTarget("pypi", package_name.strip(), spec, None, source_url=source.strip())
    if "://" in spec or spec.startswith("git+"):
        match = _EGG_FRAGMENT_RE.search(spec)
        sanitized_source = _sanitize_url(spec)
        package_name = match.group(1) if match else PurePath(sanitized_source).name.removesuffix(".git")
        return PackageIntentTarget(
            "pypi",
            package_name or None,
            spec,
            None,
            source_url=spec,
            editable=editable,
        )
    if "@" in spec and not spec.startswith(("./", "../", "/")):
        package_name, requested_specifier = spec.rsplit("@", 1)
        normalized_name, detected_extras = split_python_extras(package_name)
        return PackageIntentTarget(
            "pypi",
            normalized_name or None,
            spec,
            requested_specifier or None,
            dependency_group=dependency_group,
            extras=extras or detected_extras,
            editable=editable,
        )
    normalized_name, requested_specifier = split_python_specifier(spec)
    package_name, detected_extras = split_python_extras(normalized_name)
    if package_name.startswith(("./", "../", "/")):
        package_name = Path(package_name).name or package_name
    return PackageIntentTarget(
        "pypi",
        package_name or None,
        spec,
        requested_specifier,
        dependency_group=dependency_group,
        extras=extras or detected_extras,
        editable=editable,
    )


def version_target(ecosystem: str, spec: str, *, source_url: str | None = None) -> PackageIntentTarget:
    package_name, requested_specifier = _split_package_token(spec)
    return PackageIntentTarget(ecosystem, package_name, spec, requested_specifier, source_url=source_url)


def coordinate_target(ecosystem: str, spec: str) -> PackageIntentTarget:
    parts = spec.split(":")
    if len(parts) < 3:
        return PackageIntentTarget(ecosystem, spec or None, spec, None)
    return PackageIntentTarget(ecosystem, ":".join(parts[:2]), spec, parts[-1] or None)


def composer_target(spec: str) -> PackageIntentTarget:
    package_name, requested_specifier = spec.split(":", 1) if ":" in spec else (spec, None)
    return PackageIntentTarget("packagist", package_name, spec, requested_specifier)


def homebrew_target(spec: str, *, cask: bool = False) -> PackageIntentTarget:
    ecosystem = "homebrew-cask" if cask else "homebrew"
    return PackageIntentTarget(ecosystem, spec or None, spec, None)


def homebrew_tap_target(spec: str, *, source_url: str | None = None) -> PackageIntentTarget:
    return PackageIntentTarget("homebrew-tap", spec or None, spec, None, source_url=source_url)


def split_python_specifier(spec: str) -> tuple[str, str | None]:
    matched = _PYTHON_VERSION_RE.match(spec.strip())
    if matched is None:
        return spec, None
    name = matched.group("name") or spec
    operator = matched.group("op")
    version = (matched.group("version") or "").strip()
    if operator and version:
        return name, version if operator in {"==", "==="} else f"{operator}{version}"
    return name, None


def split_python_extras(name: str) -> tuple[str, tuple[str, ...]]:
    matched = _EXTRAS_RE.match(name)
    if matched is None:
        return name, ()
    return matched.group("name"), tuple(item for item in matched.group("extras").split(",") if item)


def _sanitize_url(value: str) -> str:
    http_source = _HTTP_SOURCE_IN_TOKEN_RE.search(value)
    if http_source is not None:
        source = value[http_source.start() :]
        if re.match(r"(?i)^https?://[^/\\]", source) is None:
            scheme = source.partition(":")[0].lower()
            # npm treats slashless, single-slash, and backslash HTTP(S)
            # specifiers as remote URLs.  They are rejected by Guard, and the
            # persisted command shape must not retain their query/userinfo.
            return f"{value[: http_source.start()]}{scheme}:<redacted-source>"
    if "://" not in value and not value.startswith("git+"):
        return value
    scheme_split = value.split("://", 1)
    if len(scheme_split) == 2 and "@" in scheme_split[1].split("/", 1)[0]:
        scheme, remainder = scheme_split
        authority, *tail = remainder.split("/", 1)
        authority = authority.rsplit("@", 1)[1]
        suffix = f"/{tail[0]}" if tail else ""
        return f"{scheme}://{authority}{suffix}".split("?", 1)[0].split("#", 1)[0]
    return value.split("?", 1)[0].split("#", 1)[0]


def _split_js_named_source_spec(spec: str) -> tuple[str | None, str | None]:
    for index, character in enumerate(spec):
        if character != "@" or index == 0:
            continue
        package_name = spec[:index].strip()
        source_candidate = spec[index + 1 :].strip()
        if package_name and parse_npm_source_spec(source_candidate) is not None:
            return package_name, source_candidate
    return None, None


def _is_unnamed_js_source_spec(value: str) -> bool:
    lowered = value.lower()
    return (
        re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", value) is not None
        or lowered.startswith(("git@", "git+", "github:", "gitlab:", "bitbucket:", "file:"))
        or "@" not in value
    )


def _source_url_package_name(source_url: str) -> str | None:
    parsed_source = parse_npm_source_spec(source_url)
    if parsed_source is not None and parsed_source.canonical_repository is not None:
        return parsed_source.canonical_repository.rsplit("/", 1)[-1] or None
    normalized = source_url.strip()
    candidate = (
        normalized.partition(":")[2]
        if normalized.startswith(("github:", "gitlab:", "bitbucket:", "file:"))
        else normalized
    )
    sanitized = _sanitize_url(candidate)
    package_name = PurePath(sanitized).name
    if package_name.endswith(".tar.gz"):
        return package_name[: -len(".tar.gz")] or normalized
    if package_name.endswith((".git", ".tar", ".tgz")):
        return package_name.rsplit(".", 1)[0] or normalized
    return package_name or normalized

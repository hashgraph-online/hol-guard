"""Shared package intent models and artifact builders."""

from __future__ import annotations

import hashlib
import json
import re
import shlex
from dataclasses import asdict, dataclass
from pathlib import Path, PurePath
from typing import Literal

from ..models import GuardArtifact
from .mcp_protection import _split_package_token
from .typescript_launch_evidence import TypeScriptLaunchEvidence
from .workspace_path_guard import existing_paths_within_workspace

IntentKind = Literal["install", "execute", "sync"]
EvidenceStatus = Literal["available", "missing", "not_regular", "unreadable", "unstable"]
_EXTRAS_RE = re.compile(r"^(?P<name>[A-Za-z0-9_.-]+)\[(?P<extras>[A-Za-z0-9_,.-]+)\]$")
_EGG_FRAGMENT_RE = re.compile(r"(?:^|[#&])egg=([^&#]+)")
_PYTHON_VERSION_RE = re.compile(r"(?P<name>[^<>=!~\s]+)(?P<op>===|==|~=|!=|<=|>=|<|>|=)?(?P<version>.*)")
_JS_SOURCE_PREFIXES = ("http://", "https://", "git+", "github:", "gitlab:", "bitbucket:", "file:")


@dataclass(frozen=True, slots=True)
class PackageIntentTarget:
    ecosystem: str
    package_name: str | None
    raw_spec: str
    requested_specifier: str | None
    source_url: str | None = None
    alias: str | None = None
    dependency_group: str | None = None
    extras: tuple[str, ...] = ()
    editable: bool = False

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


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
    command_tokens: tuple[str, ...]
    redacted_command: str
    targets: tuple[PackageIntentTarget, ...]
    manifest_paths: tuple[str, ...] = ()
    lockfile_paths: tuple[str, ...] = ()
    flags: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()
    local_executions: tuple[LocalPackageExecutionEvidence, ...] = ()

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
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
                "redacted_command": intent.redacted_command,
                "targets": [target.to_dict() for target in intent.targets],
                "manifest_paths": list(manifest_paths),
                "lockfile_paths": list(lockfile_paths),
                "local_executions": [evidence.to_dict() for evidence in intent.local_executions],
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
            "redacted_command": intent.redacted_command,
            "request_summary": package_request_summary(intent),
            "runtime_request_signals": [f"invokes a package {intent.intent_kind} request via {intent.package_manager}"],
            "runtime_request_summary": package_runtime_summary(intent),
            "runtime_request_reason": package_runtime_reason(intent),
            **_local_execution_runtime_metadata(intent),
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
        if "://" in token or token.startswith("git+"):
            redacted.append(_sanitize_url(token))
            continue
        redacted.append(token)
    return shlex.join(redacted)


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
    named_source_package, source_url = _split_js_named_source_spec(normalized_spec)
    if source_url is not None:
        return PackageIntentTarget("npm", named_source_package, spec, None, source_url=source_url, alias=alias)
    if _looks_like_js_source_spec(normalized_spec):
        return PackageIntentTarget(
            "npm",
            _source_url_package_name(normalized_spec),
            spec,
            None,
            source_url=normalized_spec,
            alias=alias,
        )
    package_name, requested_specifier = _split_package_token(normalized_spec)
    if _looks_like_js_source_spec(requested_specifier):
        return PackageIntentTarget("npm", package_name, spec, None, source_url=requested_specifier, alias=alias)
    return PackageIntentTarget("npm", package_name, spec, requested_specifier, alias=alias)


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
        sanitized_source = spec.split("?", 1)[0].split("#", 1)[0]
        package_name = match.group(1) if match else PurePath(sanitized_source).name.removesuffix(".git")
        return PackageIntentTarget(
            "pypi",
            package_name or None,
            spec,
            None,
            source_url=sanitized_source,
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
    if "://" not in value and not value.startswith("git+"):
        return value
    scheme_split = value.split("://", 1)
    if len(scheme_split) == 2 and "@" in scheme_split[1].split("/", 1)[0]:
        scheme, remainder = scheme_split
        authority, *tail = remainder.split("/", 1)
        authority = authority.split("@", 1)[1]
        suffix = f"/{tail[0]}" if tail else ""
        return f"{scheme}://{authority}{suffix}".split("?", 1)[0].split("#", 1)[0]
    return value.split("?", 1)[0].split("#", 1)[0]


def _split_js_named_source_spec(spec: str) -> tuple[str | None, str | None]:
    if "@" not in spec:
        return None, None
    package_name, source_candidate = spec.rsplit("@", 1)
    normalized_package_name = package_name.strip()
    normalized_source = source_candidate.strip()
    if not normalized_package_name or not _looks_like_js_source_spec(normalized_source):
        return None, None
    return normalized_package_name, normalized_source


def _looks_like_js_source_spec(value: str | None) -> bool:
    if not value:
        return False
    normalized = value.strip()
    if normalized.startswith(_JS_SOURCE_PREFIXES) or "://" in normalized:
        return True
    if normalized.startswith("@") or normalized.startswith(("./", "../", "/")) or ":" in normalized:
        return False
    parts = normalized.split("/")
    return len(parts) == 2 and all(part.strip() for part in parts)


def _source_url_package_name(source_url: str) -> str | None:
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

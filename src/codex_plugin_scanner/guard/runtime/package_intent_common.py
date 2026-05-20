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

IntentKind = Literal["install", "execute", "sync"]
_EXTRAS_RE = re.compile(r"^(?P<name>[A-Za-z0-9_.-]+)\[(?P<extras>[A-Za-z0-9_,.-]+)\]$")
_EGG_FRAGMENT_RE = re.compile(r"(?:^|[#&])egg=([^&#]+)")
_PYTHON_VERSION_RE = re.compile(r"(?P<name>[^<>=!~\s]+)(?P<op>===|==|~=|!=|<=|>=|<|>|=)?(?P<version>.*)")


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
    fingerprint = hashlib.sha256(
        json.dumps(
            {
                "harness": harness,
                "package_manager": intent.package_manager,
                "intent_kind": intent.intent_kind,
                "redacted_command": intent.redacted_command,
                "targets": [target.to_dict() for target in intent.targets],
                "manifest_paths": list(intent.manifest_paths),
                "lockfile_paths": list(intent.lockfile_paths),
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
            "intent_kind": intent.intent_kind,
            "targets": [target.to_dict() for target in intent.targets],
            "manifest_paths": list(intent.manifest_paths),
            "lockfile_paths": list(intent.lockfile_paths),
            "flags": list(intent.flags),
            "notes": list(intent.notes),
            "redacted_command": intent.redacted_command,
            "request_summary": package_request_summary(intent),
            "runtime_request_signals": [f"invokes a package {intent.intent_kind} request via {intent.package_manager}"],
            "runtime_request_summary": package_runtime_summary(intent),
            "runtime_request_reason": package_runtime_reason(intent),
        },
    )


def package_request_summary(intent: PackageIntent) -> str:
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
    if intent.intent_kind == "execute":
        return f"Executes a remote package through {intent.package_manager} before it is trusted locally."
    if intent.lockfile_paths:
        return (
            f"Mutates project dependencies through {intent.package_manager} using "
            "existing manifest and lockfile context."
        )
    return f"Mutates project dependencies through {intent.package_manager}."


def package_runtime_reason(intent: PackageIntent) -> str:
    return (
        f"Guard parsed this command as a package {intent.intent_kind} request and "
        "kept only package metadata plus a redacted command shape."
    )


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
    for token in tokens:
        if token.startswith("-"):
            flags.append(token.split("=", 1)[0] if token.startswith("--") and "=" in token else token)
    return tuple(dict.fromkeys(flags))


def existing_relative_paths(workspace: Path | None, candidates: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    if workspace is None:
        return ()
    resolved: list[str] = []
    for candidate in candidates:
        if not candidate:
            continue
        path = Path(candidate)
        disk_path = path if path.is_absolute() else workspace / path
        if disk_path.exists():
            normalized = candidate if not path.is_absolute() else path.name
            if normalized not in resolved:
                resolved.append(normalized)
    return tuple(resolved)


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
    package_name, requested_specifier = _split_package_token(normalized_spec)
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

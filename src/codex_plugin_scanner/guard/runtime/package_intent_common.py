"""Shared package intent models and artifact builders."""

from __future__ import annotations

import hashlib
import re
import shlex
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Literal, cast

from ..models import GuardArtifact
from .typescript_launch_evidence import TypeScriptLaunchEvidence, TypeScriptLaunchStatus

IntentKind = Literal["install", "execute", "sync"]
EvidenceStatus = Literal["available", "missing", "not_regular", "unreadable", "unstable"]
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
    #: Whether the native parser judged this a routine local JS runner already
    #: bound to local project state. The runtime computes it beside the
    #: manifest, lockfile and executable reads it depends on; Python reads it.
    routine_local_runner: bool = False

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        payload["command_tokens"] = shlex.split(self.redacted_command)
        payload["targets"] = [target.to_dict() for target in self.targets]
        return payload

    @classmethod
    def from_dict(
        cls,
        payload: Mapping[str, object],
        *,
        runtime_private_metadata: Mapping[str, object] | None = None,
    ) -> PackageIntent:
        """Hydrate exact private targets and argv without rehashing redacted sources."""

        if not isinstance(payload.get("package_manager"), str):
            raise ValueError("package intent payload missing package_manager")
        intent_kind = payload.get("intent_kind")
        if intent_kind not in ("install", "execute", "sync"):
            raise ValueError("package intent payload missing intent_kind")
        targets = _package_intent_targets_from_dict(payload.get("targets"), runtime_private_metadata)
        redacted_command = payload.get("redacted_command")
        if runtime_private_metadata is not None:
            command_tokens = runtime_private_metadata.get("command_tokens")
            if not isinstance(command_tokens, (list, tuple)) or any(
                not isinstance(token, str) for token in command_tokens
            ):
                raise ValueError("package intent exact command metadata missing")
        else:
            command_tokens = payload.get("command_tokens")
            if not isinstance(command_tokens, (list, tuple)) and isinstance(redacted_command, str):
                command_tokens = shlex.split(redacted_command)
        return cls(
            package_manager=str(payload["package_manager"]),
            intent_kind=cast(IntentKind, intent_kind),
            command_tokens=_str_tuple(command_tokens),
            redacted_command=str(redacted_command) if isinstance(redacted_command, str) else "",
            targets=targets,
            manifest_paths=_str_tuple(payload.get("manifest_paths")),
            lockfile_paths=_str_tuple(payload.get("lockfile_paths")),
            flags=_str_tuple(payload.get("flags")),
            notes=_str_tuple(payload.get("notes")),
            local_executions=tuple(
                evidence
                for evidence in (
                    _local_execution_evidence_from_dict(item) for item in _dict_items(payload.get("local_executions"))
                )
                if evidence is not None
            ),
            execution_context_hashes=_str_tuple(payload.get("execution_context_hashes")),
            execution_context_cwds=_str_tuple(payload.get("execution_context_cwds")),
            execution_context_reason_codes=_str_tuple(payload.get("execution_context_reason_codes")),
            routine_local_runner=payload.get("routine_local_runner") is True,
        )


def _dict_items(value: object) -> tuple[Mapping[str, object], ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(item for item in value if isinstance(item, Mapping))


def _str_tuple(value: object) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(item for item in value if isinstance(item, str))


def _opt_str(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _package_execution_file_evidence_from_dict(
    value: object,
) -> PackageExecutionFileEvidence | None:
    if not isinstance(value, Mapping):
        return None
    status = value.get("status")
    if status not in ("available", "missing", "not_regular", "unreadable", "unstable"):
        status = "missing"
    path = value.get("path")
    return PackageExecutionFileEvidence(
        path=path if isinstance(path, str) else "",
        resolved_path=_opt_str(value.get("resolved_path")),
        status=cast(EvidenceStatus, status),
        file_identity=_opt_str(value.get("file_identity")),
        content_hash=_opt_str(value.get("content_hash")),
    )


def _typescript_launch_evidence_from_dict(value: object) -> TypeScriptLaunchEvidence | None:
    if not isinstance(value, Mapping):
        return None
    status = value.get("status")
    if status not in ("complete", "incomplete"):
        status = "incomplete"
    schema_version = value.get("schema_version")
    return TypeScriptLaunchEvidence(
        schema_version=schema_version if isinstance(schema_version, int) else 0,
        status=cast(TypeScriptLaunchStatus, status),
        reasons=_str_tuple(value.get("reasons")),
        binding_digest=str(value.get("binding_digest") or ""),
        manager_name=str(value.get("manager_name") or ""),
        package_name=_opt_str(value.get("package_name")),
        executable_name=_opt_str(value.get("executable_name")),
        declared_version=_opt_str(value.get("declared_version")),
        locked_version=_opt_str(value.get("locked_version")),
        installed_version=_opt_str(value.get("installed_version")),
        config_mode=str(value.get("config_mode") or "implicit_or_config_driven"),
        source_files=_str_tuple(value.get("source_files")),
        direct_silent_verification=bool(value.get("direct_silent_verification")),
    )


def _local_execution_evidence_from_dict(value: object) -> LocalPackageExecutionEvidence | None:
    if not isinstance(value, Mapping):
        return None
    return LocalPackageExecutionEvidence(
        manager_name=str(value.get("manager_name") or ""),
        path_source=str(value.get("path_source") or ""),
        effective_cwd=str(value.get("effective_cwd") or ""),
        cwd_source=str(value.get("cwd_source") or ""),
        manager_is_guard_shim=bool(value.get("manager_is_guard_shim")),
        local_only_requested=bool(value.get("local_only_requested")),
        context_hash=str(value.get("context_hash") or ""),
        package_name=_opt_str(value.get("package_name")),
        executable_name=_opt_str(value.get("executable_name")),
        declared_version=_opt_str(value.get("declared_version")),
        manager=_package_execution_file_evidence_from_dict(value.get("manager")),
        local_executable=_package_execution_file_evidence_from_dict(value.get("local_executable")),
        manifests=tuple(
            evidence
            for evidence in (
                _package_execution_file_evidence_from_dict(item) for item in _dict_items(value.get("manifests"))
            )
            if evidence is not None
        ),
        lockfiles=tuple(
            evidence
            for evidence in (
                _package_execution_file_evidence_from_dict(item) for item in _dict_items(value.get("lockfiles"))
            )
            if evidence is not None
        ),
        typescript_launch=_typescript_launch_evidence_from_dict(value.get("typescript_launch")),
    )


def _package_intent_targets_from_dict(
    public_targets: object,
    runtime_private_metadata: Mapping[str, object] | None,
) -> tuple[PackageIntentTarget, ...]:
    targets: list[PackageIntentTarget] = []
    if runtime_private_metadata is None:
        for public_target in _dict_items(public_targets):
            target = _package_intent_target_from_dict(public_target)
            if target is None:
                continue
            expected = target.to_dict()
            if any(
                key in public_target and public_target[key] != expected.get(key)
                for key in ("raw_spec_hash", "source_url_hash")
            ):
                raise ValueError("package intent exact target metadata missing")
            targets.append(target)
        return tuple(targets)

    private_targets = runtime_private_metadata.get("package_targets")
    if (
        not isinstance(public_targets, (list, tuple))
        or not isinstance(private_targets, (list, tuple))
        or len(private_targets) != len(public_targets)
    ):
        raise ValueError("package intent private target integrity invalid")
    for private_target, public_target in zip(private_targets, public_targets, strict=True):
        target = _package_intent_target_from_dict(private_target)
        if target is None or not isinstance(public_target, Mapping):
            raise ValueError("package intent private target integrity invalid")
        public_fields = dict(public_target)
        extras = public_fields.get("extras")
        if isinstance(extras, list):
            public_fields["extras"] = tuple(extras)
        if target.to_dict() != public_fields:
            raise ValueError("package intent private target integrity invalid")
        targets.append(target)
    return tuple(targets)


def _package_intent_target_from_dict(value: object) -> PackageIntentTarget | None:
    if not isinstance(value, Mapping):
        return None
    ecosystem = value.get("ecosystem")
    if not isinstance(ecosystem, str) or not ecosystem:
        return None
    return PackageIntentTarget(
        ecosystem=ecosystem,
        package_name=_opt_str(value.get("package_name")),
        raw_spec=str(value.get("raw_spec") or ""),
        requested_specifier=_opt_str(value.get("requested_specifier")),
        source_url=_opt_str(value.get("source_url")),
        source_kind=_opt_str(value.get("source_kind")),
        source_repository=_opt_str(value.get("source_repository")),
        source_revision_kind=_opt_str(value.get("source_revision_kind")),
        source_identity=_opt_str(value.get("source_identity")),
        source_invalid_reason=_opt_str(value.get("source_invalid_reason")),
        alias=_opt_str(value.get("alias")),
        dependency_group=_opt_str(value.get("dependency_group")),
        extras=_str_tuple(value.get("extras")),
        editable=bool(value.get("editable")),
    )


def build_package_request_artifact(
    harness: str,
    intent: PackageIntent,
    *,
    config_path: str,
    source_scope: str,
    guard_home: Path | None = None,
    deadline_monotonic: float | None = None,
) -> GuardArtifact:
    """Name the review a package request gets, by asking the runtime.

    The id this returns is the key a saved package approval is stored under, so
    it has exactly one derivation: the runtime's own builder, over the exact
    intent. Deriving it a second time here would let the two spellings drift
    and silently re-key reviews the user had already approved.

    The import is local because `native_package_authority` imports the artifact
    model this module's callers also reach through.
    """
    from ..native_package_authority import package_request_artifact_native

    return package_request_artifact_native(
        intent,
        harness=harness,
        config_path=config_path,
        source_scope=source_scope,
        guard_home=guard_home,
        deadline_monotonic=deadline_monotonic,
    )


def redact_package_request_token(value: str) -> str:
    """Return a persistence-safe package argv token without URL credentials."""

    return _sanitize_url(value)


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

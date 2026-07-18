"""Trusted policy file I/O and local policy row adapters."""

from __future__ import annotations

import difflib
import hashlib
import itertools
import json
import os
import re
import secrets
import stat
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Final, cast, final

from .models import DecisionScope, GuardAction, PolicyDecision
from .policy_document import GuardPolicyDocument, PolicyRule
from .policy_document_yaml import (
    MAX_POLICY_BYTES,
    format_policy_document_yaml,
    parse_policy_document_yaml,
)

_POLICY_API_VERSION: Final = "guard.hashgraphonline.com/v1alpha1"
_POLICY_KIND: Final = "GuardPolicy"
_POLICY_IMPORT_SOURCE: Final = "policy-yaml-import"
_POLICY_FILE_MODE: Final = 0o600
_POLICY_DIRECTORY_MODE_MASK: Final = 0o022
_MAX_COMPILED_ROWS: Final = 10_000
_IDENTIFIER_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_UTC_TIMESTAMP_RE: Final = re.compile(
    r"^[0-9]{4}-(0[1-9]|1[0-2])-([0-2][0-9]|3[01])T" + r"([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](\.[0-9]{1,9})?Z$"
)
_REDACTED_TIMESTAMP: Final = "1970-01-01T00:00:00Z"
_SUPPORTED_MATCH_KEYS: Final = frozenset({"artifacts", "harnesses", "publishers", "tools", "workspaces"})
_TOOL_SELECTOR_FAMILIES: Final = {
    "file-read": "file-read",
    "mcp": "mcp",
    "mcp-tool": "mcp-tool",
    "package-request": "package-request",
    "prompt": "prompt",
    "prompt-env-read": "prompt-env-read",
    "prompt-file": "prompt-file",
    "shell": "tool-action",
    "tool-action": "tool-action",
}
_LOCAL_SCOPES: Final = frozenset({"artifact", "workspace", "publisher", "harness", "global"})
_PROVENANCE_SOURCES: Final = frozenset(
    {
        "suggested-memory",
        "review-decision",
        "builder",
        "import",
        "legacy",
        "cloud",
        "local",
        "policy-bundle",
    }
)


@final
class PolicyFileTrustError(ValueError):
    """Raised when a policy path cannot be trusted for local I/O."""

    def __init__(self, code: str, path: Path) -> None:
        self.code = code
        self.path = path
        super().__init__(code)


@final
class PolicyCompilationError(ValueError):
    """Raised when a canonical rule cannot map to local PolicyDecision rows."""

    def __init__(self, code: str, rule_id: str) -> None:
        self.code = code
        self.rule_id = rule_id
        super().__init__(f"{code}: {rule_id}")


@dataclass(frozen=True)
class CompiledPolicyRow:
    decision: PolicyDecision
    rule_id: str
    provenance_json: str


@dataclass(frozen=True, slots=True)
class PolicyDocumentDiff:
    changed: bool
    text: str
    additions: tuple[str, ...]
    modifications: tuple[str, ...]
    removals: tuple[str, ...]
    impacted_scopes: tuple[str, ...]
    impacted_harnesses: tuple[str, ...]
    impacted_artifact_families: tuple[str, ...]
    conflict_warnings: tuple[str, ...]
    broadened_rules: tuple[str, ...] = ()
    narrowed_rules: tuple[str, ...] = ()
    unchanged_rules: tuple[str, ...] = ()
    effective_action_changes: tuple[str, ...] = ()
    broad_relaxing_changes: tuple[str, ...] = ()


def _assert_trusted_parent_metadata(path: Path, metadata: os.stat_result) -> None:
    if not stat.S_ISDIR(metadata.st_mode):
        raise PolicyFileTrustError("policy_parent_not_directory", path)
    if metadata.st_uid != os.geteuid():
        raise PolicyFileTrustError("policy_parent_not_owned", path)
    if stat.S_IMODE(metadata.st_mode) & _POLICY_DIRECTORY_MODE_MASK:
        raise PolicyFileTrustError("policy_parent_insecure_mode", path)


def _open_trusted_parent(path: Path) -> int:
    parent = path.parent
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        parts = parent.parts
        if not parts:
            raise OSError("policy parent has no path components")
        descriptor = os.open(parts[0], flags)
        for component in parts[1:]:
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        _assert_trusted_parent_metadata(parent, os.fstat(descriptor))
        return descriptor
    except PolicyFileTrustError:
        if descriptor is not None:
            os.close(descriptor)
        raise
    except OSError as error:
        if descriptor is not None:
            os.close(descriptor)
        raise PolicyFileTrustError("policy_parent_unavailable", parent) from error


def _assert_trusted_file_metadata(path: Path, metadata: os.stat_result) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise PolicyFileTrustError("policy_file_not_regular", path)
    if metadata.st_uid != os.geteuid():
        raise PolicyFileTrustError("policy_file_not_owned", path)
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        raise PolicyFileTrustError("policy_file_insecure_mode", path)
    if metadata.st_nlink != 1:
        raise PolicyFileTrustError("policy_file_link_count", path)


def read_trusted_policy_bytes(path: Path, *, max_bytes: int = MAX_POLICY_BYTES) -> bytes:
    """Read one bounded, owner-only regular file without following links."""

    candidate = path.expanduser().absolute()
    parent_descriptor = _open_trusted_parent(candidate)
    try:
        try:
            before = os.stat(
                candidate.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except OSError as error:
            raise PolicyFileTrustError("policy_file_unavailable", candidate) from error
        _assert_trusted_file_metadata(candidate, before)
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(candidate.name, flags, dir_fd=parent_descriptor)
        except OSError as error:
            raise PolicyFileTrustError("policy_file_open_failed", candidate) from error
        try:
            opened = os.fstat(descriptor)
            _assert_trusted_file_metadata(candidate, opened)
            if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                raise PolicyFileTrustError("policy_file_changed", candidate)
            chunks: list[bytes] = []
            remaining = max_bytes + 1
            while remaining > 0:
                chunk = os.read(descriptor, min(65_536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            payload = b"".join(chunks)
            if len(payload) > max_bytes:
                raise PolicyFileTrustError("policy_file_too_large", candidate)
            return payload
        finally:
            os.close(descriptor)
    finally:
        os.close(parent_descriptor)


def read_trusted_policy_text(path: Path, *, max_bytes: int = MAX_POLICY_BYTES) -> str:
    payload = read_trusted_policy_bytes(path, max_bytes=max_bytes)
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise PolicyFileTrustError("policy_file_not_utf8", path.expanduser().absolute()) from error


def write_private_policy_text(path: Path, content: str) -> None:
    """Atomically replace an owner-only policy file inside a private directory."""

    candidate = path.expanduser().absolute()
    payload = content.encode("utf-8")
    if len(payload) > MAX_POLICY_BYTES:
        raise PolicyFileTrustError("policy_output_too_large", candidate)
    parent_descriptor = _open_trusted_parent(candidate)
    temporary_name = f".{candidate.name}.{secrets.token_hex(12)}.tmp"
    descriptor: int | None = None
    try:
        try:
            existing = os.stat(
                candidate.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            existing = None
        except OSError as error:
            raise PolicyFileTrustError("policy_output_unavailable", candidate) from error
        if existing is not None:
            _assert_trusted_file_metadata(candidate, existing)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(
            temporary_name,
            flags,
            _POLICY_FILE_MODE,
            dir_fd=parent_descriptor,
        )
        os.fchmod(descriptor, _POLICY_FILE_MODE)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("policy output write made no progress")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.replace(
            temporary_name,
            candidate.name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
        )
        os.fsync(parent_descriptor)
    except PolicyFileTrustError:
        raise
    except OSError as error:
        raise PolicyFileTrustError("policy_output_write_failed", candidate) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary_name, dir_fd=parent_descriptor)
        except FileNotFoundError:
            pass
        except OSError:
            pass
        os.close(parent_descriptor)


def load_trusted_policy_document(path: Path) -> GuardPolicyDocument:
    return parse_policy_document_yaml(read_trusted_policy_text(path))


def format_trusted_policy_file(source: Path, destination: Path) -> GuardPolicyDocument:
    document = load_trusted_policy_document(source)
    write_private_policy_text(destination, format_policy_document_yaml(document))
    return document


def _artifact_family(value: str) -> str:
    for separator in (":", "/"):
        if separator in value:
            return value.split(separator, 1)[0]
    return value


def _semantic_policy_diff(
    baseline: GuardPolicyDocument,
    candidate: GuardPolicyDocument,
) -> tuple[
    tuple[str, ...],
    tuple[str, ...],
    tuple[str, ...],
    tuple[str, ...],
    tuple[str, ...],
    tuple[str, ...],
    tuple[str, ...],
]:
    baseline_rules = {rule.id: rule for rule in baseline.rules}
    candidate_rules = {rule.id: rule for rule in candidate.rules}
    additions = tuple(sorted(candidate_rules.keys() - baseline_rules.keys()))
    removals = tuple(sorted(baseline_rules.keys() - candidate_rules.keys()))
    modifications = tuple(
        sorted(
            rule_id
            for rule_id in baseline_rules.keys() & candidate_rules.keys()
            if baseline_rules[rule_id].to_mapping() != candidate_rules[rule_id].to_mapping()
        )
    )
    changed_ids = set(additions) | set(modifications) | set(removals)
    impacted_rules = [
        rule
        for rule_id in sorted(changed_ids)
        for rule in (candidate_rules.get(rule_id) or baseline_rules.get(rule_id),)
        if rule is not None
    ]
    impacted_scopes = {field for rule in impacted_rules for field, values in rule.match.fields if values}
    impacted_harnesses = {
        value
        for rule in impacted_rules
        for field, values in rule.match.fields
        if field == "harnesses"
        for value in values
    }
    impacted_artifact_families = {
        _artifact_family(value)
        for rule in impacted_rules
        for field, values in rule.match.fields
        if field == "artifacts"
        for value in values
    }
    enabled_candidate_rules = [rule for rule in candidate.rules if rule.enabled]
    conflict_warnings = tuple(
        sorted(
            f"overlapping_effects:{left.id}:{right.id}"
            for left, right in itertools.combinations(enabled_candidate_rules, 2)
            if left.effect != right.effect and _matches_overlap(left, right)
        )
    )
    return (
        additions,
        modifications,
        removals,
        tuple(sorted(impacted_scopes)),
        tuple(sorted(impacted_harnesses)),
        tuple(sorted(impacted_artifact_families)),
        conflict_warnings,
    )


def _match_fields(rule: PolicyRule) -> dict[str, frozenset[str]]:
    return {field: frozenset(values) for field, values in rule.match.fields if values}


def _match_contains(container: PolicyRule, contained: PolicyRule) -> bool:
    container_fields = _match_fields(container)
    contained_fields = _match_fields(contained)
    return all(
        field in contained_fields and values.issuperset(contained_fields[field])
        for field, values in container_fields.items()
    )


def _matches_overlap(left: PolicyRule, right: PolicyRule) -> bool:
    left_fields = _match_fields(left)
    right_fields = _match_fields(right)
    return all(bool(left_fields[field] & right_fields[field]) for field in left_fields.keys() & right_fields.keys())


def _restrictive_lifetime_relaxed(previous: PolicyRule, current: PolicyRule) -> bool:
    if previous.lifetime == current.lifetime:
        return False
    if previous.lifetime.mode == "permanent":
        return current.lifetime.mode != "permanent"
    if current.lifetime.mode == "permanent":
        return False
    if previous.lifetime.mode != current.lifetime.mode:
        return True
    previous_expiry = previous.lifetime.expires_at
    current_expiry = current.lifetime.expires_at
    if previous_expiry is None:
        return current_expiry is not None
    if current_expiry is None:
        return False
    return datetime.fromisoformat(current_expiry.replace("Z", "+00:00")) < datetime.fromisoformat(
        previous_expiry.replace("Z", "+00:00")
    )


_DEFAULT_ENFORCEMENT_STRENGTH = {
    "allow": 0,
    "ignore": 0,
    "observe": 0,
    "warn": 1,
    "review": 1,
    "prompt": 1,
    "require-reapproval": 2,
    "block": 3,
    "enforce": 3,
}


def _classify_default_changes(
    baseline: GuardPolicyDocument,
    candidate: GuardPolicyDocument,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    baseline_defaults = baseline.defaults.to_mapping()
    candidate_defaults = candidate.defaults.to_mapping()
    changes: list[str] = []
    broad_relaxing: list[str] = []
    for key in sorted(baseline_defaults.keys() | candidate_defaults.keys()):
        previous = baseline_defaults.get(key)
        current = candidate_defaults.get(key)
        if previous == current:
            continue
        changes.append(f"defaults.{key}:{previous}->{current}")
        previous_strength = _DEFAULT_ENFORCEMENT_STRENGTH.get(previous) if isinstance(previous, str) else None
        current_strength = _DEFAULT_ENFORCEMENT_STRENGTH.get(current) if isinstance(current, str) else None
        if previous_strength is not None and current_strength is not None and current_strength < previous_strength:
            broad_relaxing.append(f"defaults.{key}")
    return tuple(changes), tuple(broad_relaxing)


def _classify_rule_changes(
    baseline: GuardPolicyDocument,
    candidate: GuardPolicyDocument,
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    baseline_rules = {rule.id: rule for rule in baseline.rules}
    candidate_rules = {rule.id: rule for rule in candidate.rules}
    shared_ids = baseline_rules.keys() & candidate_rules.keys()
    broadened: list[str] = []
    narrowed: list[str] = []
    unchanged: list[str] = []
    action_changes: list[str] = []
    broad_relaxing: list[str] = []
    restrictive_effects = frozenset({"block", "review"})
    relaxing_effects = frozenset({"allow", "ignore"})

    for rule_id in sorted(shared_ids):
        previous = baseline_rules[rule_id]
        current = candidate_rules[rule_id]
        if previous.to_mapping() == current.to_mapping():
            unchanged.append(rule_id)
            continue
        current_contains_previous = _match_contains(current, previous)
        previous_contains_current = _match_contains(previous, current)
        if current_contains_previous and not previous_contains_current:
            broadened.append(rule_id)
        elif previous_contains_current and not current_contains_previous:
            narrowed.append(rule_id)
        if previous.effect != current.effect or previous.enabled != current.enabled:
            action_changes.append(
                f"{rule_id}:{previous.effect if previous.enabled else 'disabled'}"
                f"->{current.effect if current.enabled else 'disabled'}"
            )
        relaxes_effect = (
            previous.enabled
            and previous.effect in restrictive_effects
            and (not current.enabled or current.effect in relaxing_effects)
        )
        relaxes_lifetime = (
            previous.enabled
            and current.enabled
            and previous.effect in restrictive_effects
            and current.effect in restrictive_effects
            and _restrictive_lifetime_relaxed(previous, current)
        )
        if (
            relaxes_effect
            or relaxes_lifetime
            or (
                current.enabled
                and current.effect in relaxing_effects
                and current_contains_previous
                and not previous_contains_current
            )
        ):
            broad_relaxing.append(rule_id)

    for rule_id in sorted(candidate_rules.keys() - baseline_rules.keys()):
        current = candidate_rules[rule_id]
        if current.enabled and current.effect in relaxing_effects:
            broad_relaxing.append(rule_id)
    for rule_id in sorted(baseline_rules.keys() - candidate_rules.keys()):
        previous = baseline_rules[rule_id]
        if previous.enabled and previous.effect in restrictive_effects:
            broad_relaxing.append(rule_id)

    default_changes, default_relaxing = _classify_default_changes(baseline, candidate)
    action_changes.extend(default_changes)
    broad_relaxing.extend(default_relaxing)
    return (
        tuple(broadened),
        tuple(narrowed),
        tuple(unchanged),
        tuple(action_changes),
        tuple(sorted(set(broad_relaxing))),
    )


def diff_policy_documents(
    baseline: GuardPolicyDocument,
    candidate: GuardPolicyDocument,
    *,
    baseline_name: str = "baseline",
    candidate_name: str = "candidate",
) -> PolicyDocumentDiff:
    baseline_text = format_policy_document_yaml(baseline)
    candidate_text = format_policy_document_yaml(candidate)
    lines = difflib.unified_diff(
        baseline_text.splitlines(keepends=True),
        candidate_text.splitlines(keepends=True),
        fromfile=baseline_name,
        tofile=candidate_name,
    )
    text = "".join(lines)
    (
        additions,
        modifications,
        removals,
        impacted_scopes,
        impacted_harnesses,
        impacted_artifact_families,
        conflict_warnings,
    ) = _semantic_policy_diff(baseline, candidate)
    (
        broadened_rules,
        narrowed_rules,
        unchanged_rules,
        effective_action_changes,
        broad_relaxing_changes,
    ) = _classify_rule_changes(baseline, candidate)
    return PolicyDocumentDiff(
        changed=bool(text),
        text=text,
        additions=additions,
        modifications=modifications,
        removals=removals,
        impacted_scopes=impacted_scopes,
        impacted_harnesses=impacted_harnesses,
        impacted_artifact_families=impacted_artifact_families,
        conflict_warnings=conflict_warnings,
        broadened_rules=broadened_rules,
        narrowed_rules=narrowed_rules,
        unchanged_rules=unchanged_rules,
        effective_action_changes=effective_action_changes,
        broad_relaxing_changes=broad_relaxing_changes,
    )


def _normalized_timestamp(value: object, *, rule_id: str) -> str:
    if isinstance(value, str):
        candidate = value.strip().replace("+00:00", "Z")
        if _UTC_TIMESTAMP_RE.fullmatch(candidate):
            return candidate
    raise PolicyCompilationError("invalid_local_policy_timestamp", rule_id)


def _normalized_expiry(value: object, *, rule_id: str, code: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise PolicyCompilationError(code, rule_id)
    candidate = value.strip().replace("+00:00", "Z")
    if not _UTC_TIMESTAMP_RE.fullmatch(candidate):
        raise PolicyCompilationError(code, rule_id)
    return candidate


def _stable_rule_id(row: Mapping[str, object]) -> str:
    policy_rule_id = row.get("policy_rule_id")
    if isinstance(policy_rule_id, str) and _IDENTIFIER_RE.fullmatch(policy_rule_id):
        return policy_rule_id
    decision_id = row.get("decision_id")
    if isinstance(decision_id, int) and not isinstance(decision_id, bool) and decision_id >= 0:
        return f"local-{decision_id}"
    encoded = json.dumps(dict(row), sort_keys=True, separators=(",", ":"), default=str).encode()
    return f"local-{hashlib.sha256(encoded).hexdigest()[:24]}"


def _provenance_source(value: object) -> str:
    if isinstance(value, str) and value in _PROVENANCE_SOURCES:
        return value
    if value == "cloud-sync":
        return "cloud"
    if value == _POLICY_IMPORT_SOURCE:
        return "import"
    return "local"


def _optional_string(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _rule_match_from_row(row: Mapping[str, object], *, include_provenance: bool) -> dict[str, object]:
    match: dict[str, object] = {}
    artifact_id = _optional_string(row.get("artifact_id"))
    harness = _optional_string(row.get("harness"))
    publisher = _optional_string(row.get("publisher"))
    workspace = _optional_string(row.get("workspace"))
    if artifact_id is not None:
        match["artifacts"] = [artifact_id]
    if harness is not None and harness != "*":
        match["harnesses"] = [harness]
    if publisher is not None:
        match["publishers"] = [publisher]
    if include_provenance and workspace is not None:
        match["workspaces"] = [workspace]
    return match


def _rule_from_policy_row(row: Mapping[str, object], *, include_provenance: bool) -> dict[str, object]:
    rule_id = _stable_rule_id(row)
    workspace = _optional_string(row.get("workspace"))
    if workspace is not None and not include_provenance:
        raise PolicyCompilationError("sensitive_local_policy_requires_provenance", rule_id)
    action = row.get("action")
    if action not in {"allow", "block"}:
        raise PolicyCompilationError("unsupported_local_policy_action", rule_id)
    expires_at = _normalized_expiry(
        row.get("expires_at"),
        rule_id=rule_id,
        code="invalid_local_policy_expiry",
    )
    provenance: dict[str, object] = {
        "source": _provenance_source(row.get("source")) if include_provenance else "export-redacted",
        "createdAt": _normalized_timestamp(row.get("updated_at"), rule_id=rule_id)
        if include_provenance
        else _REDACTED_TIMESTAMP,
    }
    owner = _optional_string(row.get("owner"))
    if include_provenance and owner is not None:
        provenance["createdBy"] = owner[:256]
    local_extension = {
        "artifactHash": row.get("artifact_hash"),
        "harness": row.get("harness"),
        "publisher": row.get("publisher"),
        "scope": row.get("scope"),
    }
    if include_provenance:
        local_extension.update(
            {
                "owner": row.get("owner"),
                "reason": row.get("reason"),
                "source": row.get("source"),
                "updatedAt": row.get("updated_at"),
                "workspace": row.get("workspace"),
            }
        )
    rule: dict[str, object] = {
        "id": rule_id,
        "enabled": True,
        "effect": action,
        "match": _rule_match_from_row(row, include_provenance=include_provenance),
        "lifetime": {
            "mode": "until" if expires_at is not None else "permanent",
            "expiresAt": expires_at,
        },
        "provenance": provenance,
        "x-hol-local": local_extension,
    }
    reason = _optional_string(row.get("reason"))
    if include_provenance and reason is not None:
        rule["description"] = reason[:4096]
    return rule


def _row_sort_decision_id(row: Mapping[str, object]) -> int:
    value = row.get("decision_id")
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def build_policy_document_from_rows(
    rows: Iterable[Mapping[str, object]],
    *,
    document_id: str = "local-policy",
    name: str = "Local Guard policy",
    revision: int = 0,
    include_provenance: bool = False,
) -> GuardPolicyDocument:
    """Build a deterministic portable document from local policy rows."""

    if not _IDENTIFIER_RE.fullmatch(document_id):
        raise ValueError("policy_document_id_invalid")
    ordered = sorted(
        (dict(row) for row in rows),
        key=lambda row: (
            _row_sort_decision_id(row),
            str(row.get("harness", "")),
            str(row.get("scope", "")),
            str(row.get("artifact_id", "")),
            json.dumps(row, sort_keys=True, separators=(",", ":"), default=str),
        ),
    )
    mapping: dict[str, object] = {
        "apiVersion": _POLICY_API_VERSION,
        "kind": _POLICY_KIND,
        "metadata": {"id": document_id, "name": name[:256], "revision": revision},
        "spec": {
            "defaults": {"mode": "prompt"},
            "rules": [_rule_from_policy_row(row, include_provenance=include_provenance) for row in ordered],
        },
    }
    return GuardPolicyDocument.from_mapping(mapping)


def _selector_values(
    match: Mapping[str, object],
    key: str,
    *,
    rule_id: str,
) -> tuple[str | None, ...]:
    value = match.get(key)
    if value is None:
        return (None,)
    if not isinstance(value, list) or not value:
        raise PolicyCompilationError("invalid_policy_match_selector", rule_id)
    items = cast(list[object], value)
    if not all(isinstance(item, str) and item for item in items):
        raise PolicyCompilationError("invalid_policy_match_selector", rule_id)
    return tuple(cast(list[str], items))


def _artifact_selector_values(
    match: Mapping[str, object],
    *,
    rule_id: str,
) -> tuple[str | None, ...]:
    artifacts = _selector_values(match, "artifacts", rule_id=rule_id)
    tools = _selector_values(match, "tools", rule_id=rule_id)
    if artifacts != (None,) and tools != (None,):
        raise PolicyCompilationError("unsupported_policy_match", rule_id)
    if tools == (None,):
        return artifacts
    families: list[str] = []
    for tool in tools:
        family = _TOOL_SELECTOR_FAMILIES.get(cast(str, tool).lower())
        if family is None:
            raise PolicyCompilationError("unsupported_policy_match", rule_id)
        families.append(f"family:{family}")
    return tuple(families)


def _local_scope(
    extension: Mapping[str, object],
    *,
    artifact_id: str | None,
    workspace: str | None,
    publisher: str | None,
    harness: str | None,
) -> DecisionScope:
    preferred = extension.get("scope")
    if isinstance(preferred, str) and preferred in _LOCAL_SCOPES:
        return cast(DecisionScope, preferred)
    if artifact_id is not None and artifact_id.startswith("family:"):
        return "workspace" if workspace is not None else "harness"
    if artifact_id is not None:
        return "artifact"
    if workspace is not None:
        return "workspace"
    if publisher is not None:
        return "publisher"
    if harness is not None:
        return "harness"
    return "global"


def compile_policy_document(document: GuardPolicyDocument) -> tuple[CompiledPolicyRow, ...]:
    """Compile the portable subset representable by the local policy store."""

    mapping = document.to_mapping()
    spec = mapping.get("spec")
    if not isinstance(spec, Mapping):
        raise PolicyCompilationError("invalid_policy_spec", document.metadata.id)
    rules = spec.get("rules")
    if not isinstance(rules, list):
        raise PolicyCompilationError("invalid_policy_rules", document.metadata.id)
    compiled: list[CompiledPolicyRow] = []
    for raw_rule in rules:
        if not isinstance(raw_rule, Mapping):
            raise PolicyCompilationError("invalid_policy_rule", document.metadata.id)
        rule_id = str(raw_rule.get("id", "unknown"))
        enabled = raw_rule.get("enabled")
        if not isinstance(enabled, bool):
            raise PolicyCompilationError("invalid_policy_enabled", rule_id)
        if not enabled:
            continue
        effect = raw_rule.get("effect")
        if effect not in {"allow", "block"}:
            raise PolicyCompilationError("unsupported_policy_effect", rule_id)
        lifetime = raw_rule.get("lifetime")
        if not isinstance(lifetime, Mapping) or lifetime.get("mode") not in {"permanent", "until"}:
            raise PolicyCompilationError("unsupported_policy_lifetime", rule_id)
        match = raw_rule.get("match")
        if not isinstance(match, Mapping):
            raise PolicyCompilationError("unsupported_policy_match", rule_id)
        unsupported = {
            key
            for key, value in match.items()
            if not str(key).startswith("x-") and key not in _SUPPORTED_MATCH_KEYS and value not in (None, [])
        }
        if unsupported:
            raise PolicyCompilationError("unsupported_policy_match", rule_id)
        local_extension = raw_rule.get("x-hol-local")
        extension = local_extension if isinstance(local_extension, Mapping) else {}
        selectors = itertools.product(
            _artifact_selector_values(match, rule_id=rule_id),
            _selector_values(match, "harnesses", rule_id=rule_id),
            _selector_values(match, "publishers", rule_id=rule_id),
            _selector_values(match, "workspaces", rule_id=rule_id),
        )
        provenance = raw_rule.get("provenance")
        provenance_mapping = provenance if isinstance(provenance, Mapping) else {}
        provenance_json = json.dumps(dict(provenance_mapping), sort_keys=True, separators=(",", ":"))
        expires_at = _normalized_expiry(
            lifetime.get("expiresAt") if lifetime.get("mode") == "until" else None,
            rule_id=rule_id,
            code="invalid_policy_expiry",
        )
        for artifact_id, harness, publisher, workspace in selectors:
            if len(compiled) >= _MAX_COMPILED_ROWS:
                raise PolicyCompilationError("policy_compilation_limit", rule_id)
            scope = _local_scope(
                extension,
                artifact_id=artifact_id,
                workspace=workspace,
                publisher=publisher,
                harness=harness,
            )
            compiled.append(
                CompiledPolicyRow(
                    decision=PolicyDecision(
                        harness=harness or "*",
                        scope=scope,
                        action=cast(GuardAction, effect),
                        artifact_id=artifact_id,
                        artifact_hash=_optional_string(extension.get("artifactHash")),
                        workspace=workspace,
                        publisher=publisher,
                        reason=_optional_string(raw_rule.get("description")),
                        owner=_optional_string(provenance_mapping.get("createdBy")),
                        source=_POLICY_IMPORT_SOURCE,
                        expires_at=_optional_string(expires_at),
                    ),
                    rule_id=rule_id,
                    provenance_json=provenance_json,
                )
            )
    return tuple(compiled)

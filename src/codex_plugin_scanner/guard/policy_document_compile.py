"""Adapters between canonical policy documents and local policy rows."""

from __future__ import annotations

import hashlib
import itertools
import json
import re
from collections.abc import Iterable, Mapping
from typing import Final, cast

from .models import DecisionScope, GuardAction, PolicyDecision
from .policy_document import GuardPolicyDocument
from .policy_document_types import CompiledPolicyRow, PolicyCompilationError

_POLICY_API_VERSION: Final = "guard.hashgraphonline.com/v1alpha1"
_POLICY_KIND: Final = "GuardPolicy"
_POLICY_IMPORT_SOURCE: Final = "policy-yaml-import"
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
    if tools != (None,) and "publishers" in match:
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
    if artifact_id is not None and artifact_id.startswith("family:"):
        return "workspace" if workspace is not None else "harness"
    preferred = extension.get("scope")
    if isinstance(preferred, str) and preferred in _LOCAL_SCOPES:
        return cast(DecisionScope, preferred)
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
        if isinstance(match.get("commands"), Mapping):
            raise PolicyCompilationError("command_expression_requires_guard_3_1_runtime", rule_id)
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

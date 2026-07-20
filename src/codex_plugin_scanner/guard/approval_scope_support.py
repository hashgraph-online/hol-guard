"""Derived approval-scope support for pending Guard review requests."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal

from .models import DECISION_SCOPE_VALUES, DecisionScope
from .package_execution_context import (
    PACKAGE_EXECUTION_CONTEXT_VERSION,
    PackageExecutionContext,
)

_SCOPED_APPROVAL_FAMILIES = frozenset(
    {
        "file-read",
        "mcp",
        "mcp-tool",
        "package-request",
        "prompt",
        "prompt-env-read",
        "prompt-file",
        "tool-action",
    }
)

APPROVAL_SCOPE_CONTRACT_VERSION: Final = "guard.approval-scopes.v2"
ResolutionAction = Literal["allow", "block"]


class StaleApprovalScopeContractError(ValueError):
    """Raised when a client resolves against a superseded scope contract."""

    def __init__(self, contract: ApprovalScopeContract) -> None:
        super().__init__("stale_scope_contract")
        self.contract = contract


class IneligibleApprovalScopeError(ValueError):
    """Raised when a V2 client selects a current but ineligible scope."""

    def __init__(
        self,
        message: str,
        contract: ApprovalScopeContract,
        *,
        action: str,
        requested_scope: str,
    ) -> None:
        super().__init__(message)
        self.contract = contract
        self.action = action
        self.requested_scope = requested_scope


@dataclass(frozen=True, slots=True)
class ApprovalScopeSelection:
    requested_scope: DecisionScope
    applied_scope: DecisionScope
    warning: str | None = None


@dataclass(frozen=True, slots=True)
class ApprovalScopeContract:
    allow_scopes: tuple[DecisionScope, ...]
    block_scopes: tuple[DecisionScope, ...]
    recommended_allow_scope: DecisionScope | None
    recommended_block_scope: DecisionScope | None
    restrictions: tuple[str, ...]
    digest: str
    task_capability_eligible: bool = False
    version: str = APPROVAL_SCOPE_CONTRACT_VERSION

    def to_dict(self) -> dict[str, object]:
        return {
            "scope_contract_version": self.version,
            "scope_contract_digest": self.digest,
            "allowed_scopes_by_action": {
                "allow": list(self.allow_scopes),
                "block": list(self.block_scopes),
            },
            "recommended_scope_by_action": {
                "allow": self.recommended_allow_scope,
                "block": self.recommended_block_scope,
            },
            "scope_restrictions": list(self.restrictions),
            "task_capability_eligibility": {
                "eligible": self.task_capability_eligible,
                "reason_codes": ["task_capability_not_enabled"],
            },
        }


def request_scope_contract(request: Mapping[str, object]) -> ApprovalScopeContract:
    """Derive the current action-aware scope contract from trusted request fields.

    This slice intentionally consumes no positive-proof assertion. Broad allow
    scopes stay unavailable until a later producer binds complete proof to the
    request. Deny breadth is limited to selectors Guard can derive canonically.
    """

    artifact_available = _string_or_none(request.get("artifact_id")) is not None
    artifact_scopes: tuple[DecisionScope, ...] = ("artifact",) if artifact_available else ()
    allow_scopes = () if _allow_is_non_overridable(request) else artifact_scopes
    block_scopes: list[DecisionScope] = list(artifact_scopes)
    trusted_family = _request_scoped_family_key(request)
    if trusted_family is not None:
        if _derived_workspace_scope_target(request) is not None:
            block_scopes.append("workspace")
        if _string_or_none(request.get("publisher")) is not None:
            block_scopes.append("publisher")
        block_scopes.extend(("harness", "global"))
    restrictions = ["broad_allow_requires_positive_proof", "task_capability_not_enabled"]
    if _allow_is_non_overridable(request):
        restrictions.append("current_action_not_overridable")
    if _derived_workspace_scope_target(request) is not None:
        restrictions.append("workspace_allow_requires_complete_proof")
    if trusted_family is not None:
        restrictions.append("harness_and_global_allow_unavailable")
    else:
        restrictions.append("broad_deny_requires_trusted_selector")
    block_scope_tuple = tuple(block_scopes)
    restrictions_tuple = tuple(restrictions)
    digest = _scope_contract_digest(
        request,
        allow_scopes=allow_scopes,
        block_scopes=block_scope_tuple,
        restrictions=restrictions_tuple,
    )
    return ApprovalScopeContract(
        allow_scopes=allow_scopes,
        block_scopes=block_scope_tuple,
        recommended_allow_scope="artifact" if "artifact" in allow_scopes else None,
        recommended_block_scope="artifact" if "artifact" in block_scopes else None,
        restrictions=restrictions_tuple,
        digest=digest,
    )


def request_scope_contract_payload(request: Mapping[str, object]) -> dict[str, object]:
    return request_scope_contract(request).to_dict()


def resolve_request_scope_selection(
    request: Mapping[str, object],
    *,
    action: str,
    requested_scope: str,
    contract_version: str | None,
    contract_digest: str | None,
) -> ApprovalScopeSelection:
    if action not in {"allow", "block"}:
        raise ValueError("unsupported_resolution_action")
    if requested_scope not in DECISION_SCOPE_VALUES:
        raise ValueError(f"Unsupported approval scope: {requested_scope}")
    typed_scope = _decision_scope(requested_scope)
    contract = request_scope_contract(request)
    if (contract_version is None) != (contract_digest is None):
        raise ValueError("incomplete_scope_contract")
    if contract_version is not None and (
        contract_version != APPROVAL_SCOPE_CONTRACT_VERSION or contract_digest != contract.digest
    ):
        raise StaleApprovalScopeContractError(contract)
    eligible = contract.allow_scopes if action == "allow" else contract.block_scopes
    if typed_scope in eligible:
        return ApprovalScopeSelection(typed_scope, typed_scope)
    if contract_version is not None or action == "block":
        raise IneligibleApprovalScopeError(
            "ineligible_request_scope",
            contract,
            action=action,
            requested_scope=requested_scope,
        )
    if "artifact" not in eligible:
        raise IneligibleApprovalScopeError(
            "request_action_not_overridable",
            contract,
            action=action,
            requested_scope=requested_scope,
        )
    return ApprovalScopeSelection(
        requested_scope=typed_scope,
        applied_scope="artifact",
        warning="legacy_scope_narrowed_to_artifact",
    )


def supported_request_scopes(request: Mapping[str, object]) -> tuple[DecisionScope, ...]:
    """Return legacy UI scopes, conservatively projected from V2 allow scopes."""

    return request_scope_contract(request).allow_scopes


def resolve_request_workspace_scope(
    request: Mapping[str, object],
    selected_workspace: str | None,
) -> str:
    workspace = _derived_workspace_scope_target(request)
    if workspace is None:
        raise ValueError("workspace_scope_unavailable")
    bound_selected = _string_or_none(selected_workspace)
    if bound_selected is not None and _normalized_workspace_path(bound_selected) != _normalized_workspace_path(
        workspace
    ):
        raise ValueError("workspace_scope_mismatch")
    return workspace


def package_request_portable_workspace_scope(
    *,
    artifact_id: str | None,
    artifact_hash: str | None,
    artifact_type: str | None = None,
    execution_context: PackageExecutionContext | None = None,
) -> str | None:
    if not _is_package_request_artifact(artifact_id=artifact_id, artifact_type=artifact_type):
        return None
    if artifact_hash is None or not artifact_hash.strip() or artifact_hash == "unknown":
        return None
    if execution_context is None or not execution_context.portable:
        return None
    if execution_context.version != PACKAGE_EXECUTION_CONTEXT_VERSION:
        return None
    material = {
        "artifact_hash": artifact_hash.strip(),
        "artifact_id": artifact_id.strip() if artifact_id is not None else None,
        "execution_context": execution_context.digest,
        "scope": "package-request-workspace",
        "version": PACKAGE_EXECUTION_CONTEXT_VERSION,
    }
    digest = hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    return f"package-request-workspace:v{PACKAGE_EXECUTION_CONTEXT_VERSION}:{digest}"


def package_request_runtime_workspace_scope(
    *,
    artifact_id: str | None,
    artifact_hash: str | None,
    artifact_type: str | None = None,
    execution_context: PackageExecutionContext | None,
) -> str | None:
    """Return the only workspace identity valid for a package-policy lookup.

    Non-portable contexts receive an exact, context-bound sentinel.  It keeps
    artifact-once decisions functional while ensuring legacy path-only and v1
    workspace approvals cannot match.
    """

    if not _is_package_request_artifact(artifact_id=artifact_id, artifact_type=artifact_type):
        return None
    if artifact_hash is None or not artifact_hash.strip() or artifact_hash == "unknown":
        return None
    portable = package_request_portable_workspace_scope(
        artifact_id=artifact_id,
        artifact_hash=artifact_hash,
        artifact_type=artifact_type,
        execution_context=execution_context,
    )
    if portable is not None:
        return portable
    if execution_context is None or execution_context.version != PACKAGE_EXECUTION_CONTEXT_VERSION:
        return None
    material = {
        "artifact_hash": artifact_hash.strip(),
        "artifact_id": artifact_id.strip() if artifact_id is not None else None,
        "execution_context": execution_context.digest,
        "scope": "package-request-workspace-exact",
        "version": PACKAGE_EXECUTION_CONTEXT_VERSION,
    }
    digest = hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    return f"package-request-workspace-exact:v{PACKAGE_EXECUTION_CONTEXT_VERSION}:{digest}"


def _derived_workspace_scope_target(request: Mapping[str, object]) -> str | None:
    stored_workspace = _string_or_none(request.get("workspace"))
    if stored_workspace is not None:
        return stored_workspace
    config_path = _string_or_none(request.get("config_path"))
    if config_path is None:
        return None
    try:
        config_file = Path(config_path).resolve()
    except Exception:
        config_file = Path(config_path)
    parent = config_file.parent
    workspace_root = parent.parent if parent.name.startswith(".") else parent
    return str(workspace_root)


def _is_package_request_artifact(*, artifact_id: str | None, artifact_type: str | None) -> bool:
    if artifact_type == "package_request":
        return True
    return isinstance(artifact_id, str) and ":package-request:" in artifact_id


def _request_scoped_family_key(request: Mapping[str, object]) -> str | None:
    family_key = _artifact_family_key(_string_or_none(request.get("artifact_id")))
    artifact_type = _string_or_none(request.get("artifact_type"))
    if family_key is None or artifact_type is None:
        return None
    expected_families = {
        "file_read_request": frozenset({"file-read"}),
        "mcp_server": frozenset({"mcp", "mcp-tool"}),
        "mcp_tool_call": frozenset({"mcp", "mcp-tool"}),
        "package_request": frozenset({"package-request"}),
        "prompt_request": frozenset({"prompt", "prompt-env-read", "prompt-file"}),
        "tool_action_request": frozenset({"tool-action"}),
    }.get(artifact_type)
    family = family_key.removeprefix("family:")
    return family_key if expected_families is not None and family in expected_families else None


def _scope_contract_digest(
    request: Mapping[str, object],
    *,
    allow_scopes: tuple[DecisionScope, ...],
    block_scopes: tuple[DecisionScope, ...],
    restrictions: tuple[str, ...],
) -> str:
    material = {
        "version": APPROVAL_SCOPE_CONTRACT_VERSION,
        "allow_scopes": allow_scopes,
        "block_scopes": block_scopes,
        "restrictions": restrictions,
        "request": {
            key: _json_boundary_value(request.get(key))
            for key in (
                "harness",
                "artifact_id",
                "artifact_type",
                "artifact_hash",
                "policy_action",
                "publisher",
                "source_scope",
                "config_path",
                "workspace",
                "launch_target",
                "normalized_identity_key",
                "action_identity",
                "queue_group_id",
                "transport",
                "changed_fields",
                "action_envelope_json",
                "scanner_evidence",
                "raw_command_text",
            )
        },
    }
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _json_boundary_value(value: object) -> object:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, Mapping):
        return {
            str(key): _json_boundary_value(item) for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, (list, tuple)):
        return [_json_boundary_value(item) for item in value]
    return {"invalid_type": type(value).__name__}


def _allow_is_non_overridable(request: Mapping[str, object]) -> bool:
    if _string_or_none(request.get("policy_action")) == "block":
        return True
    envelope = request.get("action_envelope_json")
    if not isinstance(envelope, Mapping):
        return False
    action_type = _string_or_none(envelope.get("action_type"))
    return action_type in {
        "guard_control",
        "guard-control",
        "guard_control_operation",
        "guard-control-operation",
    }


def _decision_scope(value: str) -> DecisionScope:
    if value == "global":
        return "global"
    if value == "harness":
        return "harness"
    if value == "workspace":
        return "workspace"
    if value == "publisher":
        return "publisher"
    return "artifact"


def _artifact_family_key(artifact_id: str | None) -> str | None:
    if artifact_id is None or not artifact_id.strip():
        return None
    if artifact_id.startswith("family:"):
        family = artifact_id.removeprefix("family:").strip().lower()
        return f"family:{family}" if family in _SCOPED_APPROVAL_FAMILIES else None
    parts = artifact_id.split(":")
    if len(parts) < 3:
        return None
    family = parts[2].strip().lower()
    if family not in _SCOPED_APPROVAL_FAMILIES:
        return None
    return f"family:{family}"


def _string_or_none(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value
    return None


def _normalized_workspace_path(value: str) -> str:
    try:
        resolved = str(Path(value).resolve())
    except Exception:
        resolved = value
    normalized = resolved.strip().replace("\\", "/")
    while len(normalized) > 1 and normalized.endswith("/"):
        normalized = normalized[:-1]
    if len(normalized) >= 2 and normalized[1] == ":":
        normalized = normalized.lower()
    return normalized

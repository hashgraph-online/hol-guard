"""Derived approval-scope support for pending Guard review requests."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal, cast

from .models import DECISION_SCOPE_VALUES, DecisionScope
from .package_execution_context import PACKAGE_EXECUTION_CONTEXT_VERSION, PackageExecutionContext
from .temporary_mcp_approvals import temporary_mcp_approval_payload
from .trusted_local_tools import local_tool_approval_payload

APPROVAL_SCOPE_CONTRACT_VERSION_PREFIX: Final = "guard.approval-scopes.v"
APPROVAL_SCOPE_CONTRACT_VERSION: Final = f"{APPROVAL_SCOPE_CONTRACT_VERSION_PREFIX}7"
ResolutionAction = Literal["allow", "block"]


class StaleApprovalScopeContractError(ValueError):
    """Raised when a client resolves against a superseded scope contract."""

    contract: ApprovalScopeContract

    def __init__(self, contract: ApprovalScopeContract) -> None:
        super().__init__("stale_scope_contract")
        self.contract = contract


class IneligibleApprovalScopeError(ValueError):
    """Raised when a V2 client selects a current but ineligible scope."""

    contract: ApprovalScopeContract
    action: ResolutionAction
    requested_scope: str

    def __init__(
        self,
        message: str,
        contract: ApprovalScopeContract,
        *,
        action: ResolutionAction,
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
    task_capability_reason_codes: tuple[str, ...] = ("task_capability_not_enabled",)
    exact_action_persistence_eligible: bool = False
    once_only_reason: str | None = None
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
                "reason_codes": list(self.task_capability_reason_codes),
            },
            "exact_action_persistence_eligible": self.exact_action_persistence_eligible,
            "once_only_reason": self.once_only_reason,
        }


def _native_scopes(requests: Sequence[Mapping[str, object]]) -> list[tuple[ApprovalScopeContract, str | None]]:
    # Imported here: the resident transport pulls in the native runtime, which
    # hook hot paths that only need the package scope helpers must not load.
    from .native_approval_scope import REQUEST_FIELDS, ApprovalScopeUnavailableError, native_approval_scopes

    items: list[Mapping[str, object]] = []
    for request in requests:
        item: dict[str, object] = {field: _json_boundary_value(request.get(field)) for field in REQUEST_FIELDS}
        item["workspace_target"] = _derived_workspace_scope_target(request)
        items.append(item)
    contracts: list[tuple[ApprovalScopeContract, str | None]] = []
    for native in native_approval_scopes(items):
        contract = _contract_from_native(native.contract)
        if contract is None:
            raise ApprovalScopeUnavailableError
        contracts.append((contract, native.exact_context_token))
    return contracts


def _scope_tuple(value: object) -> tuple[DecisionScope, ...] | None:
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item in DECISION_SCOPE_VALUES for item in value
    ):
        return None
    return tuple(_decision_scope(item) for item in cast(list[str], value))


def _string_tuple(value: object) -> tuple[str, ...] | None:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        return None
    return tuple(cast(list[str], value))


def _contract_from_native(payload: Mapping[str, object]) -> ApprovalScopeContract | None:
    allowed = payload.get("allowed_scopes_by_action")
    recommended = payload.get("recommended_scope_by_action")
    task = payload.get("task_capability_eligibility")
    if not isinstance(allowed, dict) or not isinstance(recommended, dict) or not isinstance(task, dict):
        return None
    allow_scopes = _scope_tuple(allowed.get("allow"))
    block_scopes = _scope_tuple(allowed.get("block"))
    restrictions = _string_tuple(payload.get("scope_restrictions"))
    reason_codes = _string_tuple(task.get("reason_codes"))
    recommended_allow = recommended.get("allow")
    recommended_block = recommended.get("block")
    recommended_scopes = (recommended_allow, recommended_block)
    digest = payload.get("scope_contract_digest")
    once_only = payload.get("once_only_reason")
    eligible = task.get("eligible")
    persistence = payload.get("exact_action_persistence_eligible")
    if (
        allow_scopes is None
        or block_scopes is None
        or restrictions is None
        or reason_codes is None
        or payload.get("scope_contract_version") != APPROVAL_SCOPE_CONTRACT_VERSION
        or not isinstance(digest, str)
        or not digest
        or not isinstance(eligible, bool)
        or not isinstance(persistence, bool)
        or (once_only is not None and not isinstance(once_only, str))
        or any(item is not None and item not in DECISION_SCOPE_VALUES for item in recommended_scopes)
    ):
        return None
    return ApprovalScopeContract(
        allow_scopes=allow_scopes,
        block_scopes=block_scopes,
        recommended_allow_scope=_decision_scope(recommended_allow) if isinstance(recommended_allow, str) else None,
        recommended_block_scope=_decision_scope(recommended_block) if isinstance(recommended_block, str) else None,
        restrictions=restrictions,
        digest=digest,
        task_capability_eligible=eligible,
        task_capability_reason_codes=reason_codes,
        exact_action_persistence_eligible=persistence,
        once_only_reason=once_only,
    )


def request_scope_contracts(requests: Sequence[Mapping[str, object]]) -> list[ApprovalScopeContract]:
    """Derive the current action-aware scope contract of each request in the resident.

    Reusable allow scopes are exposed only when Guard can persist an
    action-bound selector. The wider scope changes where that same action may
    be reused; it never turns into blanket permission for unrelated actions.
    Raises ``ApprovalScopeUnavailableError`` when the resident cannot answer.
    """

    return [contract for contract, _token in _native_scopes(requests)]


def request_scope_contract(request: Mapping[str, object]) -> ApprovalScopeContract:
    return request_scope_contracts([request])[0]


def scope_payload_for_request(request: Mapping[str, object], contract: ApprovalScopeContract) -> dict[str, object]:
    """Attach non-resident approval hints to a contract already derived."""

    payload = contract.to_dict()
    temporary_mcp_approval = temporary_mcp_approval_payload(request)
    if temporary_mcp_approval is not None:
        payload["temporary_mcp_approval"] = temporary_mcp_approval
    local_tool_approval = local_tool_approval_payload(request)
    if local_tool_approval is not None:
        payload["local_tool_approval"] = local_tool_approval
    return payload


def apply_scope_surfaces(payload: dict[str, object]) -> None:
    """Project a payload's derived contract onto the legacy UI fields.

    The stored advertisement in ``decision_v2_json`` is untrusted, so the
    contract the resident derived always replaces it.
    """

    from .native_approval_scope import ApprovalScopeUnavailableError

    allowed = payload["allowed_scopes_by_action"]
    recommended = payload["recommended_scope_by_action"]
    if not isinstance(allowed, dict) or not isinstance(recommended, dict):
        raise ApprovalScopeUnavailableError
    payload["allowed_scopes"] = list(cast(list[str], allowed["allow"]))
    payload["recommended_scope"] = recommended.get("allow")
    decision_v2 = payload.get("decision_v2_json")
    if isinstance(decision_v2, dict):
        payload["decision_v2_json"] = {
            **decision_v2,
            "approval_scopes": list(cast(list[str], payload["allowed_scopes"])),
        }


def request_scope_contract_payloads(requests: Sequence[Mapping[str, object]]) -> list[dict[str, object]]:
    payloads: list[dict[str, object]] = []
    for request, contract in zip(requests, request_scope_contracts(requests), strict=True):
        payloads.append(scope_payload_for_request(request, contract))
    return payloads


def request_scope_contract_payload(request: Mapping[str, object]) -> dict[str, object]:
    return request_scope_contract_payloads([request])[0]


def request_scope_observation(
    request: Mapping[str, object],
) -> tuple[ApprovalScopeContract, str | None]:
    """Derive one request's contract and exact-action token in one resident call."""

    return _native_scopes([request])[0]


def tool_call_exact_context_token(request: Mapping[str, object]) -> str | None:
    """Return the exact-action token bound to a tool-call approval row.

    Generic hook rows carry the token as their artifact hash. Daemon native
    rows keep the once-only native binding there and carry the persistent
    token in their action envelope.
    """

    return _native_scopes([request])[0][1]


def exact_action_allow_persistence_eligible(request: Mapping[str, object]) -> bool:
    """Return whether an artifact allow can be saved as one exact action."""

    return request_scope_contract(request).exact_action_persistence_eligible


def resolve_request_scope_selection(
    request: Mapping[str, object],
    *,
    action: str,
    requested_scope: str,
    contract_version: str | None,
    contract_digest: str | None,
    contract: ApprovalScopeContract | None = None,
) -> ApprovalScopeSelection:
    if action == "allow":
        resolution_action: ResolutionAction = "allow"
    elif action == "block":
        resolution_action = "block"
    else:
        raise ValueError("unsupported_resolution_action")
    if requested_scope not in DECISION_SCOPE_VALUES:
        raise ValueError(f"Unsupported approval scope: {requested_scope}")
    typed_scope = _decision_scope(requested_scope)
    if contract is None:
        contract = request_scope_contract(request)
    if (contract_version is None) != (contract_digest is None):
        raise ValueError("incomplete_scope_contract")
    if contract_version is not None and (
        contract_version != APPROVAL_SCOPE_CONTRACT_VERSION or contract_digest != contract.digest
    ):
        raise StaleApprovalScopeContractError(contract)
    eligible = contract.allow_scopes if resolution_action == "allow" else contract.block_scopes
    if typed_scope in eligible:
        return ApprovalScopeSelection(typed_scope, typed_scope)
    if contract_version is not None or action == "block":
        raise IneligibleApprovalScopeError(
            "ineligible_request_scope",
            contract,
            action=resolution_action,
            requested_scope=requested_scope,
        )
    if "artifact" not in eligible:
        raise IneligibleApprovalScopeError(
            "request_action_not_overridable",
            contract,
            action=resolution_action,
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


def _json_boundary_value(value: object) -> object:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, Mapping):
        mapping = cast(Mapping[object, object], value)
        return {
            str(key): _json_boundary_value(item) for key, item in sorted(mapping.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, (list, tuple)):
        return [_json_boundary_value(item) for item in cast(Sequence[object], value)]
    return {"invalid_type": type(value).__name__}


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


def _string_or_none(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value
    return None


def _normalized_workspace_path(value: str) -> str:
    try:
        # codeql[py/path-injection] This only canonicalizes an approval-scope identity; it does not access content.
        resolved = str(Path(value).resolve())
    except Exception:
        resolved = value
    normalized = resolved.strip().replace("\\", "/")
    while len(normalized) > 1 and normalized.endswith("/"):
        normalized = normalized[:-1]
    if len(normalized) >= 2 and normalized[1] == ":":
        normalized = normalized.lower()
    return normalized

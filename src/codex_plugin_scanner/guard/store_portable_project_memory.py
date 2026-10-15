"""GuardStore compatibility layer for portable project-scoped memory."""

# pyright: reportAttributeAccessIssue=false

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .action_lattice import guard_action_severity
from .project_identity import (
    enrich_project_identity_metadata,
    is_portable_project_identity,
    portable_project_identity_revision,
    resolve_portable_project_identity,
)
from .store_base import PolicyDecisionLookupResult
from .store_policy import _DEGRADED_AUTHORITY_REVISION, _most_restrictive_policy_lookup, memory_lookup_candidates

_PROJECT_IDENTITY_CACHE_MAX_ITEMS = 128
_PROJECT_IDENTITY_CACHE: dict[tuple[str, int], str] = {}
_PORTABLE_PERMISSION_FLOOR = guard_action_severity("review")


def _cached_portable_project_identity(workspace: str) -> str | None:
    """Cache only successful identities and invalidate on any identity metadata change."""
    revision = portable_project_identity_revision(workspace)
    if revision is None:
        return resolve_portable_project_identity(workspace)
    cache_key = (workspace, revision)
    cached = _PROJECT_IDENTITY_CACHE.get(cache_key)
    if cached is not None:
        return cached

    identity = resolve_portable_project_identity(workspace)
    if identity is None:
        return None

    stale_keys = [key for key in _PROJECT_IDENTITY_CACHE if key[0] == workspace]
    for stale_key in stale_keys:
        _PROJECT_IDENTITY_CACHE.pop(stale_key, None)
    if len(_PROJECT_IDENTITY_CACHE) >= _PROJECT_IDENTITY_CACHE_MAX_ITEMS:
        oldest_key = next(iter(_PROJECT_IDENTITY_CACHE))
        _PROJECT_IDENTITY_CACHE.pop(oldest_key, None)
    _PROJECT_IDENTITY_CACHE[cache_key] = identity
    return identity


def _text(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _portable_lookup_without_permission_elevation(
    lookup: PolicyDecisionLookupResult,
) -> PolicyDecisionLookupResult:
    """Keep portable selectors restrictive-only and never reuse one-shot authority.

    Git metadata lives inside the workspace and can be forged by that
    workspace. A portable selector is therefore useful for carrying managed
    restrictions across clones, but it cannot safely prove that a permissive
    approval belongs to the current local workspace. Local-path authority is
    the only source allowed to lower enforcement below review.
    """
    decision = lookup.get("decision")
    if not isinstance(decision, dict):
        return lookup
    approval_id = decision.get("approval_id")
    action_severity = guard_action_severity(decision.get("action"), unknown_action="block")
    if approval_id is not None or action_severity < _PORTABLE_PERMISSION_FLOOR:
        return {**lookup, "decision": None}
    return lookup


def _without_authority_revision(lookup: PolicyDecisionLookupResult) -> PolicyDecisionLookupResult:
    """Remove the preview-only authority revision from an enforcement result."""
    decision = lookup.get("decision")
    if not isinstance(decision, dict) or "_approval_authority_revision" not in decision:
        return lookup
    sanitized_decision = dict(decision)
    sanitized_decision.pop("_approval_authority_revision", None)
    return {**lookup, "decision": sanitized_decision}


def _restrictive_only_lookup(lookup: PolicyDecisionLookupResult) -> PolicyDecisionLookupResult:
    """Fail closed after a saved allow cannot be atomically claimed."""
    decision = lookup.get("decision")
    sanitized = _without_authority_revision(lookup)
    if not isinstance(decision, dict):
        return sanitized
    if guard_action_severity(decision.get("action"), unknown_action="block") >= _PORTABLE_PERMISSION_FLOOR:
        return sanitized
    return {**sanitized, "decision": None}


# Store mixins are composed dynamically in ``GuardStore``. Sibling mixins use
# the same file-level pyright setting because ``super()`` members are supplied
# by the final MRO rather than a direct base class.
class StorePortableProjectMemoryMixin:
    """Add restrictive portable Git project policy without weakening local scope."""

    def get_guard_operation_for_approval_request(self, request_id: str) -> dict[str, object] | None:
        operation = super().get_guard_operation_for_approval_request(request_id)
        if not isinstance(operation, dict):
            return operation
        metadata = operation.get("metadata")
        if not isinstance(metadata, Mapping):
            return operation
        return {
            **operation,
            "metadata": enrich_project_identity_metadata(metadata),
        }

    def peek_saved_decision_groups(
        self,
        harness: str,
        probes: Sequence[tuple[str, str | None]],
        *,
        workspace: str | None,
        publisher: str | None,
        runtime_exact_match_context: str | None,
        memory_command: str | None,
        memory_artifact_type: str | None,
        memory_artifact_name: str | None,
        current_action: str,
        approval_context_inputs: Mapping[str, object],
    ) -> dict[str, Any] | None:
        """Peek saved decisions for several ``(artifact_id, artifact_hash)`` probes in one resident call.

        Each probe composes its direct, exact-command and memory ids most
        restrictive (with the portable Git workspace); across probes a strictly
        more severe decision wins. Nothing is consumed. The first probe names
        the current action: the resident also checks a saved allow's context
        token against its hash, explains a miss, and composes the reuse verdict
        for ``current_action``. Returns ``decision``, ``ignored_local_integrity``,
        ``reuse`` (the verdict payload), ``saved_present`` and
        ``saved_artifact_hash``. ``None`` means the home serves no saved
        authority, so there is no saved decision to compose.
        """
        evidence = self.policy_lookup_evidence()
        if evidence.degraded_trust_status is not None:
            return None
        groups: list[dict[str, object]] = []
        for artifact_id, artifact_hash in probes:
            exact_ids, memory_id = memory_lookup_candidates(
                harness,
                artifact_id,
                memory_command=memory_command,
                memory_artifact_type=memory_artifact_type,
                memory_artifact_name=memory_artifact_name,
                guard_home=Path(self.guard_home),
            )
            groups.append(
                {
                    "artifact_hash": artifact_hash,
                    "candidate_artifact_ids": [artifact_id, *exact_ids, *([memory_id] if memory_id else [])],
                }
            )
        request = self.policy_decision_lookup_request(
            evidence,
            harness=harness,
            artifact_id=probes[0][0],
            artifact_hash=None,
            workspace=workspace,
            publisher=publisher,
            runtime_exact_match_context=runtime_exact_match_context,
            consume_one_shot=False,
        )
        request["probe_groups"] = {
            "portable_workspace": self._portable_project_workspace(workspace),
            "groups": groups,
            "reuse": {"current_action": current_action, "approval_context_inputs": dict(approval_context_inputs)},
        }
        return self.send_policy_decision_lookup(request)

    def resolve_runtime_saved_decision(
        self,
        current: Mapping[str, object],
        legacy: Mapping[str, object],
        alias: Mapping[str, object] | None,
    ) -> tuple[PolicyDecisionLookupResult, dict[str, Any] | None]:
        """Resolve a runtime hook evaluation's saved decision in one resident call.

        ``current`` and ``legacy`` probe the request hash and the legacy content
        hash with their exact-command and memory candidates; ``alias`` probes
        the Claude alias of a legacy ``claude-code:`` artifact when neither
        matched. Nothing is consumed. Returns the lookup carrying the trust and
        integrity evidence, and the decision this artifact may use.
        """
        evidence = self.policy_lookup_evidence()
        if evidence.degraded_trust_status is not None:
            degraded: PolicyDecisionLookupResult = {
                "decision": None,
                "ignored_local_integrity": None,
                "trust_status": evidence.degraded_trust_status,
                "authority_revision": _DEGRADED_AUTHORITY_REVISION,
            }
            return degraded, None
        probes = {"current": current, "legacy": legacy, **({"alias": alias} if alias is not None else {})}
        runtime = {
            name: {**probe, "portable_workspace": self._portable_project_workspace(_text(probe.get("workspace")))}
            for name, probe in probes.items()
        }
        request = self.policy_decision_lookup_request(
            evidence,
            harness=str(current["harness"]),
            artifact_id=_text(current.get("artifact_id")),
            artifact_hash=_text(current.get("artifact_hash")),
            workspace=_text(current.get("workspace")),
            publisher=_text(current.get("publisher")),
            runtime_exact_match_context=_text(current.get("exact_match_context")),
            consume_one_shot=False,
        )
        request["probe_groups"] = {"groups": [], "runtime": runtime}
        payload = self.send_policy_decision_lookup(request)
        return payload["lookup"], payload["decision"]

    def mcp_policy_lookup_input(
        self,
        harness: str,
        artifact_id: str,
        *,
        workspace: str | None,
        memory_command: str | None,
        memory_artifact_type: str | None,
        memory_artifact_name: str | None,
    ) -> dict[str, object]:
        """Ship the keyring-facing evidence once so the resident can read saved policy itself.

        The resident runs the same non-consuming probes this class composes in
        ``resolve_policy_decision_lookup`` (direct, exact-command and memory ids,
        portable Git workspace, most restrictive wins) over one store connection.
        """
        evidence = self.policy_lookup_evidence()
        exact_ids, memory_id = memory_lookup_candidates(
            harness,
            artifact_id,
            memory_command=memory_command,
            memory_artifact_type=memory_artifact_type,
            memory_artifact_name=memory_artifact_name,
            guard_home=Path(self.guard_home),
        )
        lookup: dict[str, object] = {
            "store_path": str(self.path),
            "guard_home": str(self.guard_home),
            "now": evidence.now,
            "candidate_artifact_ids": [artifact_id, *exact_ids, *([memory_id] if memory_id else [])],
            "portable_workspace": self._portable_project_workspace(workspace),
            "integrity_state": evidence.integrity_state,
            "integrity_key_b64": evidence.integrity_key_b64,
            "integrity_key_id": evidence.integrity_key_id,
            "local_once_integrity_key_b64": evidence.local_once_integrity_key_b64,
            "local_once_integrity_key_id": evidence.local_once_integrity_key_id,
            "policy_bundle_decision_identities": evidence.policy_bundle_decision_identities,
            "degraded_trust_status": evidence.degraded_trust_status,
            "diagnostic_empty": not evidence.has_saved_rows,
        }
        return lookup

    def resolve_policy_decision_lookup(
        self,
        harness: str,
        artifact_id: str | None,
        artifact_hash: str | None = None,
        workspace: str | None = None,
        publisher: str | None = None,
        now: str | None = None,
        runtime_exact_match_context: str | None = None,
        consume_one_shot: bool = True,
        local_once_only: bool = False,
    ) -> PolicyDecisionLookupResult:
        portable_workspace = None if local_once_only else self._portable_project_workspace(workspace)
        if portable_workspace is None:
            return super().resolve_policy_decision_lookup(
                harness,
                artifact_id,
                artifact_hash=artifact_hash,
                workspace=workspace,
                publisher=publisher,
                now=now,
                runtime_exact_match_context=runtime_exact_match_context,
                consume_one_shot=consume_one_shot,
                local_once_only=local_once_only,
            )

        # Portable Git metadata is classification, not authentication. Always
        # inspect portable authority without consuming it, then discard any
        # one-shot or permission-lowering decision before composition. This
        # prevents a forged repository identity from inheriting an allow/warn
        # or burning reusable one-shot authority belonging to another clone.
        portable_preview = _portable_lookup_without_permission_elevation(
            super().resolve_policy_decision_lookup(
                harness,
                artifact_id,
                artifact_hash=artifact_hash,
                workspace=portable_workspace,
                publisher=publisher,
                now=now,
                runtime_exact_match_context=runtime_exact_match_context,
                consume_one_shot=False,
            )
        )
        normalized_workspace = workspace.strip() if isinstance(workspace, str) else None
        if portable_workspace == normalized_workspace:
            return portable_preview if not consume_one_shot else _without_authority_revision(portable_preview)

        # Preview local authority as well. A local one-shot must not be claimed
        # before a stronger portable restriction has had a chance to win.
        local_preview = super().resolve_policy_decision_lookup(
            harness,
            artifact_id,
            artifact_hash=artifact_hash,
            workspace=workspace,
            publisher=publisher,
            now=now,
            runtime_exact_match_context=runtime_exact_match_context,
            consume_one_shot=False,
        )
        effective_preview = _most_restrictive_policy_lookup([local_preview, portable_preview])
        if not consume_one_shot:
            return effective_preview

        effective_decision = effective_preview.get("decision")
        if not isinstance(effective_decision, dict) or effective_decision.get("action") != "allow":
            return _without_authority_revision(effective_preview)

        # Portable permission-lowering decisions were removed above, so any
        # effective allow came from local authority. Claim that exact preview
        # atomically. The embedded authority revision prevents a stale allow
        # from surviving a concurrent policy or approval change.
        if self.claim_approval_reuse_decision(effective_decision, now=now):
            return _without_authority_revision(effective_preview)

        # Authority changed between preview and claim. Recompute without
        # consuming anything and retain only restrictive policy; a permission
        # can be presented again on the caller's next approval cycle.
        refreshed = self.resolve_policy_decision_lookup(
            harness,
            artifact_id,
            artifact_hash=artifact_hash,
            workspace=workspace,
            publisher=publisher,
            now=now,
            runtime_exact_match_context=runtime_exact_match_context,
            consume_one_shot=False,
        )
        return _restrictive_only_lookup(refreshed)

    @staticmethod
    def _portable_project_workspace(workspace: str | None) -> str | None:
        if not isinstance(workspace, str) or not workspace.strip():
            return None
        normalized = workspace.strip()
        return normalized if is_portable_project_identity(normalized) else _cached_portable_project_identity(normalized)

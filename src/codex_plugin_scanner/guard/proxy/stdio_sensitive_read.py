"""Sensitive local file reads seen by the stdio MCP proxy.

The resident owns every verdict, token and message of a sensitive-read request
(``native_mcp_sensitive_read``). This module gathers the facts the resident
asks about, performs the store effects between its answers (policy lookup,
atomic claim, configuration refresh, receipt, approval queue) and relays the
answer. It never recomputes or overrides a verdict; if the resident cannot
answer the read is not forwarded.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .. import approvals as approvals_module
from ..approvals import (
    approval_delivery_payload,
    approval_prompt_flow,
    first_approval_url,
    queue_blocked_approvals,
)
from ..blocked_request_mode import asks_for_approval, safe_alternative_reason
from ..config import GuardConfig
from ..models import GuardArtifact, HarnessDetection
from ..native_context import _resolve_digest_home
from ..native_mcp_proxy_decision import NativeMcpProxyDecisionError
from ..native_mcp_sensitive_read import (
    lookup_facts,
    sensitive_read_context,
    sensitive_read_hint,
    sensitive_read_reuse,
)
from ..receipts import build_receipt
from ..runtime.secret_file_request_services.request_models import FileReadRequestMatch
from ..runtime.secret_file_requests import build_file_read_request_artifact, extract_sensitive_file_read_request

if TYPE_CHECKING:
    from .stdio import StdioGuardProxy

NotForwarded = tuple[str, dict[str, Any]]


def _artifact(proxy: StdioGuardProxy, request: FileReadRequestMatch) -> GuardArtifact:
    return build_file_read_request_artifact(
        harness=proxy.harness,
        request=request,
        config_path=str(proxy._policy_path()),
        source_scope="project" if proxy.cwd is not None else "global",
    )


def _context(proxy: StdioGuardProxy, artifact: GuardArtifact, config: object, home: Path) -> tuple[str, str]:
    return sensitive_read_context(
        artifact,
        config=config,
        cwd=proxy.cwd,
        harness=proxy.harness,
        server_launch_identity=proxy._session_launch_identity(),
        configured_env_values_hash=proxy._session_env_values_hash(),
        guard_home=home,
    )


def _lookup(
    proxy: StdioGuardProxy,
    artifact: GuardArtifact,
    token: str,
    *,
    diagnose: bool,
) -> tuple[Mapping[str, Any] | None, dict[str, object] | None]:
    store = proxy.guard_store
    if store is None:
        return None, None
    raw = store.resolve_policy_decision_lookup(
        proxy.harness,
        artifact.artifact_id,
        artifact_hash=token,
        workspace=str(proxy.cwd) if proxy.cwd is not None else None,
        publisher=artifact.publisher,
        consume_one_shot=False,
    )
    diagnosed: str | None = None
    if diagnose and raw["decision"] is None and raw["ignored_local_integrity"] is None:
        diagnosed = store.approval_reuse_validation_reason(
            proxy.harness,
            artifact.artifact_id,
            token,
            str(proxy.cwd) if proxy.cwd is not None else None,
            artifact.publisher,
        )
    return raw["decision"], lookup_facts(raw, diagnosed)


def _approval_item(artifact: GuardArtifact, token: str, policy_action: str, evidence: list[Any]) -> dict[str, Any]:
    return {
        "artifact_id": artifact.artifact_id,
        "artifact_name": artifact.name,
        "artifact_hash": token,
        "policy_action": policy_action,
        "changed_fields": ["file_read_request"],
        "artifact_type": artifact.artifact_type,
        "source_scope": artifact.source_scope,
        "config_path": artifact.config_path,
        "launch_target": artifact.metadata.get("request_summary"),
        "scanner_evidence": list(evidence),
    }


def _detection(proxy: StdioGuardProxy, artifact: GuardArtifact) -> HarnessDetection:
    return HarnessDetection(
        harness=proxy.harness,
        installed=True,
        command_available=True,
        config_paths=(artifact.config_path,),
        artifacts=(artifact,),
    )


def _fail_closed(event: dict[str, Any], tool_name: str) -> NotForwarded:
    event["decision"] = "block"
    event["policy_action"] = "block"
    event["transport_outcome"] = "not-forwarded"
    return (
        f"Guard could not evaluate sensitive local file access for {tool_name}; the native runtime is unavailable.",
        {"guardPolicyAction": "block", "transportOutcome": "not-forwarded"},
    )


def evaluate_sensitive_read(
    proxy: StdioGuardProxy,
    *,
    tool_name: str,
    params: object,
    event: dict[str, Any],
) -> NotForwarded | None:
    """Evaluate one ``tools/call``; ``None`` means forward it to the child."""

    request = extract_sensitive_file_read_request(
        tool_name,
        params.get("arguments") if isinstance(params, dict) else None,
        cwd=proxy.cwd,
    )
    if request is None:
        return None
    try:
        return _evaluate(proxy, request, tool_name=tool_name, event=event)
    except NativeMcpProxyDecisionError:
        return _fail_closed(event, tool_name)


def _evaluate(
    proxy: StdioGuardProxy,
    request: FileReadRequestMatch,
    *,
    tool_name: str,
    event: dict[str, Any],
) -> NotForwarded | None:
    store = proxy.guard_store
    home = _resolve_digest_home(getattr(store, "guard_home", None))
    artifact = _artifact(proxy, request)
    current_action, token = _context(proxy, artifact, proxy.guard_config, home)
    saved_decision, lookup = _lookup(proxy, artifact, token, diagnose=True)

    def reuse(stage: str, **fields: Any) -> dict[str, Any]:
        values: dict[str, Any] = {
            "stage": stage,
            "current_action": current_action,
            "artifact_hash_value": token,
            "lookup": lookup,
            "claimed_allow_hash": None,
            "tool_name": tool_name,
            "path_class": request.path_match.path_class,
            "asks_for_approval": asks_for_approval(proxy.guard_config),
            "approval_center_present": proxy.approval_center_url is not None,
            "store_present": store is not None,
            "guard_home": home,
        }
        values.update(fields)
        return sensitive_read_reuse(**values)

    decision = reuse("initial")
    if decision["claim_candidate"] and saved_decision is not None and store is not None:
        if not store.claim_approval_reuse_decision(saved_decision):
            decision = reuse("claim_failed")
        else:
            # The atomic claim is authority only for the exact context it
            # consumed; rebuild every policy- and launch-bound input after it.
            claimed_hash = token
            provider = proxy._current_config_provider
            try:
                fresh_config = provider() if provider is not None else None
            except Exception:
                fresh_config = None
            if not isinstance(fresh_config, GuardConfig):
                decision = reuse("refresh_failed")
            else:
                proxy.guard_config = fresh_config
                artifact = _artifact(proxy, request)
                current_action, token = _context(proxy, artifact, fresh_config, home)
                _saved, lookup = _lookup(proxy, artifact, token, diagnose=False)
                decision = reuse("postclaim", claimed_allow_hash=claimed_hash)

    policy_action = str(decision["policy_action"])
    evidence = list(decision["reuse_evidence"])
    event["artifact_id"] = artifact.artifact_id
    event["artifact_type"] = artifact.artifact_type
    event["path_summary"] = request.path_match.normalized_path
    event["risk_summary"] = artifact.metadata.get("runtime_request_summary")
    event["approval_reuse_status"] = decision["event_status"]
    event["approval_reuse_reason_code"] = decision["event_reason_code"]
    if decision["terminal_saved_block"]:
        event["terminal_saved_block"] = True
    if store is not None:
        store.add_receipt(
            build_receipt(
                harness=proxy.harness,
                artifact_id=artifact.artifact_id,
                artifact_hash=token,
                policy_decision=policy_action,
                capabilities_summary=f"file read request • {request.tool_name}",
                changed_capabilities=["file_read_request"],
                provenance_summary=f"runtime MCP tool request evaluated from {proxy._policy_path()}",
                artifact_name=artifact.name,
                source_scope=artifact.source_scope,
                approval_source=decision["approval_source"],
                scanner_evidence=tuple(evidence),
            )
        )
    non_forward = decision["non_forward"]
    event["decision"] = policy_action
    event["policy_action"] = policy_action
    event["transport_outcome"] = "forwarded" if non_forward is None else "not-forwarded"
    if non_forward is None:
        return None
    message = str(non_forward["message"])
    data: dict[str, Any] = {
        "guardPolicyAction": non_forward["response_action"],
        "transportOutcome": "not-forwarded",
    }
    if non_forward["wrap_safe_alternative"]:
        message = safe_alternative_reason(message)
    redaction = getattr(proxy.guard_config, "receipt_redaction_level", "full")
    if non_forward["record_unprompted_review"]:
        approvals_module.record_unprompted_review(
            detection=_detection(proxy, artifact),
            evaluation={"artifacts": [_approval_item(artifact, token, policy_action, evidence)]},
            store=store,
            approval_center_url=proxy.approval_center_url,
            redaction_level=redaction,
        )
    if non_forward["queue_approvals"]:
        assert store is not None
        center_url = proxy.approval_center_url
        assert center_url is not None
        event["approval_requests"] = queue_blocked_approvals(
            redaction_level=redaction,
            detection=_detection(proxy, artifact),
            evaluation={"artifacts": [_approval_item(artifact, token, policy_action, evidence)]},
            store=store,
            approval_center_url=center_url,
        )
        approval_flow = approval_prompt_flow(proxy.harness, managed_install=store.get_managed_install(proxy.harness))
        event["approval_center_url"] = center_url
        event["approval_delivery"] = approval_delivery_payload(approval_flow)
        review_url = first_approval_url(event["approval_requests"], approval_center_url=center_url) or center_url
        request_id = next(
            (
                str(item["request_id"])
                for item in event["approval_requests"]
                if isinstance(item, dict) and isinstance(item.get("request_id"), str)
            ),
            "waiting-request",
        )
        proxy._maybe_open_approval_center(review_url=review_url, open_key=request_id)
        event["review_hint"], message = sensitive_read_hint(
            policy_action=policy_action,
            message=message,
            approval_summary=approval_flow["summary"],
            review_url=review_url,
            guard_home=home,
        )
        data.update(
            {
                "approvalCenterUrl": center_url,
                "approvalRequests": event["approval_requests"],
                "approvalDelivery": event["approval_delivery"],
                "reviewHint": event["review_hint"],
                "reviewUrl": review_url,
            }
        )
    return message, data

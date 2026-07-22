"""Focused fixtures and HTTP helpers for command-activity API tests."""

# pyright: reportAny=false, reportPrivateUsage=false, reportUnusedCallResult=false

from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import datetime, timezone

from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.runtime.command_activity_contract import (
    ActivityApprovalReuseStatus,
    ActivityDecisionReason,
    ActivityLatencyBucket,
    ActivityMatchClass,
    ActivityParseConfidence,
    CommandActivity,
    CommandActivityEvidence,
    CommandActivityMatch,
    CommandExecutionStatus,
    CommandHookPhase,
    CommandProofLevel,
    ReceiptLinkStatus,
)
from codex_plugin_scanner.guard.runtime.effect_contract import EffectKind
from codex_plugin_scanner.guard.runtime.extension_evidence import EvidenceSeverity, ExtensionRuleIdentity
from codex_plugin_scanner.guard.store import GuardStore


def evidence(
    activity_id: str,
    *,
    minute: int,
    prompted: bool = False,
    harness: str = "codex",
) -> CommandActivityEvidence:
    activity = CommandActivity(
        activity_id=activity_id,
        occurred_at=datetime(2026, 7, 18, 20, minute, tzinfo=timezone.utc),
        harness=harness,
        hook_phase=CommandHookPhase.PRE,
        execution_status=CommandExecutionStatus.ALLOWED_UNCONFIRMED,
        proof_level=CommandProofLevel.PRE_HOOK,
        policy_action="review" if prompted else "allow",
        decision_reason_code=ActivityDecisionReason.EXTENSION_MATCH,
        controlling_rule_id="command.git.push",
        parse_confidence=ActivityParseConfidence.EXACT,
        uncertainty_class=None,
        match_count=1,
        prompted=prompted,
        approval_reuse_status=ActivityApprovalReuseStatus.NOT_APPLICABLE,
        request_correlation=None,
        session_correlation=None,
        receipt_link_status=ReceiptLinkStatus.LINKED if prompted else ReceiptLinkStatus.NOT_APPLICABLE,
        receipt_id=f"receipt:{activity_id}" if prompted else None,
        evaluation_latency_bucket=ActivityLatencyBucket.LE_5_MS,
        persistence_latency_bucket=ActivityLatencyBucket.LE_2_MS,
    )
    match = CommandActivityMatch(
        activity_id=activity_id,
        ordinal=0,
        identity=ExtensionRuleIdentity("command.git", "2.2.0", "command.git.push", "1.0.0"),
        match_class=ActivityMatchClass.UNSAFE,
        severity=EvidenceSeverity.HIGH,
        default_floor="review",
        effect_claims=frozenset({EffectKind.REMOTE_STATE_MUTATION}),
    )
    return CommandActivityEvidence(activity, (match,))


def seed(store: GuardStore) -> None:
    for index in range(3):
        store.record_command_activity(
            evidence(
                f"activity:{index + 1:02d}",
                minute=index,
                prompted=index == 1,
            )
        )


def json_request(
    daemon: GuardDaemonServer,
    path: str,
    *,
    method: str = "GET",
    token: str | None = None,
    payload: dict[str, object] | None = None,
    origin: str | None = None,
    extra_headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, object], dict[str, str]]:
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if token is not None:
        if token.startswith("gld1."):
            headers["X-Guard-Dashboard-Session"] = token
        else:
            headers["X-Guard-Token"] = token
    if origin is not None:
        headers["Origin"] = origin
    if extra_headers is not None:
        headers.update(extra_headers)
    data = None if method == "GET" else json.dumps(payload or {}).encode("utf-8")
    request = urllib.request.Request(
        f"http://127.0.0.1:{daemon.port}{path}",
        data=data,
        headers=headers,
        method=method,
    )
    try:
        response = urllib.request.urlopen(request, timeout=5)
    except urllib.error.HTTPError as error:
        body = json.loads(error.read().decode("utf-8"))
        return error.code, body, dict(error.headers.items())
    with response:
        body = json.loads(response.read().decode("utf-8"))
        return response.status, body, dict(response.headers.items())


def raw_request(
    daemon: GuardDaemonServer,
    path: str,
    *,
    token: str,
    origin: str | None = None,
    last_event_id: str | None = None,
) -> urllib.request.Request:
    headers = {"X-Guard-Dashboard-Session": token}
    if origin is not None:
        headers["Origin"] = origin
    if last_event_id is not None:
        headers["Last-Event-ID"] = last_event_id
    return urllib.request.Request(
        f"http://127.0.0.1:{daemon.port}{path}",
        headers=headers,
        method="GET",
    )


__all__ = ("evidence", "json_request", "raw_request", "seed")

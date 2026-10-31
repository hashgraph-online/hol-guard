"""Which published Cloud policy rule queued a review request.

Cloud Review links a request to the rule that produced it, so a reviewer can
read the exact rule their workspace published. The request row does not keep
the deciding rule, so the first claim built for a request asks the native
policy lookup the same question the hook asked, without consuming anything,
and records the answer once. Every later claim for that request reads the
recorded answer, which keeps the claim hash stable while the request is open
even when the bundle or local decisions change afterwards.
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Callable, Mapping
from contextlib import AbstractContextManager
from datetime import datetime
from typing import Protocol, cast

from .synced_policy import SyncPayloadReader, validated_synced_policy_bundle

ATTRIBUTION_STATE_PREFIX = "review_policy_attribution:"
_REMOTE_POLICY_SOURCE = "policy-bundle"
_REVIEW_ACTIONS = frozenset({"review", "require-reapproval"})
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class _AttributionStore(SyncPayloadReader, Protocol):
    def insert_sync_payload_if_absent(self, state_key: str, payload: Mapping[str, object], now: str) -> None: ...

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
    ) -> Mapping[str, object]: ...


def _text(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _identifier(value: object) -> str | None:
    text = _text(value)
    return text if text is not None and _IDENTIFIER.fullmatch(text) else None


def _timestamp(value: object) -> datetime | None:
    text = _text(value)
    if text is None:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _already_delivered(store: object, request_id: str) -> bool:
    """A request Cloud has already seen keeps the claim it was sent with."""

    connect = getattr(store, "_connect", None)
    if not callable(connect):
        return False
    connect = cast(Callable[[], AbstractContextManager[sqlite3.Connection]], connect)
    try:
        with connect() as connection:
            row: object = connection.execute(
                """
                select 1 from guard_review_outbox_events
                where local_request_id = ?
                  and (attempt_count > 0 or acknowledged_at is not null)
                limit 1
                """,
                (request_id,),
            ).fetchone()
    except sqlite3.Error:
        return True
    return row is not None


def _bundle_rule_ids(bundle: Mapping[str, object]) -> set[str]:
    rules = bundle.get("rules")
    if not isinstance(rules, list):
        return set()
    return {rule_id for rule in rules if isinstance(rule, dict) and (rule_id := _identifier(rule.get("ruleId")))}


def _resolve(store: _AttributionStore, request_row: Mapping[str, object]) -> dict[str, str]:
    policy_action = _text(request_row.get("policy_action"))
    harness = _text(request_row.get("harness"))
    created_at = _text(request_row.get("created_at"))
    created = _timestamp(created_at)
    if policy_action not in _REVIEW_ACTIONS or harness is None or created is None:
        return {}
    bundle = validated_synced_policy_bundle(store)
    if bundle is None:
        return {}
    bundle_version = _identifier(bundle.get("bundleVersion"))
    issued = _timestamp(bundle.get("issuedAt"))
    # A bundle that arrived after the request cannot be the one that queued it.
    if bundle_version is None or issued is None or issued > created:
        return {}
    lookup = store.resolve_policy_decision_lookup(
        harness,
        _text(request_row.get("artifact_id")),
        artifact_hash=_text(request_row.get("artifact_hash")),
        workspace=_text(request_row.get("workspace")),
        publisher=_text(request_row.get("publisher")),
        now=created_at,
        consume_one_shot=False,
    )
    decision = lookup.get("decision")
    if not isinstance(decision, Mapping) or decision.get("source") != _REMOTE_POLICY_SOURCE:
        return {}
    # The hook queues either review action for a review row.
    if _text(decision.get("action")) not in _REVIEW_ACTIONS:
        return {}
    rule_id = _identifier(decision.get("owner"))
    if rule_id is None or rule_id not in _bundle_rule_ids(bundle):
        return {}
    return {"policyBundleVersion": bundle_version, "policyRuleId": rule_id}


def review_policy_attribution(store: object, request_row: Mapping[str, object]) -> dict[str, str]:
    """Return the recorded ``policyRuleId``/``policyBundleVersion`` for a request, or ``{}``.

    The first call records the answer, including "no Cloud rule", so the
    claim never gains or loses these fields later.
    """

    request_id = _text(request_row.get("request_id"))
    get_payload = getattr(store, "get_sync_payload", None)
    insert_payload = getattr(store, "insert_sync_payload_if_absent", None)
    if request_id is None or not callable(get_payload) or not callable(insert_payload):
        return {}
    state_key = f"{ATTRIBUTION_STATE_PREFIX}{request_id}"
    recorded = get_payload(state_key)
    if not isinstance(recorded, dict):
        attribution: dict[str, str] = {}
        if not _already_delivered(store, request_id):
            try:
                attribution = _resolve(cast(_AttributionStore, store), request_row)
            except Exception:
                # Nothing is recorded, so a later build can still answer; a
                # claim that reaches Cloud first marks the request delivered.
                return {}
        _ = insert_payload(state_key, attribution, datetime.now().astimezone().isoformat())
        recorded = get_payload(state_key)
        if not isinstance(recorded, dict):
            return {}
    recorded_fields = cast(dict[str, object], recorded)
    rule_id = _identifier(recorded_fields.get("policyRuleId"))
    bundle_version = _identifier(recorded_fields.get("policyBundleVersion"))
    if rule_id is None or bundle_version is None:
        return {}
    return {"policyBundleVersion": bundle_version, "policyRuleId": rule_id}

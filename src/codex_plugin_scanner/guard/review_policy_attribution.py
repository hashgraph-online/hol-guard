"""Which published Cloud policy rule queued a review request.

Cloud Review links a request to the rule that produced it, so a reviewer can
read the exact rule their workspace published. The request row does not keep
the deciding rule, so the first claim built for a request asks the native
policy lookup the same question the hook asked, without consuming anything,
and records the answer once. Every later claim for that request reads the
recorded answer, which keeps the claim hash stable while the request is open
even when the bundle or local decisions change afterwards.

Cloud verifies its signed decision against the claim it received, so a claim
must never gain these fields after it was sent. Every first answer is
recorded, including "no rule" after a failed lookup, and a request is only
attributed while its first outbox event is still waiting for its first
upload. Acknowledged events are deleted, so anything else may already have
reached Cloud without the fields.
"""

from __future__ import annotations

import logging
import re
import sqlite3
from collections.abc import Callable, Mapping
from contextlib import AbstractContextManager
from datetime import datetime
from typing import Protocol, cast

from .synced_policy import SyncPayloadReader, validated_synced_policy_bundle

ATTRIBUTION_STATE_PREFIX = "review_policy_attribution:"
_LOGGER = logging.getLogger(__name__)
_REMOTE_POLICY_SOURCE = "policy-bundle"
_CANONICAL_POLICY_SOURCE = "policy-bundle-canonical"
_V2_CONTRACT = "guard-policy-bundle.v2"
# A v2 bundle names the published document it carries, so its attribution
# names that document revision rather than the v1 bundle version string.
_V2_ATTRIBUTION_PREFIX = f"{_V2_CONTRACT}:"
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


def _first_claim_not_yet_sent(store: object, request_id: str) -> bool:
    """True only while the request's first outbox event awaits its first upload."""

    connect = getattr(store, "_connect", None)
    if not callable(connect):
        return False
    connect = cast(Callable[[], AbstractContextManager[sqlite3.Connection]], connect)
    with connect() as connection:
        rows: list[tuple[object, object, object]] = connection.execute(
            """
            select request_sequence, attempt_count, acknowledged_at
            from guard_review_outbox_events
            where local_request_id = ?
            """,
            (request_id,),
        ).fetchall()
    return any(sequence == 1 for sequence, _, _ in rows) and all(
        attempts == 0 and acknowledged is None for _, attempts, acknowledged in rows
    )


def _bundle_rule_ids(bundle: Mapping[str, object]) -> set[str]:
    rules = bundle.get("rules")
    if not isinstance(rules, list):
        return set()
    return {rule_id for rule in rules if isinstance(rule, dict) and (rule_id := _identifier(rule.get("ruleId")))}


def _v2_document(bundle: Mapping[str, object]) -> tuple[str, set[str]] | None:
    """The attribution version and rule ids of the document a v2 bundle carries."""

    payload = bundle.get("payload")
    if not isinstance(payload, Mapping):
        return None
    metadata = payload.get("metadata")
    spec = payload.get("spec")
    revision = metadata.get("revision") if isinstance(metadata, Mapping) else None
    rules = spec.get("rules") if isinstance(spec, Mapping) else None
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1 or not isinstance(rules, list):
        return None
    rule_ids = {rule_id for rule in rules if isinstance(rule, dict) and (rule_id := _identifier(rule.get("id")))}
    return f"{_V2_ATTRIBUTION_PREFIX}{revision}", rule_ids


def _bundle_identity(bundle: Mapping[str, object]) -> tuple[str, str, set[str]] | None:
    """The decision source, attribution version and rule ids a bundle publishes."""

    if bundle.get("contractVersion") == _V2_CONTRACT:
        document = _v2_document(bundle)
        return None if document is None else (_CANONICAL_POLICY_SOURCE, *document)
    bundle_version = _identifier(bundle.get("bundleVersion"))
    if bundle_version is None:
        return None
    return _REMOTE_POLICY_SOURCE, bundle_version, _bundle_rule_ids(bundle)


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
    identity = _bundle_identity(bundle)
    issued = _timestamp(bundle.get("issuedAt"))
    # A bundle that arrived after the request cannot be the one that queued it.
    if identity is None or issued is None or issued > created:
        return {}
    source, bundle_version, rule_ids = identity
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
    if not isinstance(decision, Mapping) or decision.get("source") != source:
        return {}
    # The hook queues either review action for a review row.
    if _text(decision.get("action")) not in _REVIEW_ACTIONS:
        return {}
    rule_id = _identifier(decision.get("owner"))
    if rule_id is None or rule_id not in rule_ids:
        return {}
    return {"policyBundleVersion": bundle_version, "policyRuleId": rule_id}


def review_policy_attribution(store: object, request_row: Mapping[str, object]) -> dict[str, str]:
    """Return the recorded ``policyRuleId``/``policyBundleVersion`` for a request, or ``{}``.

    The first call records the answer, including "no Cloud rule" and a
    failed lookup, so the claim never gains or loses these fields later.
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
        try:
            if _first_claim_not_yet_sent(store, request_id):
                attribution = _resolve(cast(_AttributionStore, store), request_row)
        except Exception as error:
            # A claim built now may reach Cloud, so the failure is recorded as
            # "no rule" rather than retried into a different claim hash.
            _LOGGER.warning(
                "Review policy attribution failed (%s); recording no rule", type(error).__name__, exc_info=True
            )
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

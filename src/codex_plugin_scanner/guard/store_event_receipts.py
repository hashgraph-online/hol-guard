"""GuardStore domain mixin extracted from store.py."""

# pyright: reportAttributeAccessIssue=false, reportUndefinedVariable=false

from __future__ import annotations

# ruff: noqa: F403,F405
from .native_store_policy import encode_key
from .store_base import *

LOCAL_ONCE_LEGACY_AUTHORITY_KIND = "legacy"
EXACT_CLOUD_AUTHORITY_KIND = "exact-cloud"


_EVENT_PAGE_ITEM_KEYS = frozenset({"event_id", "event_name", "occurred_at", "payload_json"})


def _event_page(answer: object) -> tuple[list[dict[str, object]], bool]:
    """Check one native ``list_events`` page and parse each stored payload."""

    if not isinstance(answer, dict) or set(answer) != {"items", "more"}:
        raise RuntimeError("native list_events returned no answer")
    raw_items = answer["items"]
    more = answer["more"]
    if not isinstance(raw_items, list) or not isinstance(more, bool):
        raise RuntimeError("native list_events returned no answer")
    items: list[dict[str, object]] = []
    for item in raw_items:
        if not isinstance(item, dict) or set(item) != _EVENT_PAGE_ITEM_KEYS:
            raise RuntimeError("native list_events returned no answer")
        event_id = item["event_id"]
        event_name = item["event_name"]
        occurred_at = item["occurred_at"]
        payload_json = item["payload_json"]
        if (
            isinstance(event_id, bool)
            or not isinstance(event_id, int)
            or not isinstance(event_name, str)
            or not isinstance(occurred_at, str)
            or not isinstance(payload_json, str)
        ):
            raise RuntimeError("native list_events returned no answer")
        payload = json.loads(payload_json)
        items.append(
            {
                "event_id": event_id,
                "event_name": event_name,
                "occurred_at": occurred_at,
                "payload": payload if isinstance(payload, dict) else {},
            }
        )
    return items, more


class StoreEventReceiptsMixin:
    def record_local_once_approval(
        self,
        *,
        request_id: str,
        harness: str,
        artifact_id: str | None,
        artifact_hash: str | None,
        workspace: str | None,
        publisher: str | None,
        action: str,
        created_at: str,
        expires_at: str,
        authority_kind: str = LOCAL_ONCE_LEGACY_AUTHORITY_KIND,
    ) -> str | None:
        """Mint exact one-shot authority for an approval granted on this install.

        The row written here is the authority a later native review reads to
        allow an execution without asking again, so the resident signs it where
        the verdict is decided. This side reads the install key out of the
        keyring and ships it; it signs nothing and decides nothing. An install
        with no key material has no authority to mint, which is why that case
        answers ``None`` rather than calling.
        """

        key, key_id = self._policy_integrity_secret_material(create=True)
        if key is None or key_id is None:
            return None
        approval_id = self._native_store_call(
            "record_local_once_approval",
            {
                "request_id": request_id,
                "harness": harness,
                "artifact_id": artifact_id,
                "artifact_hash": artifact_hash,
                "workspace": workspace,
                "publisher": publisher,
                "action": action,
                "created_at": created_at,
                "expires_at": expires_at,
                "authority_kind": authority_kind,
                "integrity_key_b64": encode_key(key),
                "integrity_key_id": key_id,
            },
        )
        return None if approval_id is None else str(approval_id)

    def list_events(self, limit: int = 100, event_name: str | None = None) -> list[dict[str, object]]:
        """The local event log, newest first, read from bounded native pages."""

        items: list[dict[str, object]] = []
        before: dict[str, object] | None = None
        while True:
            wanted = -1 if limit < 0 else limit - len(items)
            if wanted == 0:
                return items
            args: dict[str, object] = {"limit": wanted}
            if event_name is not None:
                args["event_name"] = event_name
            if before is not None:
                args["before"] = before
            page, more = _event_page(self._native_store_call("list_events", args))
            items.extend(page)
            if not more:
                return items
            if not page:
                raise RuntimeError("native list_events returned no answer")
            last = page[-1]
            before = {"occurred_at": last["occurred_at"], "event_id": last["event_id"]}

    def list_events_after(
        self,
        event_id: int,
        *,
        limit: int = 100,
        event_names: tuple[str, ...] | None = None,
    ) -> list[dict[str, object]]:
        args: dict[str, object] = {"event_id": event_id, "limit": limit}
        if event_names:
            args["event_names"] = list(event_names)
        answer = self._native_store_call("list_events_after", args)
        if not isinstance(answer, list):
            raise RuntimeError("native list_events_after returned no answer")
        items: list[dict[str, object]] = []
        for item in answer:
            if not isinstance(item, dict) or set(item) != {"event_id", "event_name", "occurred_at", "payload"}:
                raise RuntimeError("native list_events_after returned no answer")
            if (
                isinstance(item["event_id"], bool)
                or not isinstance(item["event_id"], int)
                or not isinstance(item["event_name"], str)
                or not isinstance(item["occurred_at"], str)
                or not isinstance(item["payload"], dict)
            ):
                raise RuntimeError("native list_events_after returned no answer")
            items.append(item)
        return items

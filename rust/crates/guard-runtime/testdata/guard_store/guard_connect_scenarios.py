# ruff: noqa: E501
"""Scenarios for the guard connect-state parity vectors.

Shared by the recorder (which runs them through the ORIGINAL Python store) and
the Python parity test (which replays them through the new wrappers). Steps are
either `{"sql": [(statement, params), ...]}` or `{"method", "args", "kwargs"}`;
a method step may carry `profile`, the cloud sync profile the Python store would
derive from its secret store (the resident never sees secrets).
"""

from __future__ import annotations

import json

NOW = "2026-10-10T12:00:00+00:00"
PAST = "2020-01-01T00:00:00+00:00"
FUTURE = "2099-01-01T00:00:00+00:00"
T1 = "2026-10-10T10:00:00+00:00"
T2 = "2026-10-10T10:05:00+00:00"
T3 = "2026-10-10T10:10:00+00:00"
SYNC_URL = "https://hol.org/api/guard/receipts/sync"
PROFILE = {"auth_mode": "oauth", "sync_url": "https://hol.org/api/guard/receipts/sync", "workspace_id": "ws-1"}
PROFILE_BARE = {"auth_mode": "oauth", "sync_url": "not a url"}


def call(method: str, label: str = "", *args: object, profile: object = None, **kwargs: object) -> dict[str, object]:
    return {"method": method, "label": label, "args": args, "kwargs": kwargs, "profile": profile}


def sql(label: str, *statements: tuple[str, tuple[object, ...]]) -> dict[str, object]:
    return {"label": label, "sql": list(statements)}


def state_row(
    request_id: str,
    *,
    status: str = "connected",
    milestone: str = "first_sync_pending",
    reason: str | None = None,
    updated_at: str = T1,
    expires_at: str = FUTURE,
    completed_at: str | None = T1,
    proof: object = "{}",
    sync_url: str = SYNC_URL,
    allowed_origin: str = "https://hol.org",
) -> tuple[str, tuple[object, ...]]:
    proof_text = proof if isinstance(proof, str) else json.dumps(proof)
    return (
        "insert into guard_connect_states (request_id, sync_url, allowed_origin, status, milestone, reason, "
        "created_at, updated_at, expires_at, completed_at, proof_json) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            request_id,
            sync_url,
            allowed_origin,
            status,
            milestone,
            reason,
            T1,
            updated_at,
            expires_at,
            completed_at,
            proof_text,
        ),
    )


def request_row(request_id: str, status: str = "pending") -> tuple[str, tuple[object, ...]]:
    return (
        "insert into guard_connect_requests (request_id, sync_url, allowed_origin, pairing_secret_hash, status, "
        "created_at, expires_at, completed_at) values (?, ?, ?, 'hash', ?, ?, ?, null)",
        (request_id, SYNC_URL, "https://hol.org", status, T1, FUTURE),
    )


def summary(payload: object) -> dict[str, object]:
    return sql(
        "sync summary",
        (
            "insert or replace into sync_state (state_key, payload_json, updated_at) values ('sync_summary', ?, ?)",
            (payload if isinstance(payload, str) else json.dumps(payload), T1),
        ),
    )


def clear_summary() -> dict[str, object]:
    return sql("clear summary", ("delete from sync_state where state_key = 'sync_summary'", ()))


def reset() -> dict[str, object]:
    return sql(
        "reset",
        ("delete from guard_connect_states", ()),
        ("delete from guard_connect_requests", ()),
        ("delete from sync_state", ()),
    )


FULL_SUMMARY = {
    "synced_at": T3,
    "receipts_stored": 7,
    "inventory_tracked": 3,
    "runtime_session_id": "rs-1",
    "runtime_session_synced_at": T2,
}

SCENARIOS: list[dict[str, object]] = [
    {
        "name": "pairing_then_latest_and_effective",
        "steps": [
            call("get_latest_guard_connect_state", "empty", now=NOW),
            call("get_effective_guard_connect_state", "empty no profile", now=NOW),
            call("get_effective_guard_connect_state", "empty profile", now=NOW, profile=PROFILE),
            call(
                "record_guard_connect_pairing_completed",
                "generated id",
                sync_url=SYNC_URL,
                allowed_origin="https://hol.org",
                now=T1,
            ),
            call("get_latest_guard_connect_state", "after pairing", now=NOW),
            call("get_effective_guard_connect_state", "connected without profile", now=NOW),
            call("get_effective_guard_connect_state", "connected profile", now=NOW, profile=PROFILE),
            summary(FULL_SUMMARY),
            call("get_effective_guard_connect_state", "profile + summary", now=NOW, profile=PROFILE),
            call("get_effective_guard_connect_state", "summary without profile", now=NOW),
            call(
                "record_guard_connect_pairing_completed",
                "explicit id padded",
                sync_url=SYNC_URL,
                allowed_origin="https://hol.org",
                now=T2,
                request_id="  conn-explicit  ",
            ),
            call(
                "record_guard_connect_pairing_completed",
                "duplicate id",
                sync_url=SYNC_URL,
                allowed_origin="https://hol.org",
                now=T3,
                request_id="conn-explicit",
            ),
            call(
                "record_guard_connect_pairing_completed",
                "blank id falls back",
                sync_url=SYNC_URL,
                allowed_origin="https://hol.org",
                now=T3,
                request_id="   ",
            ),
            call("get_latest_guard_connect_state", "latest by updated_at", now=NOW),
        ],
    },
    {
        "name": "waiting_request_expiry",
        "steps": [
            sql(
                "seed",
                request_row("r-old"),
                request_row("r-new"),
                state_row("r-old", status="waiting", milestone="waiting_for_browser", expires_at=PAST, updated_at=T1),
                state_row("r-new", status="waiting", milestone="waiting_for_browser", expires_at=FUTURE, updated_at=T2),
            ),
            call("get_latest_guard_connect_state", "newest still waiting", now=NOW),
            sql(
                "make old newest", ("update guard_connect_states set updated_at = ? where request_id = 'r-old'", (T3,))
            ),
            call("get_latest_guard_connect_state", "old expires", now=NOW),
            call("get_latest_guard_connect_state", "expiry idempotent", now=NOW),
            call("get_effective_guard_connect_state", "expired with profile", now=NOW, profile=PROFILE),
            sql(
                "invalid expiry", ("update guard_connect_states set expires_at = 'soon' where request_id = 'r-new'", ())
            ),
            sql(
                "r-new newest",
                (
                    "update guard_connect_states set updated_at = ? where request_id = 'r-new'",
                    ("2026-10-10T13:00:00+00:00",),
                ),
            ),
            call("get_latest_guard_connect_state", "unparsable expiry", now=NOW),
            sql(
                "naive expiry",
                ("update guard_connect_states set expires_at = '2020-01-01T00:00:00' where request_id = 'r-new'", ()),
            ),
            call("get_latest_guard_connect_state", "naive expiry is utc", now=NOW),
            sql(
                "zulu expiry",
                (
                    "update guard_connect_states set status='waiting', milestone='waiting_for_browser', expires_at = '2099-01-01T00:00:00Z', updated_at = '2026-10-10T13:00:00+00:00' where request_id = 'r-new'",
                    (),
                ),
            ),
            call("get_latest_guard_connect_state", "zulu future stays waiting", now=NOW),
        ],
    },
    {
        "name": "sync_result_selection",
        "steps": [
            call(
                "record_latest_guard_connect_sync_result",
                "empty",
                status="connected",
                milestone="first_sync_succeeded",
                now=NOW,
            ),
            sql(
                "seed",
                state_row("c-1", updated_at=T1),
                state_row("c-2", updated_at=T2),
                state_row("c-3", status="expired", milestone="expired", updated_at=T3),
            ),
            call(
                "record_latest_guard_connect_sync_result",
                "latest connected by updated_at",
                status="connected",
                milestone="first_sync_failed",
                now=NOW,
                reason="boom",
            ),
            call(
                "record_latest_guard_connect_sync_result",
                "unknown request id",
                status="connected",
                milestone="first_sync_succeeded",
                now=NOW,
                request_id="nope",
            ),
            call(
                "record_latest_guard_connect_sync_result",
                "terminal state untouched",
                status="connected",
                milestone="first_sync_succeeded",
                now=NOW,
                request_id="c-3",
            ),
            call(
                "record_latest_guard_connect_sync_result",
                "retry_required skipped without id",
                status="connected",
                milestone="first_sync_succeeded",
                now=NOW,
                request_id=None,
            ),
            call(
                "record_latest_guard_connect_sync_result",
                "explicit retry_required",
                status="connected",
                milestone="first_sync_succeeded",
                now=NOW,
                request_id="c-2",
            ),
            call(
                "record_latest_guard_connect_sync_result",
                "padded id",
                status="retry_required",
                milestone="first_sync_failed",
                now=NOW,
                request_id=" c-1 ",
                reason="padded",
            ),
            call(
                "record_latest_guard_connect_sync_result",
                "blank id is not none",
                status="connected",
                milestone="first_sync_pending",
                now=NOW,
                request_id="  ",
            ),
            call(
                "record_latest_guard_connect_sync_result",
                "invalid status",
                status="bogus",
                milestone="first_sync_succeeded",
                now=NOW,
                request_id="c-1",
            ),
            call(
                "record_latest_guard_connect_sync_result",
                "invalid milestone",
                status="connected",
                milestone="bogus",
                now=NOW,
                request_id="c-1",
            ),
            call(
                "record_latest_guard_connect_sync_result",
                "invalid status without state",
                status="bogus",
                milestone="x",
                now=NOW,
                request_id="missing",
            ),
            call(
                "record_latest_guard_connect_sync_result",
                "waiting status",
                status="waiting",
                milestone="waiting_for_browser",
                now=NOW,
                request_id="c-1",
            ),
        ],
    },
    {
        "name": "sync_payload_proof_merge",
        "steps": [
            sql(
                "seed",
                state_row(
                    "p-1",
                    proof={
                        "pairing_completed_at": T1,
                        "first_synced_at": None,
                        "receipts_stored": 1,
                        "extra": {"k": "é"},
                    },
                ),
            ),
            call("record_latest_guard_connect_sync_success", "full payload", sync_payload=FULL_SUMMARY, now=NOW),
            call(
                "record_latest_guard_connect_sync_success",
                "inventory alias",
                sync_payload={"inventory": "12"},
                now=NOW,
                request_id="p-1",
            ),
            call(
                "record_latest_guard_connect_sync_success",
                "coercions",
                sync_payload={
                    "receipts_stored": -4,
                    "inventory_tracked": True,
                    "synced_at": None,
                    "runtime_session_id": 5,
                },
                now=NOW,
            ),
            call(
                "record_latest_guard_connect_sync_success",
                "string and float",
                sync_payload={"receipts_stored": " 9 ", "inventory_tracked": 2.5},
                now=NOW,
            ),
            call(
                "record_latest_guard_connect_sync_success",
                "unparsable string",
                sync_payload={"receipts_stored": "many", "inventory": ""},
                now=NOW,
            ),
            call("record_latest_guard_connect_sync_success", "empty payload", sync_payload={}, now=NOW),
            call("record_latest_guard_connect_sync_success", "no payload", sync_payload=None, now=NOW),
            call(
                "record_latest_guard_connect_sync_result",
                "failure with reason",
                status="retry_required",
                milestone="first_sync_failed",
                now=NOW,
                reason="network",
                request_id="p-1",
            ),
            call(
                "record_latest_guard_connect_sync_result",
                "retry_required recovers by id",
                status="connected",
                milestone="first_sync_succeeded",
                now=NOW,
                request_id="p-1",
                sync_payload={"receipts_stored": 3},
            ),
        ],
    },
    {
        "name": "effective_state_normalization",
        "steps": [
            sql("connected pending", state_row("e-1", reason="hello")),
            call("get_effective_guard_connect_state", "no profile, connected -> retry_required", now=NOW),
            call("get_effective_guard_connect_state", "profile only", now=NOW, profile=PROFILE),
            call("get_effective_guard_connect_state", "bare profile url", now=NOW, profile=PROFILE_BARE),
            summary(FULL_SUMMARY),
            call("get_effective_guard_connect_state", "summary promotes", now=NOW, profile=PROFILE),
            call("get_effective_guard_connect_state", "summary, no profile", now=NOW),
            summary({"inventory": 4, "receipts_stored": -1}),
            call("get_effective_guard_connect_state", "inventory alias and negative", now=NOW, profile=PROFILE),
            summary({"receipts_stored": True, "synced_at": "", "runtime_session_id": ""}),
            call("get_effective_guard_connect_state", "bool counts and blanks", now=NOW, profile=PROFILE),
            summary([1, 2]),
            call("get_effective_guard_connect_state", "list summary ignored", now=NOW, profile=PROFILE),
            summary("5"),
            call("get_effective_guard_connect_state", "scalar summary ignored", now=NOW, profile=PROFILE),
            summary({}),
            call("get_effective_guard_connect_state", "empty summary", now=NOW, profile=PROFILE),
            summary(FULL_SUMMARY),
            reset(),
            summary(FULL_SUMMARY),
            call("get_effective_guard_connect_state", "no state, profile + summary", now=NOW, profile=PROFILE),
            clear_summary(),
            call("get_effective_guard_connect_state", "no state, profile only", now=NOW, profile=PROFILE),
            sql(
                "retry_required",
                state_row("e-2", status="retry_required", milestone="first_sync_failed", reason="bad", updated_at=T2),
            ),
            summary(FULL_SUMMARY),
            call("get_effective_guard_connect_state", "retry_required stays", now=NOW, profile=PROFILE),
            call("get_effective_guard_connect_state", "retry_required without profile", now=NOW),
            sql(
                "failed milestone",
                (
                    "update guard_connect_states set status='connected', milestone='first_sync_failed' where request_id='e-2'",
                    (),
                ),
            ),
            call("get_effective_guard_connect_state", "failed milestone blocks promotion", now=NOW, profile=PROFILE),
            sql(
                "not available",
                ("update guard_connect_states set milestone='sync_not_available' where request_id='e-2'", ()),
            ),
            call("get_effective_guard_connect_state", "sync_not_available blocks", now=NOW, profile=PROFILE),
            sql(
                "expired",
                (
                    "update guard_connect_states set status='expired', milestone='expired', reason=null where request_id='e-2'",
                    (),
                ),
            ),
            clear_summary(),
            call("get_effective_guard_connect_state", "expired -> pending", now=NOW, profile=PROFILE),
            call("get_effective_guard_connect_state", "expired without profile", now=NOW),
            sql(
                "waiting",
                (
                    "update guard_connect_states set status='waiting', milestone='waiting_for_browser' where request_id='e-2'",
                    (),
                ),
            ),
            call("get_effective_guard_connect_state", "waiting -> pending", now=NOW, profile=PROFILE),
            sql(
                "empty reason",
                (
                    "update guard_connect_states set status='connected', milestone='first_sync_succeeded', reason='' where request_id='e-2'",
                    (),
                ),
            ),
            call("get_effective_guard_connect_state", "empty reason kept", now=NOW, profile=PROFILE),
            sql(
                "proof carries counts",
                (
                    "update guard_connect_states set proof_json = ?, completed_at = null where request_id='e-2'",
                    (
                        json.dumps(
                            {
                                "receipts_stored": 9,
                                "inventory_items": True,
                                "pairing_completed_at": "x",
                                "runtime_session_id": "old",
                            }
                        ),
                    ),
                ),
            ),
            summary({"receipts_stored": 2, "runtime_session_id": "new"}),
            call("get_effective_guard_connect_state", "proof max", now=NOW, profile=PROFILE),
            sql(
                "blank origin",
                ("update guard_connect_states set allowed_origin = '', sync_url = '' where request_id='e-2'", ()),
            ),
            call("get_effective_guard_connect_state", "blank origin falls back", now=NOW, profile=PROFILE),
            call("get_effective_guard_connect_state", "blank origin and bare profile", now=NOW, profile=PROFILE_BARE),
        ],
    },
    {
        "name": "stored_proof_documents",
        "steps": [
            sql("invalid proof", state_row("l-1", proof="{not json", updated_at=T1)),
            call("get_latest_guard_connect_state", "invalid proof", now=NOW),
            sql("list proof", ("update guard_connect_states set proof_json = '[1,2]' where request_id='l-1'", ())),
            call("get_latest_guard_connect_state", "list proof", now=NOW),
            sql("null-ish proof", ("update guard_connect_states set proof_json = 'null' where request_id='l-1'", ())),
            call("get_latest_guard_connect_state", "null proof", now=NOW),
            sql(
                "ordered proof",
                (
                    "update guard_connect_states set proof_json = ? where request_id='l-1'",
                    ('{"zeta": 1, "alpha": [1, 2], "inventory_items": 5}',),
                ),
            ),
            call(
                "record_latest_guard_connect_sync_success",
                "merge keeps key order",
                sync_payload={"receipts_stored": 2, "runtime_session_id": "r"},
                now=NOW,
            ),
            call("get_latest_guard_connect_state", "after merge", now=NOW),
            sql(
                "duplicate keys",
                (
                    'update guard_connect_states set proof_json = \'{"a": 1, "b": 2, "a": 3}\' where request_id=\'l-1\'',
                    (),
                ),
            ),
            call(
                "record_latest_guard_connect_sync_success",
                "duplicate key merge",
                sync_payload={"synced_at": "é"},
                now=NOW,
            ),
            call("get_latest_guard_connect_state", "after duplicate merge", now=NOW),
        ],
    },
]

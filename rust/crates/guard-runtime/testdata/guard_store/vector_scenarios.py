"""Seed builders and step lists for the guard_store parity recorder."""

from __future__ import annotations

import json
from collections.abc import Callable

from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.store import GuardStore

SOURCE = "default"
WORKSPACE = "workspace-1"
MACHINE = "machine-1"
INSTALLATION = "install-1"
GRANT = "grant-1"
IDENTITY_KEYS = ("oauth_subject_hash", "workspace_id", "machine_id", "machine_installation_id")


def stamp(seconds: int) -> str:
    return f"2026-09-01T00:{seconds // 60:02d}:{seconds % 60:02d}+00:00"


DECIMALS: dict[str, object] = {
    "action_type": "shell_command",
    "command": "ls",
    "tool_name": "Bash",
    "timeout": 0.1,
    "tiny": 1e-7,
    "huge": 1.5e300,
    "negative_zero": -0.0,
    "whole": 2.0,
    "nested": {"ratios": [0.5, 1e16, 123456789.123456789], "count": 3},
}


def request(request_id: str, action_envelope: dict[str, object] | None = None) -> GuardApprovalRequest:
    return GuardApprovalRequest(
        request_id=request_id,
        harness="codex",
        artifact_id=f"codex:project:{request_id}",
        artifact_name="Recorded request",
        artifact_type="tool_action_request",
        artifact_hash=f"hash-{request_id}",
        publisher=None,
        policy_action="require-reapproval",
        recommended_scope="artifact",
        changed_fields=("shell_command",),
        source_scope="project",
        config_path="/workspace/repo/.guard/config.toml",
        workspace="/workspace/repo",
        launch_target="cat /workspace/repo/.npmrc",
        review_command=f"hol-guard approvals approve {request_id}",
        approval_url=f"http://127.0.0.1:5474/approvals/{request_id}",
        action_envelope_json=action_envelope or {"action_type": "shell_command", "command": "ls", "tool_name": "Bash"},
    )


class Context:
    def __init__(self, store: GuardStore) -> None:
        self.store = store
        self.binding: dict[str, str] = {}

    def ident(self) -> dict[str, str]:
        return {key: self.binding.get(key) for key in IDENTITY_KEYS}

    def identity(self, **override: str) -> dict[str, str]:
        base = self.ident()
        base.update(override)
        return base

    def event_id(self, sequence: int) -> str:
        with self.store._connect() as connection:
            row = connection.execute(
                "select event_id from guard_review_outbox_events where stream_sequence = ?", (sequence,)
            ).fetchone()
        return str(row[0]) if row else "missing-event"


def bind(ctx: Context, *, workspace: str = WORKSPACE, grant: str = GRANT) -> None:
    payload = json.dumps({"grant_id": grant, "workspace_id": workspace, "machine_id": MACHINE})
    with ctx.store._connect() as connection:
        connection.execute(
            "insert into sync_state (state_key, payload_json, updated_at) values ('oauth_local_credentials', ?, ?) "
            "on conflict(state_key) do update set payload_json = excluded.payload_json",
            (payload, stamp(0)),
        )
        connection.execute(
            "update guard_devices set installation_id = ? where device_key = 'local-device'", (INSTALLATION,)
        )
    binding = ctx.store.get_review_event_oauth_binding()
    ctx.binding = dict(binding) if binding else {}


def add(ctx: Context, request_ids: list[str], *, offset: int = 1) -> None:
    for index, request_id in enumerate(request_ids):
        ctx.store.add_approval_request(request(request_id), stamp(offset + index))


def set_continuation(ctx: Context, request_id: str, snapshot: dict[str, object]) -> None:
    with ctx.store._connect() as connection:
        connection.execute(
            "update approval_requests set continuation_snapshot_json = ? where request_id = ?",
            (json.dumps(snapshot), request_id),
        )


Step = tuple[str, Callable[[Context], dict[str, object]]]


def scenario_empty(ctx: Context) -> list[Step]:
    return [
        ("get_review_event_oauth_binding", lambda c: {}),
        ("review_event_outbox_status", lambda c: {"now": stamp(30)}),
        ("list_ready_review_events", lambda c: {"now": stamp(30), "limit": 5, **c.identity()}),
        ("count_recoverable_unbound_review_events", lambda c: {}),
        ("refresh_review_event_outbox_binding", lambda c: {}),
        ("list_review_event_snapshots", lambda c: {"request_id": "missing"}),
    ]


def seed_bound(ctx: Context) -> None:
    bind(ctx)
    add(ctx, ["r1", "r2", "r3"])


def scenario_bound(ctx: Context) -> list[Step]:
    other = {"workspace_id": "workspace-other"}
    steps: list[Step] = [
        ("get_review_event_oauth_binding", lambda c: {}),
        ("review_event_outbox_status", lambda c: {"now": stamp(30)}),
        ("review_event_outbox_status", lambda c: {"now": stamp(30), **c.ident()}),
        ("review_event_outbox_status", lambda c: {"now": stamp(30), **c.identity(**other)}),
        ("list_ready_review_events", lambda c: {"now": stamp(30), "limit": 10, **c.ident()}),
        ("list_ready_review_events", lambda c: {"now": stamp(30), "limit": 2, **c.ident()}),
        ("list_ready_review_events", lambda c: {"now": stamp(30), "limit": 10, **c.identity(**other)}),
        ("list_review_event_snapshots", lambda c: {"request_id": "r1"}),
        ("list_pending_review_request_ids", lambda c: {"binding": c.ident(), "limit": 2}),
        ("list_pending_review_request_ids", lambda c: {"binding": c.ident(), "limit": 5, "after_request_id": "r1"}),
        (
            "list_pending_review_request_ids",
            lambda c: {"binding": c.ident(), "limit": 5, "descending": True, "through_request_id": "r2"},
        ),
    ]
    for attempt in range(4):
        steps.append(
            (
                "retry_review_events",
                lambda c, a=attempt: {"sequences": [1], "now": stamp(40 + a), "error": f"boom-{a}", **c.ident()},
            )
        )
    steps += [
        (
            "retry_review_events",
            lambda c: {"sequences": [2, 2, -1], "now": "not-a-time", "error": "x" * 40, **c.ident()},
        ),
        ("list_ready_review_events", lambda c: {"now": stamp(41), "limit": 10, **c.ident()}),
        ("list_ready_review_events", lambda c: {"now": "2030-01-01T00:00:00+00:00", "limit": 10, **c.ident()}),
        ("review_event_outbox_status", lambda c: {"now": stamp(41), **c.ident()}),
        (
            "quarantine_review_event",
            lambda c: {"sequence": 3, "reason": "invalid_payload", "error": "bad", **c.ident()},
        ),
        (
            "quarantine_review_event",
            lambda c: {"sequence": 99, "reason": "invalid_payload", "error": "bad", **c.ident()},
        ),
        ("review_event_outbox_status", lambda c: {"now": stamp(41), **c.ident()}),
        ("acknowledge_review_events", lambda c: {"sequences": [3], **c.ident()}),
        ("acknowledge_review_events", lambda c: {"sequences": [1, 2], **c.identity(**other)}),
        ("acknowledge_review_events", lambda c: {"sequences": [1, 2], **c.ident()}),
        ("review_event_outbox_status", lambda c: {"now": stamp(41), **c.ident()}),
        ("list_ready_review_events", lambda c: {"now": "2030-01-01T00:00:00+00:00", "limit": 10, **c.ident()}),
    ]
    return steps


def reassign(workspace: str, *, only_unbound: bool = False) -> dict[str, object]:
    return {"approved_source": SOURCE, "approved_workspace_id": workspace, "only_unbound": only_unbound}


def seed_unbound(ctx: Context) -> None:
    add(ctx, ["u1", "u2"])
    bind(ctx)


def scenario_unbound(ctx: Context) -> list[Step]:
    return [
        ("count_recoverable_unbound_review_events", lambda c: {}),
        ("review_event_outbox_status", lambda c: {"now": stamp(30), **c.ident()}),
        ("refresh_review_event_outbox_binding_for_identity", lambda c: c.identity(workspace_id="workspace-other")),
        ("reassign_quarantined_review_events", lambda c: reassign(WORKSPACE, only_unbound=True)),
        ("count_recoverable_unbound_review_events", lambda c: {}),
        ("refresh_review_event_outbox_binding_for_identity", lambda c: c.identity()),
        ("refresh_review_event_outbox_binding", lambda c: {}),
        ("list_ready_review_events", lambda c: {"now": stamp(30), "limit": 10, **c.ident()}),
    ]


def seed_unbound_refresh(ctx: Context) -> None:
    add(ctx, ["u1", "u2"])
    bind(ctx)


def scenario_unbound_refresh(ctx: Context) -> list[Step]:
    return [
        ("refresh_review_event_outbox_binding", lambda c: {}),
        ("reassign_quarantined_review_events", lambda c: reassign(WORKSPACE)),
        ("refresh_review_event_outbox_binding", lambda c: {}),
        ("list_pending_review_request_ids", lambda c: {"binding": c.ident(), "limit": 10}),
    ]


def seed_rebinding(ctx: Context) -> None:
    bind(ctx)
    add(ctx, ["q1", "q2"])
    bind(ctx, workspace="workspace-2")
    add(ctx, ["q3"], offset=5)


def scenario_rebinding(ctx: Context) -> list[Step]:
    return [
        ("get_review_event_oauth_binding", lambda c: {}),
        ("count_recoverable_unbound_review_events", lambda c: {}),
        ("refresh_review_event_outbox_binding", lambda c: {}),
        ("review_event_outbox_status", lambda c: {"now": stamp(30)}),
        ("reassign_quarantined_review_events", lambda c: reassign("workspace-9")),
        ("reassign_quarantined_review_events", lambda c: reassign("workspace-2", only_unbound=True)),
        ("reassign_quarantined_review_events", lambda c: reassign("workspace-2")),
        ("review_event_outbox_status", lambda c: {"now": stamp(30)}),
        ("list_ready_review_events", lambda c: {"now": stamp(30), "limit": 10, **c.ident()}),
    ]


def seed_requeue(ctx: Context) -> None:
    bind(ctx)
    add(ctx, ["p1", "p2", "p3"])
    ctx.store.acknowledge_review_events([1], **ctx.ident())


def scenario_requeue(ctx: Context) -> list[Step]:
    snapshot = ctx.store.get_raw_approval_request_snapshot("p2")
    return [
        ("requeue_pending_review_events", lambda c: {"changed_at": stamp(52), "request_ids": []}),
        (
            "requeue_pending_review_events",
            lambda c: {"changed_at": stamp(52), "request_ids": ["p2"], "request_snapshots": {"p2": snapshot}},
        ),
        ("requeue_pending_review_events", lambda c: {"changed_at": stamp(51), "request_ids": ["p3"]}),
        ("requeue_pending_review_events", lambda c: {"changed_at": stamp(50), "require_binding": True}),
        ("review_event_outbox_status", lambda c: {"now": stamp(60), **c.ident()}),
        ("list_ready_review_events", lambda c: {"now": stamp(60), "limit": 20, **c.ident()}),
    ]


def scenario_requeue_all(ctx: Context) -> list[Step]:
    return [
        ("requeue_pending_review_events", lambda c: {"changed_at": stamp(50), "require_binding": True}),
        ("requeue_pending_review_events", lambda c: {"changed_at": stamp(51)}),
        ("list_ready_review_events", lambda c: {"now": stamp(60), "limit": 20, **c.ident()}),
    ]


def scenario_requeue_repair(ctx: Context) -> list[Step]:
    return [
        ("requeue_pending_review_events", lambda c: {"changed_at": stamp(53), "snapshot_repair_sequences": {"p3": 4}}),
        ("requeue_pending_review_events", lambda c: {"changed_at": stamp(53), "snapshot_repair_sequences": {"p3": 2}}),
        ("requeue_pending_review_events", lambda c: {"changed_at": stamp(54), "snapshot_repair_sequences": {"p9": 4}}),
        ("list_ready_review_events", lambda c: {"now": stamp(60), "limit": 20, **c.ident()}),
    ]


def scenario_rebinding_identity(ctx: Context) -> list[Step]:
    return [
        ("refresh_review_event_outbox_binding_for_identity", lambda c: c.identity(machine_id="machine-other")),
        ("refresh_review_event_outbox_binding_for_identity", lambda c: c.identity()),
        ("review_event_outbox_status", lambda c: {"now": stamp(30), **c.ident()}),
    ]


def seed_decimals(ctx: Context) -> None:
    bind(ctx)
    ctx.store.add_approval_request(request("d1", DECIMALS), stamp(1))
    ctx.store.add_approval_request(request("d2"), stamp(2))


def scenario_requeue_decimals(ctx: Context) -> list[Step]:
    snapshot = ctx.store.list_review_event_snapshots("d1")[0]
    return [
        ("list_review_event_snapshots", lambda c: {"request_id": "d1"}),
        (
            "requeue_pending_review_events",
            lambda c: {"changed_at": stamp(52), "request_ids": ["d1"], "request_snapshots": {"d1": snapshot}},
        ),
        ("requeue_pending_review_events", lambda c: {"changed_at": stamp(53), "request_ids": ["d1"]}),
        ("list_review_event_snapshots", lambda c: {"request_id": "d1"}),
        ("list_ready_review_events", lambda c: {"now": stamp(60), "limit": 20, **c.ident()}),
    ]


def scenario_requeue_marker(ctx: Context) -> list[Step]:
    native = {"schema": "guard-cloud-review-native-workspace-review-request.v1", "native_replay": True, "key": "v"}
    plain = {"schema": "other.v1", "note": "caf\u00e9", "n": 3}
    return [
        (
            "requeue_pending_review_events_with_marker",
            lambda c: {
                "changed_at": stamp(54),
                "marker_key": "marker-a",
                "marker_payload": native,
                "require_binding": True,
            },
        ),
        (
            "requeue_pending_review_events_with_marker",
            lambda c: {
                "changed_at": stamp(55),
                "marker_key": "marker-a",
                "marker_payload": plain,
                "request_ids": ["p1", "p3"],
                "only_retry_identity_drift": True,
            },
        ),
        (
            "requeue_pending_review_events_with_marker",
            lambda c: {
                "changed_at": stamp(56),
                "marker_key": "marker-b",
                "marker_payload": plain,
                "request_ids": ["p3"],
            },
        ),
        ("list_ready_review_events", lambda c: {"now": stamp(60), "limit": 20, **c.ident()}),
    ]


def seed_repair(ctx: Context) -> None:
    bind(ctx)
    add(ctx, ["f1", "f2"])
    from codex_plugin_scanner.guard.review_correlation import cloud_review_correlation_id  # type: ignore

    wrong = cloud_review_correlation_id("elsewhere")
    set_continuation(
        ctx,
        "f1",
        {
            "correlationId": wrong,
            "capability": "retry-only",
            "hookAttached": False,
            "opaqueTargetId": None,
            "waitDeadline": None,
        },
    )


def scenario_repair(ctx: Context) -> list[Step]:
    return [
        (
            "repair_rejected_review_correlation",
            lambda c: {"event_sequence": 1, "binding": c.identity(workspace_id="x"), "changed_at": stamp(70)},
        ),
        (
            "repair_rejected_review_correlation",
            lambda c: {"event_sequence": 2, "binding": c.ident(), "changed_at": stamp(70)},
        ),
        (
            "repair_rejected_review_correlation",
            lambda c: {"event_sequence": 77, "binding": c.ident(), "changed_at": stamp(70)},
        ),
        (
            "repair_rejected_review_correlation",
            lambda c: {"event_sequence": 1, "binding": c.ident(), "changed_at": stamp(71)},
        ),
        (
            "repair_rejected_review_correlation",
            lambda c: {"event_sequence": 1, "binding": c.ident(), "changed_at": stamp(72)},
        ),
        ("list_review_event_snapshots", lambda c: {"request_id": "f1"}),
        ("review_event_outbox_status", lambda c: {"now": stamp(80), **c.ident()}),
    ]


def seed_recover(ctx: Context) -> None:
    bind(ctx)
    add(ctx, ["s1", "s2"])
    ctx.store.requeue_pending_review_events(changed_at=stamp(20))


def scenario_recover(ctx: Context) -> list[Step]:
    def collide(c: Context, sequences: list[int]) -> dict[str, object]:
        return {
            "collisions": {seq: c.event_id(seq) for seq in sequences},
            "acknowledged_through": 5,
            "binding": c.ident(),
        }

    return [
        ("recover_review_snapshot_sequences", lambda c: collide(c, [3])),
        ("recover_review_snapshot_sequences", lambda c: {**collide(c, [4]), "acknowledged_through": 0}),
        (
            "recover_review_snapshot_sequences",
            lambda c: {**collide(c, [3, 4]), "binding": c.identity(workspace_id="x")},
        ),
        (
            "recover_review_snapshot_sequences",
            lambda c: {"collisions": {1: "missing-event"}, "acknowledged_through": 0, "binding": c.ident()},
        ),
        ("review_event_outbox_status", lambda c: {"now": stamp(80), **c.ident()}),
    ]


SCENARIOS: list[tuple[str, Callable[[Context], None], Callable[[Context], list[Step]]]] = [
    ("empty", lambda c: None, scenario_empty),
    ("bound_lifecycle", seed_bound, scenario_bound),
    ("unbound_then_bound", seed_unbound, scenario_unbound),
    ("unbound_refresh", seed_unbound_refresh, scenario_unbound_refresh),
    ("rebinding_quarantine", seed_rebinding, scenario_rebinding),
    ("requeue", seed_requeue, scenario_requeue),
    ("requeue_decimals", seed_decimals, scenario_requeue_decimals),
    ("requeue_marker", seed_requeue, scenario_requeue_marker),
    ("requeue_all", seed_requeue, scenario_requeue_all),
    ("requeue_repair", seed_requeue, scenario_requeue_repair),
    ("rebinding_identity", seed_rebinding, scenario_rebinding_identity),
    ("repair_rejected_correlation", seed_repair, scenario_repair),
    ("recover_sequences", seed_recover, scenario_recover),
]

from __future__ import annotations

import json
import sqlite3
import urllib.request
from dataclasses import replace
from pathlib import Path

from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.daemon.approval_extension_recommendation import (
    RECOMMENDATION_SCHEMA,
    build_approval_extension_recommendation,
    with_approval_extension_recommendation,
)
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_allow_hint import EXTENSION_ALLOW_HINT_SCHEMA
from codex_plugin_scanner.guard.runtime.extension_control_authority import AuthorityHealth
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    CONTROL_SCHEMA_VERSION,
    ControlLayerKind,
    ControlState,
    ControlTarget,
    ControlTargetKind,
    ExtensionControl,
    ExtensionControlLayer,
)
from codex_plugin_scanner.guard.runtime.extension_control_runtime import ExtensionControlRuntimeSnapshot
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_approvals import (
    add_approval_request,
    approval_index_statements,
    approval_schema_statement,
    get_approval_extension_allow_hint,
    get_approval_request,
    list_approval_requests,
)

REGISTRY = BUILT_IN_COMMAND_EXTENSION_REGISTRY
GIT_ADD = "command.git.permission.add"
HARD_RESET = "command.git.permission.hard-reset"


def _hint(*permission_ids: str) -> dict[str, object]:
    permissions = [REGISTRY.permission(permission_id) for permission_id in permission_ids]
    assert all(permission is not None for permission in permissions)
    return {
        "schema": EXTENSION_ALLOW_HINT_SCHEMA,
        "permission_ids": list(permission_ids),
        "rule_ids": [permission.rule_ids[0] for permission in permissions],
        "extension_ids": sorted({permission.extension_id for permission in permissions}),
        "catalog_digest": REGISTRY.catalog_digest,
    }


def _layer(kind: ControlLayerKind, controls: tuple[tuple[ControlTargetKind, str, ControlState], ...]):
    return ExtensionControlLayer(
        schema_version=CONTROL_SCHEMA_VERSION,
        kind=kind,
        catalog_digest=REGISTRY.catalog_digest,
        global_lockdown=False,
        controls=tuple(
            sorted(
                (ExtensionControl(ControlTarget(kind_, target_id), state) for kind_, target_id, state in controls),
                key=lambda control: control.target,
            )
        ),
    )


def _snapshot(
    *,
    health: AuthorityHealth = AuthorityHealth.PROTECTED,
    local: tuple[tuple[ControlTargetKind, str, ControlState], ...] = (),
    managed: tuple[tuple[ControlTargetKind, str, ControlState], ...] = (),
) -> ExtensionControlRuntimeSnapshot:
    layers = [_layer(ControlLayerKind.LOCAL_ADMIN, local)]
    if managed:
        layers.append(_layer(ControlLayerKind.SIGNED_CLOUD, managed))
    return ExtensionControlRuntimeSnapshot(
        health=health,
        revision=7,
        catalog_digest=REGISTRY.catalog_digest,
        effective_digest="e" * 64,
        layers=tuple(layers),
    )


def _approval(hint: dict[str, object] | None, *, status: str = "pending") -> dict[str, object]:
    return {"request_id": "req-1", "status": status, "extension_allow_hint": hint}


def _request(request_id: str, *, hint: dict[str, object] | None) -> GuardApprovalRequest:
    return GuardApprovalRequest(
        request_id=request_id,
        harness="codex",
        artifact_id="codex:project:tool",
        artifact_name="tool",
        artifact_hash=f"hash-{request_id}",
        policy_action="require-reapproval",
        recommended_scope="artifact",
        changed_fields=("args",),
        source_scope="project",
        config_path="/workspace/.codex/config.toml",
        workspace="workspace-a",
        launch_target="git add src/app.py",
        action_envelope_json={
            "action_type": "shell_command",
            "tool_name": "Bash",
            "command": "git add src/app.py",
            "target_paths": [],
            "network_hosts": [],
            "mcp_server": None,
            "mcp_tool": None,
        },
        review_command=f"hol-guard approvals approve {request_id}",
        approval_url=f"http://127.0.0.1/pending/{request_id}",
        extension_allow_hint=hint,
    )


def _connection() -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.execute(approval_schema_statement())
    for statement in approval_index_statements():
        connection.execute(statement)
    return connection


def test_store_round_trips_and_refreshes_hint_on_dedupe() -> None:
    connection = _connection()
    add_approval_request(connection, _request("req-1", hint=None), "2026-10-09T10:00:00+00:00")
    assert get_approval_extension_allow_hint(connection, "req-1") is None

    add_approval_request(connection, _request("req-2", hint=_hint(GIT_ADD)), "2026-10-09T10:01:00+00:00")

    assert get_approval_extension_allow_hint(connection, "req-1") == _hint(GIT_ADD)
    stored = get_approval_request(connection, "req-1")
    assert stored is not None
    assert "extension_allow_hint" not in stored
    listed = list_approval_requests(connection)
    assert [item["request_id"] for item in listed] == ["req-1"]
    assert all("extension_allow_hint" not in item for item in listed)


def test_existing_store_gains_hint_column(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    legacy = sqlite3.connect(guard_home / "guard.db")
    legacy.row_factory = sqlite3.Row
    legacy.execute(approval_schema_statement())
    add_approval_request(legacy, _request("req-old", hint=None), "2026-10-08T10:00:00+00:00")
    # Recreate a pre-upgrade table: same row, no hint column.
    legacy.execute("alter table approval_requests drop column extension_allow_hint_json")
    legacy.commit()
    assert "extension_allow_hint_json" not in {row[1] for row in legacy.execute("pragma table_info(approval_requests)")}
    legacy.close()

    store = GuardStore(guard_home)

    with sqlite3.connect(guard_home / "guard.db") as upgraded:
        columns = {row[1] for row in upgraded.execute("pragma table_info(approval_requests)")}
    assert "extension_allow_hint_json" in columns
    preserved = store.get_approval_request("req-old")
    assert preserved is not None and preserved["launch_target"] == "git add src/app.py"
    assert store.get_approval_extension_allow_hint("req-old") is None

    # A repeat of the same action after upgrade refreshes the existing row's hint.
    store.add_approval_request(_request("req-1", hint=_hint(GIT_ADD)), "2026-10-09T10:00:00+00:00")
    assert store.get_approval_extension_allow_hint("req-old") == _hint(GIT_ADD)
    assert "extension_allow_hint" not in (store.get_approval_request("req-old") or {})


def test_available_recommendation_for_git_add() -> None:
    recommendation = build_approval_extension_recommendation(
        _approval(_hint(GIT_ADD)), registry=REGISTRY, snapshot=_snapshot()
    )

    assert recommendation is not None
    assert recommendation["schema"] == RECOMMENDATION_SCHEMA
    assert recommendation["status"] == "available"
    assert recommendation["caution"] is False
    assert recommendation["revision"] == 7
    [permission] = recommendation["permissions"]
    assert permission["permission_id"] == GIT_ADD
    assert permission["extension_id"] == "command.git"
    assert permission["rule_id"] == "command.git.add"
    assert permission["cli_command"] == f"hol-guard command controls set {GIT_ADD} --state allow"
    assert "src/app.py" not in json.dumps(recommendation)


def test_destructive_permission_carries_caution() -> None:
    recommendation = build_approval_extension_recommendation(
        _approval(_hint(HARD_RESET)), registry=REGISTRY, snapshot=_snapshot()
    )

    assert recommendation is not None
    assert recommendation["caution"] is True
    assert recommendation["permissions"][0]["caution_reason"] in {"critical", "destructive", "sensitive"}


def test_no_recommendation_when_not_applicable() -> None:
    enabled = ((ControlTargetKind.PERMISSION, GIT_ADD, ControlState.ENABLED),)
    managed_off = ((ControlTargetKind.PERMISSION, GIT_ADD, ControlState.DISABLED),)
    extension_off = ((ControlTargetKind.EXTENSION, "command.git", ControlState.DISABLED),)
    hint = _hint(GIT_ADD)

    def build(approval, snapshot):
        return build_approval_extension_recommendation(approval, registry=REGISTRY, snapshot=snapshot)

    assert build(_approval(hint), _snapshot(local=enabled)) is None
    assert build(_approval(hint), _snapshot(managed=managed_off)) is None
    assert build(_approval(hint), _snapshot(local=extension_off)) is None
    assert build(_approval(hint, status="approved"), _snapshot()) is None
    assert build(_approval({**hint, "catalog_digest": "0" * 64}), _snapshot()) is None
    assert build(_approval(None), _snapshot()) is None
    locked = _snapshot()
    locked = replace(locked, layers=(replace(locked.layers[0], global_lockdown=True),))
    assert build(_approval(hint), locked) is None


def test_relied_permission_must_still_be_enabled() -> None:
    relied = "command.git.permission.commit"
    assert REGISTRY.permission(relied) is not None
    hint = {**_hint(GIT_ADD), "relied_permission_ids": [relied]}

    def build(snapshot):
        return build_approval_extension_recommendation(_approval(hint), registry=REGISTRY, snapshot=snapshot)

    relied_on = ((ControlTargetKind.PERMISSION, relied, ControlState.ENABLED),)
    relied_off = ((ControlTargetKind.PERMISSION, relied, ControlState.DISABLED),)
    assert build(_snapshot(local=relied_on)) is not None
    assert build(_snapshot(managed=relied_on)) is not None
    assert build(_snapshot()) is None
    assert build(_snapshot(local=relied_on, managed=relied_off)) is None
    legacy = build_approval_extension_recommendation(_approval(_hint(GIT_ADD)), registry=REGISTRY, snapshot=_snapshot())
    assert legacy is not None


def test_unhealthy_authority_reports_unavailable() -> None:
    recommendation = build_approval_extension_recommendation(
        _approval(_hint(GIT_ADD)), registry=REGISTRY, snapshot=_snapshot(health=AuthorityHealth.TAMPERED)
    )

    assert recommendation is not None
    assert recommendation["status"] == "authority_unavailable"


def test_enrichment_strips_hint_and_respects_include() -> None:
    approval = _approval(_hint(GIT_ADD))

    enriched = with_approval_extension_recommendation(approval, registry=REGISTRY, snapshot=_snapshot(), include=True)
    hidden = with_approval_extension_recommendation(approval, registry=REGISTRY, snapshot=_snapshot(), include=False)

    assert "extension_allow_hint" not in enriched
    assert enriched["extension_recommendation"]["permissions"][0]["permission_id"] == GIT_ADD
    assert "extension_allow_hint" not in hidden
    assert "extension_recommendation" not in hidden


def _get_json(port: int, path: str, *, token: str) -> dict[str, object]:
    request = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers={"X-Guard-Token": token}, method="GET")
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def test_daemon_request_detail_includes_recommendation(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    store.add_approval_request(_request("req-1", hint=_hint(GIT_ADD)), "2026-10-09T10:00:00+00:00")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        detail = _get_json(daemon.port, "/v1/requests/req-1", token=daemon._server.auth_token)
    finally:
        daemon.stop()

    assert "extension_allow_hint" not in detail
    recommendation = detail["extension_recommendation"]
    assert recommendation["schema"] == RECOMMENDATION_SCHEMA
    assert recommendation["status"] in {"available", "authority_unavailable"}
    assert [item["permission_id"] for item in recommendation["permissions"]] == [GIT_ADD]

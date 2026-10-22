from __future__ import annotations

import json
import sqlite3
import urllib.request
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.daemon import approval_extension_recommendation as recommendation_module
from codex_plugin_scanner.guard.daemon.approval_extension_recommendation import RECOMMENDATION_SCHEMA
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_allow_hint import EXTENSION_ALLOW_HINT_SCHEMA
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_approvals import (
    get_approval_request,
    list_approval_requests,
)
from tests.native_approval_writes import add_approval_request, native_approval_connection

REGISTRY = BUILT_IN_COMMAND_EXTENSION_REGISTRY
GIT_ADD = "command.git.permission.add"


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
    return native_approval_connection()


def _stored_hint(connection: sqlite3.Connection, request_id: str) -> object:
    row = connection.execute(
        "select extension_allow_hint_json from approval_requests where request_id = ?", (request_id,)
    ).fetchone()
    return json.loads(row[0]) if row is not None and row[0] is not None else None


def test_store_round_trips_and_refreshes_hint_on_dedupe() -> None:
    connection = _connection()
    add_approval_request(connection, _request("req-1", hint=None), "2026-10-09T10:00:00+00:00")
    assert _stored_hint(connection, "req-1") is None

    add_approval_request(connection, _request("req-2", hint=_hint(GIT_ADD)), "2026-10-09T10:01:00+00:00")

    assert _stored_hint(connection, "req-1") == _hint(GIT_ADD)
    stored = get_approval_request(connection, "req-1")
    assert stored is not None
    assert "extension_allow_hint" not in stored
    listed = list_approval_requests(connection)
    assert [item["request_id"] for item in listed] == ["req-1"]
    assert all("extension_allow_hint" not in item for item in listed)


def test_existing_store_gains_hint_column(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    GuardStore(guard_home).add_approval_request(_request("req-old", hint=None), "2026-10-08T10:00:00+00:00")
    legacy = sqlite3.connect(guard_home / "guard.db")
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


def _get_json(port: int, path: str, *, token: str) -> dict[str, object]:
    request = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers={"X-Guard-Token": token}, method="GET")
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def _resident_recommends(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, object]]:
    """Answer each recommendation ask as the resident would for an applicable hint.

    Whether a hint applies is the resident's decision, pinned by its own tests
    and by the client tests; here only the daemon's read path is under test.
    """

    asked: list[dict[str, object]] = []

    def decide(query, guard_home, _fields, validate, **_kwargs):
        asked.append({"query": query, "guard_home": guard_home})
        permission_id = query["hint"]["permission_ids"][0]
        validate(
            {
                "kind": query["kind"],
                "recommendation": {
                    "schema": RECOMMENDATION_SCHEMA,
                    "status": "available",
                    "permissions": [
                        {
                            "permission_id": permission_id,
                            "label": "Git add",
                            "description": None,
                            "example_command": None,
                            "extension_id": "command.git",
                            "extension_name": None,
                            "rule_id": query["hint"]["rule_ids"][0],
                            "risk_tier": "low",
                            "caution": False,
                            "caution_reason": None,
                            "caution_detail": None,
                            "cli_command": f"hol-guard command controls set {permission_id} --state allow",
                        }
                    ],
                    "caution": False,
                    "revision": query["snapshot"]["revision"],
                    "catalog_digest": query["snapshot"]["catalog_digest"],
                },
            }
        )
        return {}

    monkeypatch.setattr(recommendation_module, "_decide", decide)
    return asked


def test_daemon_request_detail_includes_recommendation(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    asked = _resident_recommends(monkeypatch)
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
    # The resident of the daemon's own home is the one asked.
    assert [entry["guard_home"] for entry in asked] == [store.guard_home]


def test_daemon_request_detail_computes_live_recommendation_for_legacy_pending_row(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from codex_plugin_scanner.guard.daemon import native_review_allow_hint

    _resident_recommends(monkeypatch)
    store = GuardStore(tmp_path / "guard-home")
    store.add_approval_request(_request("req-legacy", hint=None), "2026-10-09T10:00:00+00:00")
    monkeypatch.setattr(
        native_review_allow_hint,
        "live_approval_extension_allow_hint",
        lambda approval, **_kwargs: _hint(GIT_ADD) if approval.get("request_id") == "req-legacy" else None,
    )
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        detail = _get_json(daemon.port, "/v1/requests/req-legacy", token=daemon._server.auth_token)
    finally:
        daemon.stop()

    assert "extension_allow_hint" not in detail
    recommendation = detail["extension_recommendation"]
    assert recommendation["schema"] == RECOMMENDATION_SCHEMA
    assert [item["permission_id"] for item in recommendation["permissions"]] == [GIT_ADD]


def test_daemon_request_detail_without_a_resident_answer_lists_the_request_without_advice(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def refused(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise recommendation_module.NativeApprovalExtensionRecommendationError(
            "native_approval_extension_recommendation_unavailable"
        )

    monkeypatch.setattr(recommendation_module, "_decide", refused)
    store = GuardStore(tmp_path / "guard-home")
    store.add_approval_request(_request("req-1", hint=_hint(GIT_ADD)), "2026-10-09T10:00:00+00:00")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        detail = _get_json(daemon.port, "/v1/requests/req-1", token=daemon._server.auth_token)
    finally:
        daemon.stop()

    assert detail["request_id"] == "req-1"
    assert "extension_allow_hint" not in detail and "extension_recommendation" not in detail

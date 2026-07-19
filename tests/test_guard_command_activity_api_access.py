"""Daemon authentication, CORS, cursor, and SSE tests for command activity."""

# pyright: reportAny=false, reportArgumentType=false, reportGeneralTypeIssues=false
# pyright: reportIndexIssue=false, reportPrivateUsage=false, reportUnknownArgumentType=false
# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnusedCallResult=false

from __future__ import annotations

import base64
import json
import urllib.parse
import urllib.request
from pathlib import Path

from codex_plugin_scanner.guard.daemon.command_activity_api import stream_command_activity_events
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.local_dashboard_session import build_local_dashboard_session_token
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_command_activity_api_support import json_request, raw_request, seed


def _dashboard_token(daemon: GuardDaemonServer, *, surface: str = "dashboard", **claims: object) -> str:
    return build_local_dashboard_session_token(
        auth_token=daemon._server.auth_token,
        surface=surface,
        extra_claims=dict(claims),
    )


def test_activity_routes_require_auth_and_exact_hosted_origin(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    seed(store)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token(daemon)
        unauthenticated, _, _ = json_request(daemon, "/v1/command-activity")
        allowed, payload, headers = json_request(
            daemon,
            "/v1/command-activity",
            token=token,
            origin="https://hol.org",
        )
        forbidden, body, _ = json_request(
            daemon,
            "/v1/command-activity",
            token=token,
            origin="https://attacker.example",
        )
    finally:
        daemon.stop()

    assert unauthenticated == 401
    assert allowed == 200
    assert len(payload["items"]) == 3
    assert headers["Access-Control-Allow-Origin"] == "https://hol.org"
    assert forbidden == 403
    assert body == {"error": "forbidden_origin"}


def test_dashboard_session_scope_is_an_exact_path_allowlist(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    seed(store)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        scoped = _dashboard_token(
            daemon,
            surface="command-action",
            action_path="command_activity_read",
            allowed_read_paths=["/v1/command-activity"],
        )
        allowed, _, _ = json_request(daemon, "/v1/command-activity", token=scoped)
        analytics, _, _ = json_request(daemon, "/v1/command-activity/analytics", token=scoped)
        feedback, _, _ = json_request(
            daemon,
            "/v1/command-activity/feedback",
            method="POST",
            token=scoped,
            payload={"activity_id": "activity:01", "label": "should_not_have_interrupted"},
        )
    finally:
        daemon.stop()

    assert allowed == 200
    assert analytics == 401
    assert feedback == 401


def test_signed_cursor_rejects_tampering_and_filter_rebinding(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    seed(store)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token(daemon)
        status, first, _ = json_request(daemon, "/v1/command-activity?limit=2", token=token)
        cursor = str(first["next_cursor"])
        second_status, second, _ = json_request(
            daemon,
            f"/v1/command-activity?limit=2&cursor={urllib.parse.quote(cursor)}",
            token=token,
        )
        prefix, encoded, signature = cursor.split(".")
        decoded_signature = base64.urlsafe_b64decode(signature + "=")
        alias = next(
            candidate
            for character in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
            if (candidate := signature[:-1] + character) != signature
            and base64.urlsafe_b64decode(candidate + "=") == decoded_signature
        )
        tampered = f"{prefix}.{encoded}.{alias}"
        tampered_status, tampered_body, _ = json_request(
            daemon,
            f"/v1/command-activity?limit=2&cursor={urllib.parse.quote(tampered)}",
            token=token,
        )
        rebound_status, rebound_body, _ = json_request(
            daemon,
            f"/v1/command-activity?limit=2&prompted=true&cursor={urllib.parse.quote(cursor)}",
            token=token,
        )
    finally:
        daemon.stop()

    assert status == 200
    assert [item["activity_id"] for item in second["items"]] == ["activity:01"]
    assert second_status == 200
    assert tampered_status == 400
    assert tampered_body == {"error": "invalid_cursor"}
    assert rebound_status == 400
    assert rebound_body == {"error": "invalid_cursor"}


def test_query_and_feedback_payloads_fail_closed(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    seed(store)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token(daemon)
        cases = [
            "/v1/command-activity?limit=101",
            "/v1/command-activity?limit=1&limit=2",
            "/v1/command-activity?unknown=value",
            "/v1/command-activity?prompted=1",
            "/v1/command-activity/analytics?days=398",
            "/v1/command-activity/analytics?dimension=harness",
            "/v1/command-extensions?limit=101",
            "/v1/command-activity?cursor=" + "x" * 2_049,
            "/v1/command-activity?extension_id=" + "a" * 8_193,
            "/v1/command-activity/events?cursor=invalid",
            "/v1/command-activity/events?cursor=0&cursor=1",
        ]
        statuses = [json_request(daemon, path, token=token)[0] for path in cases]
        invalid_feedback = json_request(
            daemon,
            "/v1/command-activity/feedback",
            method="POST",
            token=token,
            payload={
                "activity_id": "activity:01",
                "label": "should_not_have_interrupted",
                "notes": "free form must never be accepted",
            },
        )
        missing_feedback = json_request(
            daemon,
            "/v1/command-activity/feedback",
            method="POST",
            token=token,
            payload={"activity_id": "activity:missing", "label": "expected_guard_to_stop_this"},
        )
        valid_feedback = json_request(
            daemon,
            "/v1/command-activity/feedback",
            method="POST",
            token=token,
            payload={"activity_id": "activity:01", "label": "expected_guard_to_stop_this"},
        )
    finally:
        daemon.stop()

    assert statuses == [400] * len(cases)
    assert invalid_feedback[:2] == (400, {"error": "invalid_feedback_payload"})
    assert missing_feedback[:2] == (404, {"error": "activity_not_found"})
    assert valid_feedback[0] == 200
    assert valid_feedback[1]["label"] == "expected_guard_to_stop_this"


def test_analytics_and_extensions_are_paginated_bounded_contracts(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    seed(store)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token(daemon)
        analytics_status, analytics, _ = json_request(
            daemon,
            "/v1/command-activity/analytics?days=7&dimension=harness&dimension_value=codex",
            token=token,
        )
        first_status, first, _ = json_request(daemon, "/v1/command-extensions?limit=2", token=token)
        cursor = urllib.parse.quote(str(first["next_cursor"]))
        second_status, second, _ = json_request(
            daemon,
            f"/v1/command-extensions?limit=2&cursor={cursor}",
            token=token,
        )
    finally:
        daemon.stop()

    assert analytics_status == 200
    assert analytics["commands_checked"] == 3
    assert analytics["scope"] == {"dimension": "harness", "dimension_value": "codex"}
    assert first_status == second_status == 200
    assert len(first["items"]) == len(second["items"]) == 2
    first_extension_ids = [str(item["extension_id"]) for item in first["items"]]
    second_extension_ids = [str(item["extension_id"]) for item in second["items"]]
    extension_ids = first_extension_ids + second_extension_ids
    assert extension_ids == sorted(extension_ids)
    assert {item["extension_id"] for item in first["items"]}.isdisjoint(
        {item["extension_id"] for item in second["items"]}
    )
    serialized = json.dumps(first)
    assert "reference_urls" not in serialized
    assert "project_markers" not in serialized


def test_sse_emits_only_invalidation_type_and_activity_id(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    seed(store)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    response = None
    try:
        token = _dashboard_token(daemon)
        query_token_status, _, _ = json_request(
            daemon,
            "/v1/command-activity/events?token=forbidden",
            token=token,
        )
        response = urllib.request.urlopen(
            raw_request(
                daemon,
                "/v1/command-activity/events?cursor=0",
                token=token,
                origin="https://hol.org",
            ),
            timeout=5,
        )
        event_id = response.readline().decode("utf-8").strip()
        data_line = response.readline().decode("utf-8").strip()
        payload = json.loads(data_line.removeprefix("data: "))
    finally:
        if response is not None:
            response.close()
        daemon.stop()

    assert daemon._server.active_stream_clients == 0
    assert query_token_status == 401
    assert event_id.startswith("id: ")
    assert payload == {"event": "command_activity_invalidated", "activity_id": "activity:01"}
    assert set(payload) == {"event", "activity_id"}


def test_sse_last_event_id_resumes_without_replay(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    seed(store)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    response = None
    try:
        token = _dashboard_token(daemon)
        response = urllib.request.urlopen(
            raw_request(
                daemon,
                "/v1/command-activity/events?cursor=0",
                token=token,
                last_event_id="2",
            ),
            timeout=5,
        )
        event_id = response.readline().decode("utf-8").strip()
        data_line = response.readline().decode("utf-8").strip()
        payload = json.loads(data_line.removeprefix("data: "))
    finally:
        if response is not None:
            response.close()
        daemon.stop()

    assert event_id == "id: 3"
    assert payload == {"event": "command_activity_invalidated", "activity_id": "activity:03"}


def test_sse_retention_gap_emits_reset_before_retained_events(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    seed(store)
    with store._connect() as connection:
        connection.execute("delete from command_activity_invalidations where sequence = 1")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    response = None
    try:
        token = _dashboard_token(daemon)
        response = urllib.request.urlopen(
            raw_request(daemon, "/v1/command-activity/events?cursor=0", token=token),
            timeout=5,
        )
        reset_id = response.readline().decode("utf-8").strip()
        reset_event = response.readline().decode("utf-8").strip()
        reset_data = response.readline().decode("utf-8").strip()
        reset_payload = json.loads(reset_data.removeprefix("data: "))
    finally:
        if response is not None:
            response.close()
        daemon.stop()

    assert reset_id == "id: 1"
    assert reset_event == "event: command_activity_reset"
    assert reset_payload == {"event": "command_activity_reset", "reset_required": True}


def test_sse_admission_is_capped(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    seed(store)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token(daemon)
        with daemon._server.active_stream_clients_lock:
            daemon._server.active_stream_clients = 8
        status, payload, _ = json_request(
            daemon,
            "/v1/command-activity/events?cursor=0",
            token=token,
        )
    finally:
        with daemon._server.active_stream_clients_lock:
            daemon._server.active_stream_clients = 0
        daemon.stop()

    assert status == 429
    assert payload == {"error": "too_many_streams"}


def test_sse_header_failure_releases_admission_slot() -> None:
    class FailingHeaderHandler:
        active: int = 0

        def _try_increment_active_stream_clients(self, maximum: int) -> bool:
            assert maximum == 8
            self.active += 1
            return True

        def _decrement_active_stream_clients(self) -> None:
            self.active -= 1

        def _write_json(self, payload: dict[str, object], *, status: int = 200) -> None:
            raise AssertionError((payload, status))

        def send_response(self, code: int, message: str | None = None) -> None:
            raise ConnectionResetError((code, message))

    handler = FailingHeaderHandler()
    try:
        stream_command_activity_events(handler, 0)
    except ConnectionResetError:
        pass
    else:
        raise AssertionError("header failure did not propagate")
    assert handler.active == 0

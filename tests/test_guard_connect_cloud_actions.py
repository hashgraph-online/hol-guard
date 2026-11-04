"""Cloud actions choice made during hol-guard connect (no separate sign-in)."""

from __future__ import annotations

import io
import urllib.parse
from pathlib import Path
from typing import Literal

import pytest
from rich.console import Console

from codex_plugin_scanner.cli import _build_parser
from codex_plugin_scanner.guard.cli import commands as guard_commands
from codex_plugin_scanner.guard.cli import commands_support_connect, connect_flow
from codex_plugin_scanner.guard.cli.connect_cloud_actions import (
    CloudActionsConnectReport,
    check_connect_cloud_actions_declined,
    check_connect_cloud_workspace,
    cloud_actions_connect_summary,
    connect_status_cloud_actions,
    parse_cloud_actions_connect_report,
    read_cloud_actions_connect_report,
    record_cloud_actions_connect_report,
)
from codex_plugin_scanner.guard.cli.render import _render_connect
from codex_plugin_scanner.guard.store import GuardStore

WORKSPACE_ID = "6f1c2a52-6a4e-4b8e-9f0e-3f3d6c1b2a10"
OTHER_WORKSPACE_ID = "0b6e7f8a-1c2d-4e3f-8a9b-0c1d2e3f4a5b"
NOW = "2026-11-03T16:00:00+00:00"
TEST_ACCESS_VALUE = "x"


def _authorize_query(
    *, cloud_workspace_id: str | None = None, cloud_actions_declined: bool = False
) -> dict[str, list[str]]:
    url = connect_flow._build_browser_authorize_url(
        authorize_endpoint="https://hol.org/api/guard/oauth/authorize",
        client_id="guard-local-daemon",
        redirect_uri="http://127.0.0.1:50000/callback",
        state="state",
        code_challenge="challenge",
        machine_id="machine-1",
        machine_label="Laptop",
        cloud_workspace_id=cloud_workspace_id,
        cloud_actions_declined=cloud_actions_declined,
    )
    return urllib.parse.parse_qs(urllib.parse.urlparse(url).query)


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        ({"guard_cloud_actions": {"status": "on", "workspace_id": WORKSPACE_ID}}, "on"),
        ({"guard_cloud_actions": {"status": "off", "workspace_id": WORKSPACE_ID}}, "off"),
        ({}, None),
        ({"guard_cloud_actions": {"status": "maybe"}}, None),
        ({"guard_cloud_actions": "on"}, None),
    ],
)
def test_token_response_reports_cloud_actions_only_when_guard_cloud_answers(
    payload: dict[str, object], expected: str | None
) -> None:
    report = parse_cloud_actions_connect_report(payload)

    assert (report["status"] if report is not None else None) == expected


def test_token_exchange_result_carries_cloud_actions_report() -> None:
    result = connect_flow._parse_guard_token_exchange_payload(
        {
            "access_token": TEST_ACCESS_VALUE,
            "token_type": "Bearer",
            "expires_in": 300,
            "guard_cloud_actions": {"status": "on", "workspace_id": WORKSPACE_ID},
        }
    )

    assert result.cloud_actions == {"status": "on", "workspace_id": WORKSPACE_ID}


def test_plain_connect_authorize_url_has_no_cloud_actions_hints() -> None:
    query = _authorize_query()

    assert "workspace_id" not in query
    assert "cloud_actions" not in query


def test_connect_authorize_url_carries_cloud_workspace_and_decline() -> None:
    query = _authorize_query(cloud_workspace_id=WORKSPACE_ID, cloud_actions_declined=True)

    assert query["workspace_id"] == [WORKSPACE_ID]
    assert query["cloud_actions"] == ["off"]


def test_device_request_sends_decline_only_when_asked() -> None:
    def body(declined: bool) -> dict[str, list[str]]:
        return urllib.parse.parse_qs(
            connect_flow.build_device_authorization_request_body(
                machine_id="machine-1",
                machine_label="Laptop",
                runtime_id="hol-guard",
                runtime_label="HOL Guard CLI",
                client_id="guard-local-daemon",
                cloud_actions_declined=declined,
            )
        )

    assert "cloud_actions" not in body(False)
    assert body(True)["cloud_actions"] == ["off"]


def test_connect_summary_separates_pairing_from_cloud_actions() -> None:
    on = cloud_actions_connect_summary({"status": "on", "workspace_id": WORKSPACE_ID}, paired=True)
    off = cloud_actions_connect_summary({"status": "off", "workspace_id": WORKSPACE_ID}, paired=True)
    unknown = cloud_actions_connect_summary(None, paired=True)
    unpaired = cloud_actions_connect_summary({"status": "on", "workspace_id": WORKSPACE_ID}, paired=False)

    assert on["status"] == "on"
    assert "hol-guard cloud-actions ai-tools configure" in on["message"]
    assert off["status"] == "off"
    assert "hol-guard connect" in off["message"]
    assert unknown["status"] == "unknown"
    assert unpaired["status"] == "off"
    assert "not paired" in unpaired["message"]
    for summary in (on, off, unknown, unpaired):
        assert "cloud-actions login" not in summary["message"]


def test_connect_reports_wrong_workspace_and_ignored_decline() -> None:
    on_report: CloudActionsConnectReport = {"status": "on", "workspace_id": WORKSPACE_ID}

    wrong_workspace = check_connect_cloud_workspace(workspace_id=OTHER_WORKSPACE_ID, cloud_workspace_id=WORKSPACE_ID)
    matched = check_connect_cloud_workspace(workspace_id=WORKSPACE_ID.upper(), cloud_workspace_id=WORKSPACE_ID)
    unrequested = check_connect_cloud_workspace(workspace_id=OTHER_WORKSPACE_ID, cloud_workspace_id=None)
    ignored_decline = check_connect_cloud_actions_declined(report=on_report, cloud_actions_declined=True)
    honored_decline = check_connect_cloud_actions_declined(
        report={"status": "off", "workspace_id": WORKSPACE_ID}, cloud_actions_declined=True
    )
    not_declined = check_connect_cloud_actions_declined(report=on_report, cloud_actions_declined=False)

    assert wrong_workspace is not None and OTHER_WORKSPACE_ID in wrong_workspace
    assert matched is None and unrequested is None
    assert ignored_decline is not None and "--no-cloud-actions" in ignored_decline
    assert honored_decline is None and not_declined is None


def test_connect_checks_disconnect_the_computer_without_the_native_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard.mdm import runtime_request

    monkeypatch.setattr(runtime_request, "runtime_answer", lambda *_, **__: None)
    on: CloudActionsConnectReport = {"status": "on", "workspace_id": WORKSPACE_ID}

    assert parse_cloud_actions_connect_report({"guard_cloud_actions": on}) is None
    assert cloud_actions_connect_summary(on, paired=True)["status"] == "unknown"
    assert check_connect_cloud_workspace(workspace_id=WORKSPACE_ID, cloud_workspace_id=WORKSPACE_ID)
    assert check_connect_cloud_actions_declined(report=on, cloud_actions_declined=True)
    assert check_connect_cloud_workspace(workspace_id=WORKSPACE_ID, cloud_workspace_id=None) is None
    assert check_connect_cloud_actions_declined(report=on, cloud_actions_declined=False) is None


def test_connect_answer_is_kept_per_pairing(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")

    record_cloud_actions_connect_report(
        store,
        grant_id="grant-1",
        report={"status": "on", "workspace_id": WORKSPACE_ID},
        now=NOW,
    )

    assert read_cloud_actions_connect_report(store, grant_id="grant-1") == {
        "status": "on",
        "workspace_id": WORKSPACE_ID,
    }
    assert read_cloud_actions_connect_report(store, grant_id="grant-2") is None
    assert read_cloud_actions_connect_report(store, grant_id=None) is None

    record_cloud_actions_connect_report(store, grant_id="grant-1", report=None, now=NOW)

    assert read_cloud_actions_connect_report(store, grant_id="grant-1") is None


def test_connect_status_reads_answer_only_for_the_current_healthy_pairing(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    record_cloud_actions_connect_report(
        store,
        grant_id="grant-1",
        report={"status": "on", "workspace_id": WORKSPACE_ID},
        now=NOW,
    )

    current = connect_status_cloud_actions(store, oauth_storage_health={"state": "healthy", "grant_id": "grant-1"})
    replaced = connect_status_cloud_actions(store, oauth_storage_health={"state": "healthy", "grant_id": "grant-2"})
    degraded = connect_status_cloud_actions(store, oauth_storage_health={"state": "degraded", "grant_id": "grant-1"})

    assert current["status"] == "on"
    assert replaced["status"] == "unknown"
    assert degraded["status"] == "off"


def test_connect_output_shows_cloud_actions_row() -> None:
    output = io.StringIO()
    console = Console(file=output, width=200, color_system=None)

    _render_connect(
        console,
        {
            "status": "connected",
            "cloud_actions": cloud_actions_connect_summary({"status": "on", "workspace_id": WORKSPACE_ID}, paired=True),
        },
    )

    rendered = output.getvalue()
    assert "Cloud actions" in rendered
    assert "hol-guard cloud-actions ai-tools configure" in rendered


def test_connect_parser_accepts_cloud_actions_choices(tmp_path: Path) -> None:
    parser = _build_parser("hol-guard", program_mode="guard")

    args = parser.parse_args(
        [
            "connect",
            "--home",
            str(tmp_path / "guard-home"),
            "--cloud-workspace",
            WORKSPACE_ID,
            "--no-cloud-actions",
        ]
    )
    plain = parser.parse_args(["connect", "--home", str(tmp_path / "guard-home")])

    assert args.cloud_workspace == WORKSPACE_ID
    assert args.no_cloud_actions is True
    assert plain.cloud_workspace is None
    assert plain.no_cloud_actions is False


def test_connect_rejects_folder_as_cloud_workspace(tmp_path: Path, capsys) -> None:
    parser = _build_parser("hol-guard", program_mode="guard")

    with pytest.raises(SystemExit) as raised:
        parser.parse_args(["connect", "--home", str(tmp_path / "guard-home"), "--cloud-workspace", "./my-project"])

    assert raised.value.code == 2
    assert "looks like a folder" in capsys.readouterr().err


def _connected_payload(*, workspace_id: str, cloud_actions_status: Literal["on", "off"]) -> dict[str, object]:
    return {
        "status": "connected",
        "connect_mode": "browser_oauth",
        "workspace_id": workspace_id,
        "cloud_actions": cloud_actions_connect_summary(
            {"status": cloud_actions_status, "workspace_id": workspace_id},
            paired=True,
        ),
    }


def test_browser_connect_undoes_pairing_to_wrong_workspace_before_first_sync(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    seen: dict[str, object] = {}
    disconnects: list[dict[str, object]] = []

    def fake_browser_flow(**kwargs: object) -> dict[str, object]:
        seen.update(kwargs)
        return _connected_payload(workspace_id=OTHER_WORKSPACE_ID, cloud_actions_status="off")

    def fail_finalize(**kwargs: object) -> dict[str, object]:
        raise AssertionError("first sync must not run for the wrong workspace")

    def fake_disconnect(**kwargs: object) -> dict[str, object]:
        disconnects.append(kwargs)
        return {"status": "disconnected", "cloud_grant_revoked": True}

    monkeypatch.setattr(guard_commands, "_run_guard_browser_connect_flow", fake_browser_flow)
    monkeypatch.setattr(commands_support_connect, "_finalize_guard_connect_payload", fail_finalize)
    monkeypatch.setattr(guard_commands, "run_guard_disconnect_command", fake_disconnect)

    payload, exit_code = guard_commands._build_guard_device_connect_payload(
        store=GuardStore(tmp_path / "guard-home"),
        connect_url="https://hol.org/guard/connect",
        use_browser_oauth=True,
        cloud_workspace_id=WORKSPACE_ID,
        cloud_actions_declined=True,
    )

    assert seen["cloud_workspace_id"] == WORKSPACE_ID
    assert seen["cloud_actions_declined"] is True
    assert exit_code == 1
    assert payload is not None and payload["status"] == "disconnected"
    assert len(disconnects) == 1 and disconnects[0]["revoke_cloud_grant"] is True
    assert OTHER_WORKSPACE_ID in str(payload["cloud_actions_problem"])
    assert OTHER_WORKSPACE_ID in capsys.readouterr().err
    assert payload["cloud_actions"]["status"] == "off"


def test_headless_connect_undoes_the_pairing_when_cloud_actions_came_back_on_despite_decline(
    tmp_path: Path, monkeypatch
) -> None:
    seen: dict[str, object] = {}
    disconnects: list[dict[str, object]] = []

    def fake_device_flow(**kwargs: object) -> dict[str, object]:
        seen.update(kwargs)
        return _connected_payload(workspace_id=WORKSPACE_ID, cloud_actions_status="on")

    def fail_finalize(**kwargs: object) -> dict[str, object]:
        raise AssertionError("first sync must not run when Cloud actions were declined")

    def fake_disconnect(**kwargs: object) -> dict[str, object]:
        disconnects.append(kwargs)
        return {"status": "disconnected", "cloud_grant_revoked": True}

    monkeypatch.setattr(guard_commands, "_run_guard_device_connect_flow", fake_device_flow)
    monkeypatch.setattr(commands_support_connect, "_finalize_guard_connect_payload", fail_finalize)
    monkeypatch.setattr(guard_commands, "run_guard_disconnect_command", fake_disconnect)

    payload, exit_code = guard_commands._build_guard_device_connect_payload(
        store=GuardStore(tmp_path / "guard-home"),
        connect_url="https://hol.org/guard/connect",
        use_browser_oauth=False,
        cloud_actions_declined=True,
    )

    assert seen["cloud_actions_declined"] is True
    assert "cloud_workspace_id" not in seen
    assert exit_code == 1
    assert payload is not None and payload["status"] == "disconnected"
    assert len(disconnects) == 1 and disconnects[0]["revoke_cloud_grant"] is True
    assert "--no-cloud-actions" in str(payload["cloud_actions_problem"])
    assert payload["cloud_actions"]["status"] == "off"
    assert "not paired" in payload["cloud_actions"]["message"]


def test_plain_connect_keeps_its_flow_call_and_succeeds(tmp_path: Path, monkeypatch) -> None:
    seen: dict[str, object] = {}

    def fake_browser_flow(**kwargs: object) -> dict[str, object]:
        seen.update(kwargs)
        return _connected_payload(workspace_id=WORKSPACE_ID, cloud_actions_status="on")

    monkeypatch.setattr(guard_commands, "_run_guard_browser_connect_flow", fake_browser_flow)
    monkeypatch.setattr(commands_support_connect, "_finalize_guard_connect_payload", lambda **kwargs: kwargs["payload"])

    payload, exit_code = guard_commands._build_guard_device_connect_payload(
        store=GuardStore(tmp_path / "guard-home"),
        connect_url="https://hol.org/guard/connect",
        use_browser_oauth=True,
    )

    assert set(seen) == {"store", "connect_url", "wait_timeout_seconds"}
    assert exit_code == 0
    assert payload is not None and "cloud_actions_problem" not in payload


@pytest.mark.parametrize("error", [TimeoutError("timed out"), ConnectionResetError("reset")])
def test_undoing_a_pairing_clears_it_here_when_the_revoke_answer_never_arrives(
    tmp_path: Path, monkeypatch, error: OSError
) -> None:
    cleared: list[bool] = []

    def failing_disconnect(**kwargs: object) -> dict[str, object]:
        raise error

    monkeypatch.setattr(commands_support_connect, "run_guard_disconnect_command", failing_disconnect)
    store = GuardStore(tmp_path / "guard-home")
    monkeypatch.setattr(store, "clear_oauth_local_credentials", lambda: cleared.append(True))

    result = commands_support_connect._undo_unwanted_guard_connect_pairing(store)

    assert cleared == [True]
    assert result["status"] == "disconnected" and result["cloud_grant_revoked"] is False

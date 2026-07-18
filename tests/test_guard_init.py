"""Focused Guard init regressions."""

from __future__ import annotations

import json

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.cli import commands as guard_commands_module


def test_guard_init_cloud_step_uses_connect_browser_open_and_finalization(tmp_path, capsys, monkeypatch) -> None:
    home_dir = tmp_path / "home"
    guard_home = tmp_path / "guard-home"
    opened_urls: list[str] = []

    monkeypatch.setattr(
        guard_commands_module,
        "ensure_guard_daemon",
        lambda _guard_home: "http://127.0.0.1:5474",
    )
    monkeypatch.setattr(
        guard_commands_module,
        "_open_approval_center",
        lambda approval_center_url, *, store, config, open_key=None, force_open=False: {
            "opened": True,
            "reason": "opened",
            "browser_url": f"{approval_center_url}/home",
        },
    )

    def fake_connect(
        *,
        store,
        connect_url,
        wait_timeout_seconds=180,
        announce_copy=None,
        open_browser=None,
        ci_safe=False,
        machine_label=None,
    ) -> dict[str, object]:
        del store, connect_url, ci_safe, machine_label
        if open_browser is None:
            pytest.fail("init cloud step should open the device approval page")
        return {
            "status": "connected",
            "connect_mode": "device_code",
            "browser_opened": bool(open_browser("https://hol.org/guard/oauth/device")),
            "user_code": "ABCD-EFGH",
            "verification_uri": "https://hol.org/guard/oauth/device",
            "wait_timeout_seconds": wait_timeout_seconds,
            "announce_copy_present": announce_copy is not None,
        }

    monkeypatch.setattr(guard_commands_module, "_run_guard_device_connect_flow", fake_connect)
    monkeypatch.setattr(guard_commands_module.webbrowser, "open", lambda url: opened_urls.append(url) or True)
    monkeypatch.setattr(
        guard_commands_module,
        "apply_managed_install",
        lambda *_args, **_kwargs: pytest.fail("install should be skipped"),
    )
    monkeypatch.setattr(
        guard_commands_module,
        "ensure_desktop_notification_setup",
        lambda *_args, **_kwargs: pytest.fail("notification setup should be skipped"),
    )

    rc = main(
        [
            "guard",
            "init",
            "--yes",
            "--skip-apps",
            "--skip-notifications",
            "--skip-tray",
            "--wait-timeout-seconds",
            "11",
            "--home",
            str(home_dir),
            "--guard-home",
            str(guard_home),
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert opened_urls == ["https://hol.org/guard/oauth/device"]
    assert output["cloud"]["browser_opened"] is True
    assert output["cloud"]["wait_timeout_seconds"] == 11
    assert output["cloud"]["announce_copy_present"] is False
    assert output["cloud"]["status"] == "retry_required"
    assert output["cloud"]["milestone"] == "first_sync_failed"
    assert "sync_attempted" not in output["cloud"]


def test_guard_init_human_cloud_step_announces_approval_before_waiting(tmp_path, capsys, monkeypatch) -> None:
    home_dir = tmp_path / "home"
    guard_home = tmp_path / "guard-home"
    opened_urls: list[str] = []

    monkeypatch.setattr(
        guard_commands_module,
        "ensure_guard_daemon",
        lambda _guard_home: "http://127.0.0.1:5474",
    )
    monkeypatch.setattr(
        guard_commands_module,
        "_open_approval_center",
        lambda approval_center_url, *, store, config, open_key=None, force_open=False: {
            "opened": True,
            "reason": "opened",
            "browser_url": f"{approval_center_url}/home",
        },
    )

    def fake_connect(
        *,
        store,
        connect_url,
        wait_timeout_seconds=180,
        announce_copy=None,
        open_browser=None,
        ci_safe=False,
        machine_label=None,
    ) -> dict[str, object]:
        del store, connect_url, wait_timeout_seconds, ci_safe, machine_label
        assert announce_copy is not None
        assert open_browser is not None
        announce_copy(
            {
                "user_code": "ABCD-EFGH",
                "verification_uri": "https://hol.org/guard/oauth/device",
                "verification_uri_complete": "https://hol.org/guard/oauth/device?user_code=ABCD-EFGH",
            }
        )
        return {
            "status": "waiting_for_approval",
            "connect_mode": "device_code",
            "browser_opened": bool(open_browser("https://hol.org/guard/oauth/device")),
            "user_code": "ABCD-EFGH",
            "verification_uri": "https://hol.org/guard/oauth/device",
        }

    monkeypatch.setattr(guard_commands_module, "_run_guard_device_connect_flow", fake_connect)
    monkeypatch.setattr(guard_commands_module.webbrowser, "open", lambda url: opened_urls.append(url) or True)
    monkeypatch.setattr(
        guard_commands_module,
        "apply_managed_install",
        lambda *_args, **_kwargs: pytest.fail("install should be skipped"),
    )
    monkeypatch.setattr(
        guard_commands_module,
        "ensure_desktop_notification_setup",
        lambda *_args, **_kwargs: pytest.fail("notification setup should be skipped"),
    )

    rc = main(
        [
            "guard",
            "init",
            "--yes",
            "--skip-apps",
            "--skip-notifications",
            "--skip-tray",
            "--home",
            str(home_dir),
            "--guard-home",
            str(guard_home),
        ]
    )
    captured = capsys.readouterr()

    assert rc == 0
    assert opened_urls == ["https://hol.org/guard/oauth/device"]
    assert "HOL Guard headless approval" in captured.err
    assert "Open https://hol.org/guard/oauth/device" in captured.err
    assert "Enter code ABCD-EFGH" in captured.err

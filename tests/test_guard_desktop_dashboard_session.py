from __future__ import annotations

import argparse
import json
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import pytest

from codex_plugin_scanner.guard import dashboard_launcher
from codex_plugin_scanner.guard.cli import commands_dispatch_desktop


def test_desktop_dashboard_session_is_scoped_fragment_token(monkeypatch, tmp_path: Path) -> None:
    raw_daemon_token = "daemon-secret-that-must-not-cross-the-desktop-boundary"
    captured: dict[str, object] = {}
    guard_home = tmp_path / "guard-home"

    def fake_ensure_guard_daemon(received_home: Path, **kwargs: object) -> str:
        captured["guard_home"] = received_home
        captured.update(kwargs)
        return "http://127.0.0.1:43123/"

    monkeypatch.setattr(dashboard_launcher, "ensure_guard_daemon", fake_ensure_guard_daemon)
    monkeypatch.setattr(
        dashboard_launcher,
        "load_guard_daemon_auth_token",
        lambda _guard_home: raw_daemon_token,
    )

    url = dashboard_launcher.build_desktop_dashboard_session_url(guard_home=guard_home)
    assert captured["guard_home"] == guard_home
    assert captured["home_dir"] is None
    assert "executable" in captured
    parsed = urlparse(url)
    fragment = parse_qs(parsed.fragment)

    assert parsed.scheme == "http"
    assert parsed.hostname == "127.0.0.1"
    assert parsed.port == 43123
    assert parse_qs(parsed.query) == {dashboard_launcher.DESKTOP_DASHBOARD_EMBED_QUERY_KEY: ["1"]}
    assert set(fragment) == {"guard-token"}
    assert fragment["guard-token"][0].startswith("gld1.")
    assert raw_daemon_token not in url


def test_desktop_bootstrap_uses_canonical_dashboard_session_builder() -> None:
    source = __import__("inspect").getsource(commands_dispatch_desktop._run_guard_desktop_command)
    assert "build_desktop_dashboard_session_url" in source
    assert 'dashboard["sessionUrl"]' in source
    assert 'dashboard["canonical"] = True' in source
    assert "scan_installed_apps=False" in source
    assert source.index("session_url = build_desktop_dashboard_session_url") < source.index(
        "build_guard_status_payload"
    )


def test_desktop_bootstrap_aligns_runtime_before_projecting_protection(monkeypatch, tmp_path: Path) -> None:
    runtime_ready = {"value": False}
    call_order: list[str] = []
    captured: dict[str, object] = {}

    def fake_session_url(*, guard_home: Path, home_dir: Path | None = None) -> str:
        del guard_home
        captured["home_dir"] = home_dir
        call_order.append("session")
        runtime_ready["value"] = True
        return "http://127.0.0.1:43123/?desktop_embed=1#guard-token=gld1.test"

    def fake_status(_context: object, _store: object, _config: object, **kwargs: object) -> dict[str, object]:
        call_order.append("status")
        captured["scan_installed_apps"] = kwargs.get("scan_installed_apps")
        return {
            "runtime_status": "active" if runtime_ready["value"] else "offline",
            "managed_harnesses": 1,
            "receipt_count": 0,
            "pending_approvals": 0,
            "cloud_state": "local_only",
            "last_sync_at": None,
            "harnesses": [
                {
                    "harness": "codex",
                    "installed": True,
                    "command_available": True,
                    "artifact_count": 1,
                    "review_count": 0,
                    "warning_count": 0,
                    "managed": True,
                }
            ],
        }

    monkeypatch.setattr(commands_dispatch_desktop, "build_desktop_dashboard_session_url", fake_session_url)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.product.build_guard_status_payload",
        fake_status,
    )

    output = StringIO()
    result = commands_dispatch_desktop._run_guard_desktop_command(
        argparse.Namespace(desktop_command="bootstrap"),
        guard_home=tmp_path,
        context=SimpleNamespace(guard_home=tmp_path, home_dir=tmp_path / "home"),
        store=SimpleNamespace(
            list_approval_requests=lambda **_kwargs: [],
            oldest_approval_request_created_at=lambda **_kwargs: None,
            count_approval_requests=lambda **_kwargs: 0,
            list_receipts=lambda **_kwargs: [],
            receipt_summary_between=lambda **_kwargs: {
                "blocked": 0,
                "approved": 0,
                "latest_at": None,
            },
        ),
        config=SimpleNamespace(),
        output_stream=output,
    )

    payload = json.loads(output.getvalue())
    assert result == 0
    assert call_order == ["session", "status"]
    assert captured["scan_installed_apps"] is False
    assert captured["home_dir"] == tmp_path / "home"
    assert payload["status"] == "ready"
    assert payload["protection"]["state"] == "protected"
    assert payload["apps"][0]["protection"] == "protected"
    assert payload["daemon"] == {"running": True}
    assert payload["dashboard"]["sessionUrl"].startswith("http://127.0.0.1:43123/")


def test_desktop_preflight_skips_daemon_session(monkeypatch, tmp_path: Path) -> None:
    def fail_session(*, guard_home: Path, home_dir: Path | None = None) -> str:
        del guard_home, home_dir
        raise AssertionError("preflight must not start a daemon session")

    monkeypatch.setenv("HOL_GUARD_DESKTOP_PREFLIGHT", "1")
    monkeypatch.setattr(commands_dispatch_desktop, "build_desktop_dashboard_session_url", fail_session)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.product.build_guard_status_payload",
        lambda _context, _store, _config, **_kwargs: {
            "runtime_status": "offline",
            "managed_harnesses": 0,
            "receipt_count": 0,
            "pending_approvals": 0,
            "cloud_state": "local_only",
            "last_sync_at": None,
            "harnesses": [],
        },
    )

    output = StringIO()
    result = commands_dispatch_desktop._run_guard_desktop_command(
        argparse.Namespace(desktop_command="bootstrap"),
        guard_home=tmp_path,
        context=SimpleNamespace(guard_home=tmp_path),
        store=SimpleNamespace(
            list_approval_requests=lambda **_kwargs: [],
            oldest_approval_request_created_at=lambda **_kwargs: None,
            count_approval_requests=lambda **_kwargs: 0,
            list_receipts=lambda **_kwargs: [],
            receipt_summary_between=lambda **_kwargs: {
                "blocked": 0,
                "approved": 0,
                "latest_at": None,
            },
        ),
        config=SimpleNamespace(),
        output_stream=output,
    )

    payload = json.loads(output.getvalue())
    assert result == 0
    assert "sessionUrl" not in payload["dashboard"]
    assert payload["coreVersion"]


def test_desktop_preflight_refuses_session_url_builder(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HOL_GUARD_DESKTOP_PREFLIGHT", "1")
    with pytest.raises(RuntimeError, match="does not start a local daemon"):
        dashboard_launcher.build_desktop_dashboard_session_url(guard_home=tmp_path)


def test_status_payload_skips_installed_app_scan_when_requested(monkeypatch, tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.adapters.base import HarnessContext
    from codex_plugin_scanner.guard.cli import product
    from codex_plugin_scanner.guard.config import GuardConfig
    from codex_plugin_scanner.guard.store import GuardStore

    home_dir = tmp_path / "home"
    workspace = tmp_path / "workspace"
    guard_home = tmp_path / "guard-home"
    home_dir.mkdir()
    workspace.mkdir()
    store = GuardStore(guard_home)
    store.set_managed_install(
        "codex",
        True,
        str(workspace),
        {"shim_path": str(guard_home / "shims" / "codex")},
        "2026-09-12T00:00:00+00:00",
    )
    (guard_home / "shims").mkdir(parents=True)
    (guard_home / "shims" / "codex").write_text("#!/bin/sh\n", encoding="utf-8")
    context = HarnessContext(home_dir=home_dir, workspace_dir=workspace, guard_home=guard_home)
    config = GuardConfig(guard_home=guard_home, workspace=workspace)

    def fail_detect(_context: object) -> None:
        raise AssertionError("status payload must not scan installed apps")

    monkeypatch.setattr(product, "detect_all", fail_detect)

    payload = product.build_guard_status_payload(context, store, config, scan_installed_apps=False)
    harnesses = payload["harnesses"]
    assert isinstance(harnesses, list)
    assert payload["managed_harnesses"] == 1
    assert harnesses[0]["harness"] == "codex"
    assert harnesses[0]["managed"] is True
    assert harnesses[0]["review_count"] == 0
    assert harnesses[0]["installed"] is True
    assert harnesses[0]["warning_count"] == 0


def test_status_payload_marks_inactive_managed_installs_as_not_installed(monkeypatch, tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.adapters.base import HarnessContext
    from codex_plugin_scanner.guard.cli import product
    from codex_plugin_scanner.guard.config import GuardConfig
    from codex_plugin_scanner.guard.store import GuardStore

    home_dir = tmp_path / "home"
    workspace = tmp_path / "workspace"
    guard_home = tmp_path / "guard-home"
    home_dir.mkdir()
    workspace.mkdir()
    store = GuardStore(guard_home)
    store.set_managed_install(
        "codex",
        False,
        str(workspace),
        {"shim_path": str(guard_home / "shims" / "codex")},
        "2026-09-12T00:00:00+00:00",
    )
    context = HarnessContext(home_dir=home_dir, workspace_dir=workspace, guard_home=guard_home)
    config = GuardConfig(guard_home=guard_home, workspace=workspace)
    monkeypatch.setattr(
        product,
        "detect_all",
        lambda _context: (_ for _ in ()).throw(AssertionError("status payload must not scan installed apps")),
    )

    payload = product.build_guard_status_payload(context, store, config, scan_installed_apps=False)
    harness = payload["harnesses"][0]
    assert harness["managed"] is False
    assert harness["installed"] is False
    assert harness["command_available"] is False
    assert harness["next_action"] == "install"


def test_status_payload_warns_when_a_managed_shim_is_missing(monkeypatch, tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.adapters.base import HarnessContext
    from codex_plugin_scanner.guard.cli import product
    from codex_plugin_scanner.guard.config import GuardConfig
    from codex_plugin_scanner.guard.store import GuardStore

    home_dir = tmp_path / "home"
    workspace = tmp_path / "workspace"
    guard_home = tmp_path / "guard-home"
    home_dir.mkdir()
    workspace.mkdir()
    store = GuardStore(guard_home)
    store.set_managed_install(
        "codex",
        True,
        str(workspace),
        {"shim_path": str(guard_home / "shims" / "codex")},
        "2026-09-12T00:00:00+00:00",
    )
    context = HarnessContext(home_dir=home_dir, workspace_dir=workspace, guard_home=guard_home)
    config = GuardConfig(guard_home=guard_home, workspace=workspace)
    monkeypatch.setattr(
        product,
        "detect_all",
        lambda _context: (_ for _ in ()).throw(AssertionError("status payload must not scan installed apps")),
    )

    payload = product.build_guard_status_payload(context, store, config, scan_installed_apps=False)
    harness = payload["harnesses"][0]
    assert harness["managed"] is True
    assert harness["warning_count"] == 1
    assert harness["next_action"] == "review"


def test_status_payload_counts_each_missing_managed_path(monkeypatch, tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.adapters.base import HarnessContext
    from codex_plugin_scanner.guard.cli import product
    from codex_plugin_scanner.guard.config import GuardConfig
    from codex_plugin_scanner.guard.store import GuardStore

    home_dir = tmp_path / "home"
    workspace = tmp_path / "workspace"
    guard_home = tmp_path / "guard-home"
    home_dir.mkdir()
    workspace.mkdir()
    store = GuardStore(guard_home)
    store.set_managed_install(
        "codex",
        True,
        str(workspace),
        {
            "shim_path": str(guard_home / "shims" / "codex"),
            "windows_shim_path": str(guard_home / "shims" / "codex.cmd"),
        },
        "2026-09-12T00:00:00+00:00",
    )
    context = HarnessContext(home_dir=home_dir, workspace_dir=workspace, guard_home=guard_home)
    config = GuardConfig(guard_home=guard_home, workspace=workspace)
    monkeypatch.setattr(
        product,
        "detect_all",
        lambda _context: (_ for _ in ()).throw(AssertionError("status payload must not scan installed apps")),
    )

    payload = product.build_guard_status_payload(context, store, config, scan_installed_apps=False)
    assert payload["harnesses"][0]["warning_count"] == 2


def test_status_payload_warns_when_managed_opencode_config_is_missing(monkeypatch, tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.adapters.base import HarnessContext
    from codex_plugin_scanner.guard.cli import product
    from codex_plugin_scanner.guard.config import GuardConfig
    from codex_plugin_scanner.guard.store import GuardStore

    home_dir = tmp_path / "home"
    workspace = tmp_path / "workspace"
    guard_home = tmp_path / "guard-home"
    home_dir.mkdir()
    workspace.mkdir()
    store = GuardStore(guard_home)
    store.set_managed_install(
        "opencode",
        True,
        str(workspace),
        {
            "config_path": str(home_dir / ".config" / "opencode" / "opencode.json"),
            "managed_config_path": str(home_dir / ".config" / "opencode" / "opencode.json"),
            "runtime_config_path": str(guard_home / "runtime" / "opencode.json"),
        },
        "2026-09-12T00:00:00+00:00",
    )
    context = HarnessContext(home_dir=home_dir, workspace_dir=workspace, guard_home=guard_home)
    config = GuardConfig(guard_home=guard_home, workspace=workspace)
    monkeypatch.setattr(
        product,
        "detect_all",
        lambda _context: (_ for _ in ()).throw(AssertionError("status payload must not scan installed apps")),
    )

    payload = product.build_guard_status_payload(context, store, config, scan_installed_apps=False)
    harness = payload["harnesses"][0]
    assert harness["managed"] is True
    assert harness["warning_count"] == 3
    assert harness["next_action"] == "review"


def test_status_payload_still_scans_installed_apps_by_default(monkeypatch, tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.adapters.base import HarnessContext
    from codex_plugin_scanner.guard.cli import product
    from codex_plugin_scanner.guard.config import GuardConfig
    from codex_plugin_scanner.guard.models import HarnessDetection
    from codex_plugin_scanner.guard.store import GuardStore

    scanned = {"called": False}
    home_dir = tmp_path / "home"
    workspace = tmp_path / "workspace"
    guard_home = tmp_path / "guard-home"
    home_dir.mkdir()
    workspace.mkdir()
    context = HarnessContext(home_dir=home_dir, workspace_dir=workspace, guard_home=guard_home)
    store = GuardStore(guard_home)
    config = GuardConfig(guard_home=guard_home, workspace=workspace)

    def fake_detect(_context: object) -> list[HarnessDetection]:
        scanned["called"] = True
        return [
            HarnessDetection(
                harness="codex",
                installed=True,
                command_available=True,
                config_paths=(),
                artifacts=(),
            )
        ]

    monkeypatch.setattr(product, "detect_all", fake_detect)

    payload = product.build_guard_status_payload(context, store, config)
    assert scanned["called"] is True
    assert payload["harnesses"][0]["harness"] == "codex"

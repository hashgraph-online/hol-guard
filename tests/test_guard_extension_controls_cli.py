from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import sys
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.cli import (
    commands_dispatch_trust,
    commands_support_service,
    extension_controls_commands,
)
from codex_plugin_scanner.guard.cli.extension_controls_commands import (
    _mutation_payload,
    run_extension_controls_command,
)
from codex_plugin_scanner.guard.daemon import manager
from codex_plugin_scanner.guard.daemon.client import GuardDaemonRequestError
from codex_plugin_scanner.guard.daemon.discovery import authenticate_daemon_state, ensure_daemon_discovery_key
from codex_plugin_scanner.guard.daemon.runtime_peer import load_guard_daemon_endpoint


def _effective() -> dict[str, object]:
    return {
        "revision": 4,
        "catalog_digest": "a" * 64,
        "layers": [
            {
                "schema_version": "1.0.0",
                "kind": "local-admin",
                "catalog_digest": "a" * 64,
                "global_lockdown": False,
                "controls": [{"target_kind": "extension", "target_id": "existing", "state": "disabled"}],
            }
        ],
    }


def test_control_mutation_preserves_existing_local_controls() -> None:
    payload = _mutation_payload(
        _effective(),
        argparse.Namespace(
            controls_command="apply",
            target_kind="extension",
            target_id="new-target",
            state="disabled",
        ),
    )

    layers = payload["layers"]
    assert isinstance(layers, list)
    controls = layers[0]["controls"]
    assert [control["target_id"] for control in controls] == ["existing", "new-target"]


def test_global_lockdown_state_maps_without_changing_controls() -> None:
    payload = _mutation_payload(
        _effective(),
        argparse.Namespace(controls_command="global-apply", state="enabled"),
    )

    layers = payload["layers"]
    assert isinstance(layers, list)
    assert layers[0]["global_lockdown"] is True
    assert layers[0]["controls"][0]["target_id"] == "existing"


def test_status_without_daemon_is_read_only(tmp_path: Path) -> None:
    guard_home = tmp_path / "absent"
    output = io.StringIO()

    result = run_extension_controls_command(
        argparse.Namespace(controls_command="status"),
        guard_home=guard_home,
        output_stream=output,
    )

    assert result == 2
    assert not guard_home.exists()


_DESKTOP_CORE_VERSION = "3.0.86"


@contextmanager
def _signed_desktop_daemon(
    guard_home: Path,
    *,
    state_guard_home: Path | None = None,
    details_guard_home: Path | None = None,
    state_token: str = "desktop-token",
    package_version: str = _DESKTOP_CORE_VERSION,
    compatibility_version: object = manager.GUARD_DAEMON_COMPATIBILITY_VERSION,
    source_root: str | None = None,
) -> Iterator[tuple[str, str]]:
    token = "desktop-token"
    guard_home.mkdir(parents=True, exist_ok=True)
    if source_root is None:
        managed_source = (
            guard_home.parent
            / "org.hol.guard.desktop"
            / "core"
            / "versions"
            / _DESKTOP_CORE_VERSION
            / "hol-guard"
        )
        managed_source.parent.mkdir(parents=True, exist_ok=True)
        managed_source.write_text("synthetic desktop core", encoding="utf-8")
        source_root = str(managed_source)
    discovery_key = ensure_daemon_discovery_key(guard_home)
    details_home = (details_guard_home or guard_home).resolve()
    state_home = (state_guard_home or guard_home).resolve()

    class _HealthHandler(BaseHTTPRequestHandler):
        def _write_json(self, payload: dict[str, object], *, status: int = 200) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            if self.path != "/v1/healthz/details":
                self._write_json({"error": "not_found"}, status=404)
                return
            if self.headers.get("X-Guard-Token") != token:
                self._write_json({"error": "unauthorized"}, status=401)
                return
            self._write_json({**state, "ok": True, "guard_home": str(details_home)})

        def log_message(self, _format: str, *_args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), _HealthHandler)
    server.daemon_threads = True
    state: dict[str, object] = {
        "guard_home": str(state_home),
        "host": "127.0.0.1",
        "port": server.server_port,
        "compatibility_version": compatibility_version,
        "package_version": package_version,
        "runtime_fingerprint": "d" * 64,
        "pid": os.getpid(),
        "started_at": "2026-09-05T00:00:00+00:00",
        "state_id": "desktop-state",
        "source_root": source_root,
        "auth_token_id": hashlib.sha256(state_token.encode("utf-8")).hexdigest(),
    }
    auth_path = manager._auth_token_path(guard_home)
    auth_path.write_text(token, encoding="utf-8")
    state_path = manager._state_path(guard_home)
    state_path.write_text(
        json.dumps(authenticate_daemon_state(state, discovery_key=discovery_key)),
        encoding="utf-8",
    )
    if os.name != "nt":
        os.chmod(auth_path, 0o600)
        os.chmod(state_path, 0o600)

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", token
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_client_reuses_verified_desktop_owner_for_mismatched_cli_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    # Mirror the observed pipx 3.0.88 caller against the managed Core 3.0.86 peer.
    monkeypatch.setattr(manager, "__version__", "3.0.88")
    with _signed_desktop_daemon(guard_home) as (daemon_url, token):
        assert manager.load_guard_daemon_url(guard_home) is None
        client = extension_controls_commands._client(guard_home)

    assert client.daemon_url == daemon_url
    assert client.auth_token == token


def test_endpoint_rejects_incompatible_desktop_protocol(
    tmp_path: Path,
) -> None:
    guard_home = tmp_path / "guard-home"
    with _signed_desktop_daemon(guard_home, compatibility_version="not-current"):
        assert load_guard_daemon_endpoint(guard_home) is None


def test_trust_doctor_uses_verified_desktop_endpoint_without_fresh_locator(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    monkeypatch.setattr(manager, "__version__", "3.0.88")
    monkeypatch.setattr(commands_dispatch_trust, "read_approval_center_locator", lambda _home: None)

    with _signed_desktop_daemon(guard_home) as (daemon_url, _token):
        payload = commands_dispatch_trust._approval_center_status_payload(guard_home)

    assert payload["active"] is True
    assert payload["daemon_url"] == daemon_url
    assert payload["snapshot_fresh"] is False


def test_daemon_status_uses_verified_desktop_endpoint_after_running_check(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    guard_home = tmp_path / "guard-home"
    monkeypatch.setattr(manager, "__version__", "3.0.88")
    monkeypatch.setattr(commands_support_service, "_guard_daemon_pid_is_running", lambda _pid: True)
    monkeypatch.setattr(
        commands_support_service,
        "_guard_daemon_pid_matches_command",
        lambda _pid, expected_guard_home=None: True,
    )

    with _signed_desktop_daemon(guard_home) as (daemon_url, _token):
        result = commands_support_service._handle_daemon_status(guard_home, as_json=True)

    output = json.loads(capsys.readouterr().out)
    assert result == 0
    assert output["running"] is True
    assert output["version"] == _DESKTOP_CORE_VERSION
    assert output["url"] == daemon_url


def test_client_keeps_strict_current_runtime_path_before_desktop_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        extension_controls_commands,
        "load_guard_daemon_endpoint",
        lambda _home: ("http://127.0.0.1:8235", "current-token"),
    )

    client = extension_controls_commands._client(tmp_path / "guard-home")

    assert client.daemon_url == "http://127.0.0.1:8235"
    assert client.auth_token == "current-token"


def test_client_rejects_desktop_owner_for_mismatched_home(
    tmp_path: Path,
) -> None:
    guard_home = tmp_path / "guard-home"
    with _signed_desktop_daemon(guard_home, state_guard_home=tmp_path / "other-home"), pytest.raises(
        GuardDaemonRequestError, match="not running"
    ):
        extension_controls_commands._client(guard_home)


def test_client_rejects_desktop_owner_for_mismatched_health_home(
    tmp_path: Path,
) -> None:
    guard_home = tmp_path / "guard-home"
    with _signed_desktop_daemon(guard_home, details_guard_home=tmp_path / "other-home"), pytest.raises(
        GuardDaemonRequestError, match="not running"
    ):
        extension_controls_commands._client(guard_home)


def test_client_rejects_desktop_owner_with_mismatched_auth_token(
    tmp_path: Path,
) -> None:
    guard_home = tmp_path / "guard-home"
    with _signed_desktop_daemon(guard_home, state_token="wrong-token"), pytest.raises(
        GuardDaemonRequestError, match="not running"
    ):
        extension_controls_commands._client(guard_home)


def test_client_rejects_arbitrary_daemon_identity_even_when_authenticated_shape_is_present(
    tmp_path: Path,
) -> None:
    guard_home = tmp_path / "guard-home"
    with _signed_desktop_daemon(guard_home, source_root="/opt/hol-guard/lib/python"), pytest.raises(
        GuardDaemonRequestError, match="not running"
    ):
        extension_controls_commands._client(guard_home)


@pytest.mark.parametrize("program_name", ["hol-guard", "plugin-scanner", "plugin-guard", "plugin-ecosystem-scanner"])
def test_controls_help_is_available_from_every_installed_alias(
    program_name: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(sys, "argv", [program_name])
    arguments = (
        ["command", "controls", "--help"]
        if program_name == "hol-guard"
        else [
            "guard",
            "command",
            "controls",
            "--help",
        ]
    )
    with pytest.raises(SystemExit) as exit_info:
        main(arguments)

    assert exit_info.value.code == 0
    assert (
        "{status,patterns,set,list,show,preview,apply,global-preview,global-apply,enroll,recover-authority,acknowledge-degraded}"
    ) in capsys.readouterr().out


@pytest.mark.parametrize(
    ("command", "expected_calls"),
    (
        ("recover-authority", ("prompt", "require", "consume", "recover", "refresh")),
        ("acknowledge-degraded", ("prompt", "acknowledge")),
    ),
)
def test_authority_recovery_requires_and_consumes_fresh_local_approval(
    command: str,
    expected_calls: tuple[str, ...],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    view = SimpleNamespace(
        health=SimpleNamespace(value="tampered"),
        revision=7,
        catalog_digest="catalog",
    )

    class FakeStore:
        def __init__(self, guard_home: Path) -> None:
            assert guard_home == tmp_path

        def read_extension_control_authority_for_registry(self, registry: object) -> object:
            assert registry
            return view

        def recover_extension_control_authority(
            self,
            *,
            catalog_digest: str,
            migration_registry: object,
        ) -> object:
            assert catalog_digest
            assert migration_registry
            calls.append("recover")
            return view

    class FakeClient:
        def refresh_extension_controls(self) -> dict[str, object]:
            calls.append("refresh")
            return {"health": "protected", "revision": 7}

        def acknowledge_degraded_extension_controls(
            self,
            payload: dict[str, object],
        ) -> dict[str, object]:
            assert payload["approval_password"] == "password"
            assert payload["approval_totp_code"] == "123456"
            assert isinstance(payload["session_nonce"], str)
            calls.append("acknowledge")
            return {"health": "degraded-acknowledged", "revision": 0}

    monkeypatch.setattr(extension_controls_commands, "GuardStore", FakeStore)
    monkeypatch.setattr(extension_controls_commands, "_client", lambda _guard_home: FakeClient())
    monkeypatch.setattr(
        extension_controls_commands,
        "prompt_for_approval_gate",
        lambda *_args, **_kwargs: calls.append("prompt") or SimpleNamespace(password="password", totp_code="123456"),
    )
    monkeypatch.setattr(
        extension_controls_commands,
        "require_extension_control",
        lambda *_args, **_kwargs: calls.append("require") or object(),
    )
    monkeypatch.setattr(
        extension_controls_commands,
        "consume_extension_control_grant",
        lambda *_args, **_kwargs: calls.append("consume"),
    )
    output = io.StringIO()

    exit_code = extension_controls_commands._recover_authority(
        tmp_path,
        command=command,
        output_stream=output,
    )

    assert exit_code == 0
    assert calls == list(expected_calls)


def test_recommended_state_removes_explicit_local_control() -> None:
    effective = {
        "revision": 5,
        "catalog_digest": "a" * 64,
        "layers": [
            {
                "schema_version": "1.0.0",
                "kind": "local-admin",
                "catalog_digest": "a" * 64,
                "global_lockdown": False,
                "controls": [
                    {
                        "target_kind": "permission",
                        "target_id": "command.github.permission.merge-admin",
                        "state": "disabled",
                    }
                ],
            }
        ],
    }
    payload = _mutation_payload(
        effective,
        argparse.Namespace(
            controls_command="set",
            target_kind="permission",
            target_id="command.github.permission.merge-admin",
            state="recommended",
        ),
    )

    layers = payload["layers"]
    assert isinstance(layers, list)
    controls = layers[0]["controls"]
    assert controls == []


def test_patterns_filters_by_query_and_tool_and_reports_local_state(capsys: pytest.CaptureFixture[str]) -> None:
    class FakeClient:
        def extension_control_catalog(self) -> dict[str, object]:
            return {
                "extensions": [
                    {
                        "extension_id": "command.github",
                        "name": "GitHub capability protection",
                        "permissions": [
                            {
                                "permission_id": "command.github.permission.merge-remote",
                                "label": "GitHub pull-request merge",
                                "example_command": "gh pr merge 123 --merge",
                                "family": "gh-pr-merge",
                                "configurable": True,
                            },
                            {
                                "permission_id": "command.github.permission.read-remote",
                                "label": "remote GitHub state",
                                "example_command": "gh pr view 123",
                                "family": None,
                                "configurable": True,
                            },
                        ],
                    }
                ]
            }

        def effective_extension_controls(self) -> dict[str, object]:
            return {
                "revision": 3,
                "layers": [
                    {
                        "kind": "local-admin",
                        "controls": [
                            {
                                "target_kind": "permission",
                                "target_id": "command.github.permission.merge-remote",
                                "state": "disabled",
                            }
                        ],
                    }
                ],
            }

    exit_code = extension_controls_commands._patterns(
        FakeClient(),
        argparse.Namespace(query="merge", tool="command.github", json=False),
        None,
    )
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "gh pr merge 123 --merge" in out
    assert "block" in out
    assert "gh pr view 123" not in out

"""Gate settings validation and authenticated changes."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.approval_gate import ApprovalGateError, public_config
from codex_plugin_scanner.guard.approval_gate import (
    update_settings as update_approval_gate_settings,
)
from codex_plugin_scanner.guard.config import load_guard_config, reset_guard_settings
from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.totp import totp_code_at_counter
from tests.guard_approval_gate_support import (
    PASSWORD,
    _counter,
    _enable_gate,
    _enable_totp,
    _store,
)
from tests.guard_approval_gate_support import (
    _clear_agent_env_markers as _clear_agent_env_markers,
)
from tests.guard_approval_gate_support import (
    _default_store_platform as _default_store_platform,
)


def test_approval_gate_settings_import_and_reset_cannot_disable_without_password(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _enable_gate(store)

    with pytest.raises(ApprovalGateError):
        update_approval_gate_settings(store.guard_home, {"enabled": False})
    with pytest.raises(ApprovalGateError):
        reset_guard_settings(store.guard_home)

    gate = public_config(store.guard_home)
    assert gate.enabled is True


def test_approval_gate_settings_import_and_reset_require_totp_when_enabled(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _enable_gate(store)
    _enable_totp(store, now="2026-04-11T00:00:00+00:00")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        import_request = urllib.request.Request(
            f"http://127.0.0.1:{daemon.port}/v1/settings/import",
            data=json.dumps(
                {
                    "settings": {
                        "approval_wait_timeout_seconds": 90,
                        "approval_gate": {"current_password": PASSWORD},
                    }
                }
            ).encode("utf-8"),
            headers={"Content-Type": "application/json", "X-Guard-Token": daemon._server.auth_token},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as import_error:
            urllib.request.urlopen(import_request, timeout=5)
        import_body = json.loads(import_error.value.read().decode("utf-8"))

        reset_request = urllib.request.Request(
            f"http://127.0.0.1:{daemon.port}/v1/settings/reset",
            data=json.dumps(
                {
                    "confirm": "reset-local-settings",
                    "approval_gate": {"password": PASSWORD},
                }
            ).encode("utf-8"),
            headers={"Content-Type": "application/json", "X-Guard-Token": daemon._server.auth_token},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as reset_error:
            urllib.request.urlopen(reset_request, timeout=5)
        reset_body = json.loads(reset_error.value.read().decode("utf-8"))
    finally:
        daemon.stop()

    assert import_error.value.code == 403
    assert reset_error.value.code == 403
    assert import_body["error"] == "approval_gate_totp_required"
    assert reset_body["error"] == "approval_gate_totp_required"


def test_approval_gate_settings_update_requires_totp_when_enabled(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _enable_gate(store)
    secret = _enable_totp(store, now="2026-04-11T00:00:00+00:00")
    now = datetime.now(timezone.utc).isoformat()
    settings_code = totp_code_at_counter(secret=secret, counter=_counter(now))
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        missing_totp_request = urllib.request.Request(
            f"http://127.0.0.1:{daemon.port}/v1/settings",
            data=json.dumps(
                {
                    "settings": {"approval_wait_timeout_seconds": 90},
                    "approval_password": PASSWORD,
                }
            ).encode("utf-8"),
            headers={"Content-Type": "application/json", "X-Guard-Token": daemon._server.auth_token},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as totp_error:
            urllib.request.urlopen(missing_totp_request, timeout=5)
        totp_body = json.loads(totp_error.value.read().decode("utf-8"))

        verified_request = urllib.request.Request(
            f"http://127.0.0.1:{daemon.port}/v1/settings",
            data=json.dumps(
                {
                    "settings": {"approval_wait_timeout_seconds": 90},
                    "approval_totp_code": settings_code,
                }
            ).encode("utf-8"),
            headers={"Content-Type": "application/json", "X-Guard-Token": daemon._server.auth_token},
            method="POST",
        )
        with urllib.request.urlopen(verified_request, timeout=5) as update_response:
            update_body = json.loads(update_response.read().decode("utf-8"))
    finally:
        daemon.stop()

    assert totp_error.value.code == 403
    assert totp_body["error"] == "approval_gate_totp_required"
    assert update_body["settings"]["approval_wait_timeout_seconds"] == 90


def test_approval_gate_cooldown_revoke_requires_totp_when_enabled(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _enable_gate(store, cooldown_seconds=900)
    _enable_totp(store, now="2026-04-11T00:00:00+00:00")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        revoke_request = urllib.request.Request(
            f"http://127.0.0.1:{daemon.port}/v1/approval-gate/cooldown/revoke",
            data=json.dumps({"approval_gate": {"password": PASSWORD}}).encode("utf-8"),
            headers={"Content-Type": "application/json", "X-Guard-Token": daemon._server.auth_token},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as revoke_error:
            urllib.request.urlopen(revoke_request, timeout=5)
        revoke_body = json.loads(revoke_error.value.read().decode("utf-8"))
    finally:
        daemon.stop()

    assert revoke_error.value.code == 403
    assert revoke_body["error"] == "approval_gate_totp_required"


def test_approval_gate_settings_update_rejects_invalid_gate_payload_atomically(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _enable_gate(store)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        settings_request = urllib.request.Request(
            f"http://127.0.0.1:{daemon.port}/v1/settings",
            data=json.dumps(
                {
                    "settings": {
                        "approval_wait_timeout_seconds": 7,
                        "approval_gate": {
                            "enabled": True,
                            "current_password": PASSWORD,
                            "cooldown_seconds": 123,
                        },
                    }
                }
            ).encode("utf-8"),
            headers={"Content-Type": "application/json", "X-Guard-Token": daemon._server.auth_token},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as settings_error:
            urllib.request.urlopen(settings_request, timeout=5)
        body = json.loads(settings_error.value.read().decode("utf-8"))
    finally:
        daemon.stop()

    assert settings_error.value.code == 403
    assert body["error"] == "approval_gate_invalid_cooldown"
    assert load_guard_config(store.guard_home).approval_wait_timeout_seconds == 120
    assert public_config(store.guard_home).cooldown_seconds == 0

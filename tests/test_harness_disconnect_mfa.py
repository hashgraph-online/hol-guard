"""Disconnecting a managed app requires a fresh authenticator code when TOTP is on."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

from codex_plugin_scanner.guard.approval_gate import (
    ApprovalGateError,
    ApprovalGateInput,
    begin_totp_enrollment,
    confirm_totp_enrollment,
)
from codex_plugin_scanner.guard.approval_gate import (
    update_settings as update_approval_gate_settings,
)
from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.harness_disconnect_gate import require_harness_disconnect_gate
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.totp import totp_code_at_counter

PASSWORD = "correct horse battery staple"


def _counter(value: str) -> int:
    return int(datetime.fromisoformat(value).timestamp() // 30)


def _extract_secret(otpauth_uri: str) -> str:
    values = parse_qs(urlparse(otpauth_uri).query).get("secret")
    if not values:
        raise AssertionError("otpauth URI did not include a secret")
    return values[0]


def _enable_gate(guard_home: Path) -> None:
    update_approval_gate_settings(
        guard_home,
        {
            "enabled": True,
            "new_password": PASSWORD,
            "confirm_password": PASSWORD,
            "cooldown_seconds": 0,
        },
    )


def _enable_totp(guard_home: Path, *, now: str) -> str:
    enrollment = begin_totp_enrollment(
        guard_home,
        approval_gate_input=ApprovalGateInput(password=PASSWORD),
        device_label="disconnect-mfa-test",
        now=now,
    )
    secret = _extract_secret(str(enrollment["otpauth_uri"]))
    code = totp_code_at_counter(secret=secret, counter=_counter(now))
    confirm_totp_enrollment(
        guard_home,
        approval_gate_input=ApprovalGateInput(password=PASSWORD, totp_code=code),
        now=now,
    )
    return secret


def _read_json_response(request: urllib.request.Request) -> tuple[int, dict[str, object]]:
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read().decode("utf-8"))


def _request(
    port: int,
    path: str,
    *,
    token: str,
    payload: dict[str, object],
) -> urllib.request.Request:
    return urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Guard-Token": token},
        method="POST",
    )


def test_require_harness_disconnect_gate_rejects_missing_totp(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    _enable_gate(guard_home)
    _enable_totp(guard_home, now="2026-04-11T00:00:00+00:00")

    with pytest.raises(ApprovalGateError, match="TOTP code is required"):
        require_harness_disconnect_gate(guard_home, {}, harness="codex")


def test_require_harness_disconnect_gate_accepts_fresh_totp(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    _enable_gate(guard_home)
    secret = _enable_totp(guard_home, now="2026-04-11T00:00:00+00:00")
    now = datetime.now(timezone.utc).isoformat()
    code = totp_code_at_counter(secret=secret, counter=_counter(now))

    grant = require_harness_disconnect_gate(
        guard_home,
        {"approval_totp_code": code},
        harness="codex",
    )

    assert grant is not None
    assert grant.purpose == "protection_lifecycle"


def test_daemon_uninstall_requires_totp_when_authenticator_is_enabled(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", lambda: home)
    store = GuardStore(tmp_path / "guard-home")
    _enable_gate(store.guard_home)
    secret = _enable_totp(store.guard_home, now="2026-04-11T00:00:00+00:00")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        install_status, _install_payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/harnesses/opencode/install",
                token=daemon._server.auth_token,
                payload={"dry_run": False},
            )
        )
        missing_status, missing_payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/harnesses/opencode/uninstall",
                token=daemon._server.auth_token,
                payload={"dry_run": False, "confirmation_phrase": "disconnect-opencode"},
            )
        )
        code = totp_code_at_counter(
            secret=secret,
            counter=_counter(datetime.now(timezone.utc).isoformat()),
        )
        ok_status, ok_payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/harnesses/opencode/uninstall",
                token=daemon._server.auth_token,
                payload={
                    "dry_run": False,
                    "confirmation_phrase": "disconnect-opencode",
                    "approval_totp_code": code,
                },
            )
        )
    finally:
        daemon.stop()

    assert install_status == 200
    assert missing_status == 403
    assert missing_payload["error"] == "approval_gate_totp_required"
    assert ok_status == 200
    managed = ok_payload["managed_install"]
    assert isinstance(managed, dict)
    assert managed["active"] is False

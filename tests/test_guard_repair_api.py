from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.approval_gate import ApprovalGateError
from codex_plugin_scanner.guard.daemon import repair_api, repair_self_check
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.store import GuardStore

GUARD_COMMAND = "hol-guard hook --harness claude-code --event PreToolUse"
USER_COMMAND = "/usr/local/bin/my-audit-hook --log"


class _Gate:
    def __init__(self, *, enabled: bool, totp_enabled: bool = False) -> None:
        self.enabled = enabled
        self.totp_enabled = totp_enabled


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    user_home = tmp_path / "home"
    (user_home / ".claude").mkdir(parents=True)
    settings = {
        "hooks": {
            "PreToolUse": [
                {"matcher": "*", "hooks": [{"type": "command", "command": GUARD_COMMAND}]},
                {"matcher": "Bash", "hooks": [{"type": "command", "command": USER_COMMAND}]},
            ]
        }
    }
    (user_home / ".claude" / "settings.json").write_text(json.dumps(settings))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: user_home))
    monkeypatch.setenv("HOME", str(user_home))
    return user_home


def _settings_text(home: Path) -> str:
    return (home / ".claude" / "settings.json").read_text()


def _store(tmp_path: Path) -> GuardStore:
    return GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)


def _gate(monkeypatch: pytest.MonkeyPatch, *, enabled: bool, accept: bool = True, totp: bool = False) -> list[dict]:
    calls: list[dict] = []
    monkeypatch.setattr(repair_api, "public_config", lambda _home: _Gate(enabled=enabled, totp_enabled=totp))
    monkeypatch.setattr(repair_api, "_authority_home", lambda guard_home, _action: guard_home)

    def fake_require(_home: Path, **kwargs: object) -> None:
        calls.append(kwargs)
        if not accept:
            raise ApprovalGateError("approval_gate_password_invalid", "Wrong password.", status=403)

    monkeypatch.setattr(repair_api, "require_high_risk", fake_require)
    return calls


def test_removal_dry_run_lists_without_proof_or_change(tmp_path: Path, home: Path) -> None:
    before = _settings_text(home)
    report = repair_api.removal_request(_store(tmp_path), {"dry_run": True})
    assert report["status"] == "planned"
    assert [item["harness"] for item in report["harnesses"]] == ["claude-code"]
    assert _settings_text(home) == before


def test_removal_requires_explicit_confirmation(tmp_path: Path, home: Path) -> None:
    with pytest.raises(repair_api.RemovalConfirmationError):
        repair_api.removal_request(_store(tmp_path), {})
    assert GUARD_COMMAND in _settings_text(home)


def test_removal_refused_without_gate_even_with_confirmation(
    tmp_path: Path, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _gate(monkeypatch, enabled=False)
    with pytest.raises(ApprovalGateError) as error:
        repair_api.removal_request(_store(tmp_path), {"confirm": repair_api.REMOVE_CONFIRMATION})
    assert error.value.status == 423
    assert GUARD_COMMAND in _settings_text(home)


def test_removal_rejected_proof_changes_nothing(tmp_path: Path, home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _gate(monkeypatch, enabled=True, accept=False)
    with pytest.raises(ApprovalGateError):
        repair_api.removal_request(
            _store(tmp_path),
            {"confirm": repair_api.REMOVE_CONFIRMATION, "approval_password": "wrong"},
        )
    assert GUARD_COMMAND in _settings_text(home)


def test_removal_with_proof_removes_guard_hooks_only_and_reports_post_state(
    tmp_path: Path, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _gate(monkeypatch, enabled=True)
    report = repair_api.removal_request(
        _store(tmp_path),
        {"confirm": repair_api.REMOVE_CONFIRMATION, "approval_password": "pw", "approval_gate_use_cooldown": True},
    )
    assert report["status"] == "removed"
    assert report["post_state"] == {"remaining_harnesses": [], "clean": True}
    text = _settings_text(home)
    assert GUARD_COMMAND not in text and USER_COMMAND in text
    assert calls[0]["purpose"] == "protection_lifecycle"
    assert calls[0]["action"] == "hooks.remove"
    # A cooldown from an earlier proof must never authorize removal.
    assert calls[0]["approval_gate_input"].use_cooldown is False


def test_removal_requires_totp_code_when_authenticator_enabled(
    tmp_path: Path, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _gate(monkeypatch, enabled=True, totp=True)
    with pytest.raises(ApprovalGateError) as error:
        repair_api.removal_request(_store(tmp_path), {"confirm": repair_api.REMOVE_CONFIRMATION})
    assert error.value.code == "approval_gate_totp_required"
    assert GUARD_COMMAND in _settings_text(home)


def test_repair_dry_run_is_exempt_from_gate_and_runs_every_non_daemon_step(
    tmp_path: Path, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _gate(monkeypatch, enabled=True, accept=False)
    report = repair_api.repair_request(_store(tmp_path), {"dry_run": True})
    assert calls == []
    names = [step["step"] for step in report["steps"]]
    assert "daemon" not in names and "hooks" in names


def test_repair_real_run_is_gated_when_enabled(tmp_path: Path, home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _gate(monkeypatch, enabled=True, accept=False)
    with pytest.raises(ApprovalGateError):
        repair_api.repair_request(_store(tmp_path), {})


def test_repair_real_run_is_advisory_without_gate(tmp_path: Path, home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _gate(monkeypatch, enabled=False)
    report = repair_api.repair_request(_store(tmp_path), {})
    assert calls == []
    assert report["schema"] == "guard.repair.v1"


def _post(daemon: GuardDaemonServer, path: str, body: dict[str, object], *, token: bool = True) -> tuple[int, dict]:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-Guard-Token"] = daemon._server.auth_token
    request = urllib.request.Request(
        f"http://127.0.0.1:{daemon.port}{path}",
        data=json.dumps(body).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read() or b"{}")


def test_routes_require_token_and_map_errors(tmp_path: Path, home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _gate(monkeypatch, enabled=False)
    daemon = GuardDaemonServer(_store(tmp_path), host="127.0.0.1", port=0)
    daemon.start()
    try:
        assert _post(daemon, "/v1/repair", {"dry_run": True}, token=False)[0] == 401
        assert _post(daemon, "/v1/protection/remove-hooks", {"dry_run": True}, token=False)[0] == 401
        status, repaired = _post(daemon, "/v1/repair", {"dry_run": True})
        assert status == 200 and repaired["dry_run"] is True
        status, plan = _post(daemon, "/v1/protection/remove-hooks", {"dry_run": True})
        assert status == 200 and plan["status"] == "planned"
        status, payload = _post(daemon, "/v1/protection/remove-hooks", {})
        assert status == 400 and payload["confirm"] == repair_api.REMOVE_CONFIRMATION
        status, payload = _post(daemon, "/v1/protection/remove-hooks", {"confirm": repair_api.REMOVE_CONFIRMATION})
        assert status == 423
        assert GUARD_COMMAND in _settings_text(home)
    finally:
        daemon.stop()


def test_self_check_publishes_finding_only_for_broken_hooks(
    tmp_path: Path, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path)
    clean = repair_self_check.run_self_check_once(store)
    assert clean["finding"] is None and clean["hooks_broken"] == []
    monkeypatch.setattr(
        repair_self_check,
        "broken_hook_harnesses",
        lambda _context, _store: [{"harness": "codex", "setup_status": "broken"}],
    )
    broken = repair_self_check.run_self_check_once(store)
    finding = broken["finding"]
    assert finding["code"] == "hooks_broken" and finding["harnesses"] == ["codex"]
    assert finding["action"]["endpoint"] == "/v1/repair"
    # Non-destructive: the check never touches hook config.
    assert GUARD_COMMAND in _settings_text(home)

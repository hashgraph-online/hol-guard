"""Command-policy repair stays a deny and points at one local button."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from urllib.parse import parse_qs

import pytest

from codex_plugin_scanner.guard.daemon.hook_policy_repair import (
    apply_command_policy_repair,
    command_policy_repair_page_url,
)
from codex_plugin_scanner.guard.daemon.hook_worker_responses import harness_json_from_native_pre_tool
from codex_plugin_scanner.guard.runtime.extension_control_authority import AuthorityHealth

_ORIGINAL_REASON = "HOL Guard requires the native command extension policy before this action can execute."
_REPAIR_URL = "http://127.0.0.1:5474/protection/repair#guard-token=gld1.test"


class _View:
    def __init__(self, health: AuthorityHealth, revision: int = 4) -> None:
        self.health = health
        self.revision = revision


class _Store:
    def __init__(self, health: AuthorityHealth, revision: int = 4) -> None:
        self.view = _View(health, revision)

    def read_extension_control_authority_for_registry(self, registry: object) -> _View:
        assert registry is not None
        return self.view


def _blocked(**extra: object) -> dict[str, object]:
    result: dict[str, object] = {
        "decision": "deny",
        "minimum_action": "block",
        "reason_code": "native_command_control_authority_block",
        "reason": _ORIGINAL_REASON,
    }
    result.update(extra)
    return result


def _apply(store: _Store, result: dict[str, object], tmp_path: Path, **kwargs: object) -> dict[str, object]:
    return apply_command_policy_repair(
        store,
        result,
        guard_home=tmp_path,
        repair_page_url=kwargs.get("repair_page_url", lambda _home: _REPAIR_URL),
    )


def test_uncertain_and_protected_blocks_keep_the_original_reason(tmp_path: Path) -> None:
    uncertain = _blocked(reason_code="native_command_extension_uncertain")
    assert _apply(_Store(AuthorityHealth.TAMPERED), uncertain, tmp_path)["reason"] == _ORIGINAL_REASON

    protected = _apply(_Store(AuthorityHealth.PROTECTED), _blocked(), tmp_path)
    assert protected["reason"] == _ORIGINAL_REASON
    assert "repair_url" not in protected


def test_auth_failure_denies_and_links_the_repair_page(tmp_path: Path) -> None:
    result = _apply(_Store(AuthorityHealth.TAMPERED), _blocked(), tmp_path)
    assert result["minimum_action"] == "block"
    assert result["decision"] == "deny"
    assert result["repair_status"] == "approval_required"
    assert result["repair_url"] == _REPAIR_URL
    assert "press Repair protection" in str(result["reason"])
    assert _REPAIR_URL in str(result["reason"])

    rendered = harness_json_from_native_pre_tool("codex", result)
    hook_specific = rendered["hookSpecificOutput"]
    assert isinstance(hook_specific, dict)
    assert hook_specific["permissionDecision"] == "deny"
    assert _REPAIR_URL in str(hook_specific["permissionDecisionReason"])


def test_hook_does_not_rebuild_protection_from_the_blocked_call(tmp_path: Path) -> None:
    result = _apply(_Store(AuthorityHealth.TAMPERED), _blocked(), tmp_path)
    assert result["decision"] == "deny"
    assert result["minimum_action"] == "block"
    assert result["repair_status"] == "approval_required"
    assert result["repair_url"] == _REPAIR_URL
    assert "press Repair protection" in str(result["reason"])


def test_missing_resident_repair_still_sends_the_link(tmp_path: Path) -> None:
    result = _apply(_Store(AuthorityHealth.TAMPERED), _blocked(), tmp_path)
    assert result["repair_status"] == "approval_required"
    assert result["repair_url"] == _REPAIR_URL


def test_non_loopback_url_is_omitted(tmp_path: Path) -> None:
    result = _apply(
        _Store(AuthorityHealth.TAMPERED),
        _blocked(),
        tmp_path,
        repair_page_url=lambda _home: "https://example.com/protection/repair",
    )
    assert "repair_url" not in result
    assert "example.com" not in str(result["reason"])
    assert "Open HOL Guard Extensions and press Repair protection." in str(result["reason"])


def test_page_url_signs_the_loopback_repair_route(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    class _Locator:
        daemon_url = "http://127.0.0.1:5474/"

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.manager.read_approval_center_locator",
        lambda _home: _Locator(),
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.approval_hook_copy.authenticated_approval_review_url",
        lambda url, guard_home, **_kwargs: f"{url}#guard-token=gld1.test",
    )

    assert command_policy_repair_page_url(tmp_path) == ("http://127.0.0.1:5474/protection/repair#guard-token=gld1.test")


def test_repair_link_session_is_limited_to_the_repair_page(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    class _Locator:
        daemon_url = "http://127.0.0.1:5474/"

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.manager.read_approval_center_locator",
        lambda _home: _Locator(),
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.approval_hook_copy.load_guard_daemon_auth_token",
        lambda _home: "repair-test-token",
    )

    signed = command_policy_repair_page_url(tmp_path)
    assert signed is not None
    token = parse_qs(signed.split("#", 1)[1])["guard-token"][0]
    payload = token.split(".")[1]
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    assert claims["surface"] == "protection-repair"


def test_unreadable_native_result_stays_empty(tmp_path: Path) -> None:
    assert apply_command_policy_repair(_Store(AuthorityHealth.TAMPERED), object(), guard_home=tmp_path) == {}


def test_reader_failure_keeps_the_original_denial(tmp_path: Path) -> None:
    class Boom:
        def read_extension_control_authority_for_registry(self, _registry: object) -> object:
            raise RuntimeError("boom")

    result = apply_command_policy_repair(Boom(), _blocked(), guard_home=tmp_path)
    assert result["decision"] == "deny"
    assert "repair_url" not in result


def test_allowed_authority_block_is_not_rewritten(tmp_path: Path) -> None:
    result = apply_command_policy_repair(
        _Store(AuthorityHealth.TAMPERED),
        _blocked(decision="allow"),
        guard_home=tmp_path,
    )
    assert result["decision"] == "allow"
    assert result.get("repair_status") is None


def test_missing_reader_keeps_the_denial(tmp_path: Path) -> None:
    result = apply_command_policy_repair(object(), _blocked(), guard_home=tmp_path)
    assert result.get("repair_status") is None


def test_repair_link_failures_use_the_fallback(tmp_path: Path) -> None:
    def boom(_home: Path) -> str:
        raise RuntimeError("nope")

    raised = apply_command_policy_repair(
        _Store(AuthorityHealth.TAMPERED),
        _blocked(),
        guard_home=tmp_path,
        repair_page_url=boom,
    )
    blank = apply_command_policy_repair(
        _Store(AuthorityHealth.TAMPERED),
        _blocked(),
        guard_home=tmp_path,
        repair_page_url=lambda _home: "",
    )
    assert raised["repair_status"] == "approval_required"
    assert "repair_url" not in raised
    assert blank["repair_status"] == "approval_required"
    assert "repair_url" not in blank


def test_page_url_rejects_unsafe_locators(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.manager.read_approval_center_locator",
        lambda _home: type("Locator", (), {"daemon_url": None})(),
    )
    assert command_policy_repair_page_url(tmp_path) is None

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.manager.read_approval_center_locator",
        lambda _home: type("Locator", (), {"daemon_url": "https://example.com"})(),
    )
    assert command_policy_repair_page_url(tmp_path) is None

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.manager.read_approval_center_locator",
        lambda _home: type("Locator", (), {"daemon_url": "http://127.0.0.1:9"})(),
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.approval_hook_copy.authenticated_approval_review_url",
        lambda *_args, **_kwargs: "https://example.com/protection/repair",
    )
    assert command_policy_repair_page_url(tmp_path) is None


def test_fresh_totp_is_forced_onto_the_repair_grant(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard.daemon import extension_control_api as api

    captured: dict[str, object] = {}

    def require(_home: Path, *, approval_gate_input: object, **_kwargs: object) -> object:
        captured["input"] = approval_gate_input
        return object()

    monkeypatch.setattr(api, "require_extension_control", require)
    monkeypatch.setattr(api, "consume_extension_control_grant", lambda *_args, **_kwargs: None)
    service = api.ExtensionControlApiService.__new__(api.ExtensionControlApiService)
    service._store = type("Store", (), {"guard_home": tmp_path})()
    service._require_action_grant(
        {"session_nonce": "nonce-1"},
        action="recover-authority",
        subject="subject",
        require_fresh_totp=True,
    )
    assert captured["input"].require_fresh_totp is True


def test_hook_repair_does_not_shell_out() -> None:
    source = Path("src/codex_plugin_scanner/guard/daemon/hook_policy_repair.py").read_text(encoding="utf-8")
    assert "subprocess" not in source
    assert "run_guard_command" not in source
    assert "recover-authority" not in source

"""A package install paused because Guard Cloud could not check it says so.

The lockfile-only advice for an ordinary package review is wrong when Cloud is
unavailable: the lockfile-only form is paused the same way.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import local_supply_chain
from codex_plugin_scanner.guard.cli.commands_support_runtime_policy import _localize_pending_approval_copy
from codex_plugin_scanner.guard.cli.protect_approvals import _queue_local_protect_approvals
from codex_plugin_scanner.guard.local_supply_chain import build_package_protect_payload
from codex_plugin_scanner.guard.runtime.package_request_evaluation import (
    PackageRequestEvaluation,
    SupplyChainUserCopy,
)
from codex_plugin_scanner.guard.store import GuardStore

_LOCKFILE_ADVICE = "--frozen-lockfile --ignore-scripts"


def _paused_install_hint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    reasons: tuple[dict[str, str], ...],
) -> str:
    home = tmp_path / "home"
    home.mkdir()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    guard_home = home / ".hol-guard"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("HOL_GUARD_TEST_SKIP_LOCAL_APPROVAL_QUEUE", raising=False)
    store = GuardStore(guard_home)
    message = reasons[0]["message"]
    evaluation = PackageRequestEvaluation(
        decision="review",
        policy_action="review",
        enforcement="enforced",
        entitlement_state="active",
        cache_status="fresh",
        package_intent_hash="c" * 64,
        policy_version="test-policy",
        bundle_version="test-bundle",
        workspace_fingerprint=None,
        reasons=reasons,
        packages=({"name": "example-package", "requestedVersion": "1.0.0", "decision": "review"},),
        risk_summary=message,
        user_copy=SupplyChainUserCopy(
            title="Package paused",
            summary=message,
            next_step=None,
            dashboard_url=None,
            harness_message=message,
        ),
    )
    monkeypatch.setattr(local_supply_chain, "evaluate_package_request_artifact", lambda **_kwargs: evaluation)
    payload, _exit_code = build_package_protect_payload(
        command=["npm", "install", "example-package@1.0.0"],
        store=store,
        workspace_dir=workspace,
        dry_run=True,
        now="2026-10-30T16:00:00Z",
        config=None,
        unsafe_raw_output=False,
        timeout_seconds=10,
    )
    _queue_local_protect_approvals(
        payload,
        store=store,
        guard_home=guard_home,
        workspace=workspace,
        ensure_approval_daemon=lambda _home: "http://127.0.0.1:5474",
        approval_delivery_payload=lambda _harness: {},
        localize_pending_approval_copy=lambda response, harness: _localize_pending_approval_copy(
            response, harness=harness
        ),
    )
    hint = payload.get("review_hint")
    assert isinstance(hint, str), payload.get("verdict")
    return hint


@pytest.mark.parametrize("code", ["cloud_timeout", "cloud_http_error", "cloud_auth_error", "cloud_validation_error"])
def test_a_cloud_outage_pause_does_not_offer_the_lockfile_form(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, code: str
) -> None:
    hint = _paused_install_hint(
        tmp_path,
        monkeypatch,
        ({"code": code, "message": "Guard Cloud evaluation timed out, so this package request is paused."},),
    )

    assert _LOCKFILE_ADVICE not in hint
    assert "Guard Cloud could not check this package" in hint
    assert "not a finding about the package" in hint


def test_an_ordinary_package_review_keeps_the_lockfile_advice(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    hint = _paused_install_hint(
        tmp_path,
        monkeypatch,
        ({"code": "new_package_version", "message": "This package version is new to this workspace."},),
    )

    assert _LOCKFILE_ADVICE in hint
    assert "Guard Cloud could not check" not in hint

"""Watch-only regressions for install-time package protection."""

from __future__ import annotations

import os
import shlex
from dataclasses import replace
from pathlib import Path

import pytest

import codex_plugin_scanner.guard.local_supply_chain as local_supply_chain_module
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.protect import build_protect_payload
from codex_plugin_scanner.guard.runtime.supply_chain_package_eval import (
    PackageRequestEvaluation,
    SupplyChainUserCopy,
)
from codex_plugin_scanner.guard.store import GuardStore


@pytest.fixture(autouse=True)
def _fake_policy_integrity_keyring(install_fake_system_keyring) -> None:
    install_fake_system_keyring()


def _cloud_validation_block() -> PackageRequestEvaluation:
    message = (
        "Guard Cloud could not validate this package request. Guard blocked the install "
        "rather than bypassing Cloud package protection."
    )
    return PackageRequestEvaluation(
        decision="block",
        policy_action="block",
        enforcement="cloud",
        entitlement_state="active",
        cache_status="miss",
        package_intent_hash="server-memory-intent",
        policy_version="cloud-policy-v1",
        bundle_version="cloud-bundle-v1",
        workspace_fingerprint="watch-only-workspace",
        reasons=({"code": "cloud_validation_error", "message": message, "severity": "high"},),
        packages=({"name": "@modelcontextprotocol/server-memory", "decision": "block"},),
        risk_summary=message,
        user_copy=SupplyChainUserCopy(
            title="Package validation unavailable",
            summary=message,
            next_step="Retry package validation.",
            dashboard_url=None,
            harness_message=message,
        ),
    )


@pytest.mark.skipif(os.name == "nt", reason="uses a POSIX package-manager fixture")
def test_watch_only_observes_cloud_validation_block_but_executes_package_install(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    guard_home = tmp_path / "guard-home"
    home = tmp_path / "home"
    home.mkdir()
    marker = tmp_path / "npm-ran.txt"
    executable_dir = tmp_path / "bin"
    executable_dir.mkdir()
    npm = executable_dir / "npm"
    npm.write_text(
        "#!/bin/sh\n"
        f"printf '%s' \"$*\" > {shlex.quote(str(marker))}\n",
        encoding="utf-8",
    )
    npm.chmod(0o755)
    monkeypatch.setenv("PATH", str(executable_dir))
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(
        local_supply_chain_module,
        "evaluate_package_request_artifact",
        lambda **_kwargs: _cloud_validation_block(),
    )
    config = replace(
        GuardConfig(
            guard_home=guard_home,
            workspace=workspace,
            security_level="custom",
            risk_actions={"package_script": "allow", "cloud_advisory": "allow"},
        ),
        mode="observe",
    )
    store = GuardStore(guard_home)

    payload, exit_code = build_protect_payload(
        command=["npm", "install", "@modelcontextprotocol/server-memory@latest"],
        store=store,
        workspace_dir=workspace,
        dry_run=False,
        now="2026-08-08T02:00:00Z",
        config=config,
        unsafe_raw_output=False,
    )

    assert exit_code == 0
    assert payload["executed"] is True
    assert marker.read_text(encoding="utf-8") == "install @modelcontextprotocol/server-memory@latest"
    verdict = payload["verdict"]
    assert isinstance(verdict, dict)
    assert verdict["action"] == "allow"
    assert verdict["blocking"] is False
    assert verdict["observe_mode"] is True
    assert verdict["observed_policy_action"] == "block"
    assert "Watch only observed" in str(verdict["reason"])
    evaluation = payload["supply_chain_evaluation"]
    assert isinstance(evaluation, dict)
    assert evaluation["policy_action"] == "block"
    receipt = payload["receipt"]
    assert isinstance(receipt, dict)
    assert receipt["policy_decision"] == "allow"
    envelope = receipt["action_envelope_json"]
    assert isinstance(envelope, dict)
    assert envelope["policy_action"] == "allow"
    assert envelope["observe_mode"] is True
    assert envelope["observed_policy_action"] == "block"

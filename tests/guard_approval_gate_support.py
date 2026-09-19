"""Local fixtures and helpers for test_guard_approval_gate.py."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

from codex_plugin_scanner.guard import store as guard_store_module
from codex_plugin_scanner.guard.approval_gate import ApprovalGateInput, begin_totp_enrollment, confirm_totp_enrollment
from codex_plugin_scanner.guard.approval_gate import (
    update_settings as update_approval_gate_settings,
)
from codex_plugin_scanner.guard.approvals import apply_approval_resolution
from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.policy_integrity import PolicyIntegrityVerificationResult
from codex_plugin_scanner.guard.runtime.self_approval import _AGENT_ENV_MARKERS
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.totp import totp_code_at_counter


@pytest.fixture(autouse=True)
def _default_store_platform(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(guard_store_module.sys, "platform", "linux")


def _seed_guard_cloud(store, *, workspace_id=None, sync_url=None, token="demo-token", now="2026-05-19T00:00:00Z"):
    """Seed OAuth credentials (replaces legacy set_sync_credentials scaffolding).

    Also installs a test-only resolver override so sync-path exercises stay hermetic
    (no OAuth token refresh against the network). Tests that need real sync against a
    local server pass sync_url=<url>.
    """
    from codex_plugin_scanner.guard.cli.oauth_client import generate_dpop_key_pair
    from codex_plugin_scanner.guard.runtime import runner as guard_runner_module

    dpop_key_material = generate_dpop_key_pair()
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token=token,
        dpop_private_key_pem=dpop_key_material.private_key_pem,
        dpop_public_jwk=dpop_key_material.public_jwk,
        dpop_public_jwk_thumbprint=dpop_key_material.public_jwk_thumbprint,
        grant_id="grant-1",
        machine_id="machine-1",
        workspace_id=workspace_id,
        now=now,
    )
    effective_sync_url = sync_url if sync_url is not None else "https://hol.org/api/guard/receipts/sync"
    guard_runner_module._test_sync_auth_context_override = {
        "sync_url": effective_sync_url,
        "access_token": token,
        "dpop_key_material": None,
    }


PASSWORD = "correct-password"


WRONG_PASSWORD = "wrong-password"


@pytest.fixture(autouse=True)
def _clear_agent_env_markers(monkeypatch: pytest.MonkeyPatch) -> None:
    """Isolate approval-gate tests from agent-harness environment markers.

    The approval CLI refuses to mutate approvals when invoked inside a known
    agent hook context (self-approval defense). When the test suite itself
    runs under such a harness (CI agent shells, local Claude/Cursor/Codex
    sessions), those markers leak into os.environ and flip gate tests to the
    blocked path. Clear them per test; tests that exercise the defense set
    their own marker via monkeypatch.
    """

    for marker in _AGENT_ENV_MARKERS:
        monkeypatch.delenv(marker, raising=False)


def _store(tmp_path: Path) -> GuardStore:
    return GuardStore(tmp_path / "guard-home")


def _trust_local_policy_rows(monkeypatch: pytest.MonkeyPatch) -> None:
    def _valid_policy_row(
        self: GuardStore,
        row,
        *,
        mode: str,
        key: bytes | None,
        key_id: str | None,
        trusted_generation: int | None = None,
    ) -> PolicyIntegrityVerificationResult:
        return PolicyIntegrityVerificationResult(status="valid")

    monkeypatch.setattr(GuardStore, "_policy_integrity_result_for_row", _valid_policy_row)


def _enable_gate(store: GuardStore, *, cooldown_seconds: int = 0, strict_all_decisions: bool = False) -> None:
    update_approval_gate_settings(
        store.guard_home,
        {
            "enabled": True,
            "new_password": PASSWORD,
            "confirm_password": PASSWORD,
            "cooldown_seconds": cooldown_seconds,
            "strict_all_decisions": strict_all_decisions,
        },
    )


def _request(request_id: str) -> GuardApprovalRequest:
    return GuardApprovalRequest(
        request_id=request_id,
        harness="codex",
        artifact_id=f"codex:project:{request_id}",
        artifact_name="Shell command",
        artifact_type="tool_action_request",
        artifact_hash=f"hash-{request_id}",
        policy_action="require-reapproval",
        recommended_scope="artifact",
        changed_fields=("shell_command",),
        source_scope="project",
        config_path="/repo/.codex/config.toml",
        review_command=f"hol-guard approvals approve {request_id}",
        approval_url=f"http://127.0.0.1:5474/requests/{request_id}",
    )


def _add_request(store: GuardStore, request_id: str) -> None:
    store.add_approval_request(_request(request_id), "2026-04-11T00:00:00+00:00")


def _post_daemon_json(
    daemon: GuardDaemonServer,
    path: str,
    payload: dict[str, object],
) -> dict[str, object]:
    request = urllib.request.Request(
        f"http://127.0.0.1:{daemon.port}{path}",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Guard-Token": daemon._server.auth_token},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def _approve(
    store: GuardStore,
    request_id: str,
    *,
    gate_input: ApprovalGateInput | None = None,
    now: str = "2026-04-11T00:01:00+00:00",
) -> dict[str, object]:
    return apply_approval_resolution(
        store=store,
        request_id=request_id,
        action="allow",
        scope="artifact",
        workspace=None,
        reason="reviewed",
        now=now,
        approval_gate_input=gate_input,
    )


def _counter(value: str) -> int:
    return int(datetime.fromisoformat(value).timestamp() // 30)


def _extract_secret(otpauth_uri: str) -> str:
    parsed = urlparse(otpauth_uri)
    query_values = parse_qs(parsed.query)
    values = query_values.get("secret")
    if values is None or len(values) == 0:
        raise AssertionError("otpauth URI did not include a secret")
    return values[0]


def _enable_totp(store: GuardStore, *, now: str) -> str:
    enrollment = begin_totp_enrollment(
        store.guard_home,
        approval_gate_input=ApprovalGateInput(password=PASSWORD),
        device_label="test-device",
        now=now,
    )
    secret = _extract_secret(str(enrollment["otpauth_uri"]))
    code = totp_code_at_counter(secret=secret, counter=_counter(now))
    confirm_totp_enrollment(
        store.guard_home,
        approval_gate_input=ApprovalGateInput(password=PASSWORD, totp_code=code),
        now=now,
    )
    return secret

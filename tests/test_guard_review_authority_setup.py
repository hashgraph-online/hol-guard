"""Review setup must survive new processes without weakening authority failures."""

from __future__ import annotations

import io
import json
import subprocess
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.approval_gate import ApprovalGateInput, update_settings
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    CONTROL_SCHEMA_VERSION,
    ControlLayerKind,
    ExtensionControlLayer,
)
from codex_plugin_scanner.guard.runtime.extension_control_proof import (
    ExtensionControlMutation,
    issue_extension_control_proof,
)
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_review_authority_fixtures import enroll_review_authority


def _lockdown(store: GuardStore) -> None:
    password = "synthetic lockdown fixture password"
    update_settings(store.guard_home, {"enabled": True, "new_password": password, "confirm_password": password})
    layer = ExtensionControlLayer(
        schema_version=CONTROL_SCHEMA_VERSION,
        kind=ControlLayerKind.LOCAL_ADMIN,
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        global_lockdown=True,
        controls=(),
    )
    mutation = ExtensionControlMutation(
        previous_revision=0,
        catalog_digest=layer.catalog_digest,
        layers=(layer,),
        actor_id="lockdown-fixture",
        idempotency_key="lockdown-fixture-change",
        nonce="lockdown-fixture-nonce",
    )
    proof = issue_extension_control_proof(
        store.guard_home,
        mutation,
        approval_gate_input=ApprovalGateInput(password=password),
        session_nonce="lockdown-fixture-session",
    )
    store.commit_extension_control_layers(
        (layer,),
        catalog_digest=layer.catalog_digest,
        actor_id=mutation.actor_id,
        expected_revision=0,
        idempotency_key=mutation.idempotency_key,
        nonce=mutation.nonce,
        proof=proof,
    )


def test_review_authority_is_verified_in_a_fresh_process(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard"
    enroll_review_authority(guard_home)
    # A second workspace may reuse the same protected home without replacing it.
    enroll_review_authority(guard_home)
    program = "\n".join(
        (
            "from pathlib import Path",
            "import sys",
            "from codex_plugin_scanner.guard.store import GuardStore",
            "from codex_plugin_scanner.guard.approval_gate import public_config",
            "from codex_plugin_scanner.guard.runtime import command_extensions",
            "registry = command_extensions.BUILT_IN_COMMAND_EXTENSION_REGISTRY",
            "home = Path(sys.argv[1])",
            "view = GuardStore(home).read_extension_control_authority_for_registry(registry)",
            "print(view.health.value, view.revision, public_config(home).enabled)",
        )
    )
    result = subprocess.run(
        [sys.executable, "-c", program, str(guard_home)], capture_output=True, text=True, check=True, timeout=10
    )
    assert result.stdout.strip() == "protected 0 False"


@pytest.mark.parametrize("authority", ["protected", "unenrolled", "tampered", "lockdown"])
def test_sensitive_review_keeps_actual_authority_barriers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    authority: str,
) -> None:
    home = tmp_path / "home"
    workspace = tmp_path / "workspace"
    home.mkdir()
    workspace.mkdir()
    (home / "config.toml").write_text("approval_wait_timeout_seconds = 0\n", encoding="utf-8")
    if authority != "unenrolled":
        enroll_review_authority(home)
    store = GuardStore(home)
    if authority == "tampered":
        with store._connect() as connection:
            connection.execute("update extension_control_authority_snapshot set snapshot_mac = 'invalid'")
    elif authority == "lockdown":
        _lockdown(store)
    event = {"tool_name": "Read", "tool_input": {"file_path": str(workspace / ".env")}}
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(event)))
    rc = main(["guard", "hook", "--home", str(home), "--workspace", str(workspace), "--harness", "copilot", "--json"])
    output = json.loads(capsys.readouterr().out)
    assert rc == 1
    if authority in {"protected", "unenrolled"}:
        assert output["policy_action"] == "require-reapproval"
        assert store.count_pending_requests(harness="copilot") == 1
    else:
        assert output["policy_action"] == "block"
        assert store.count_pending_requests(harness="copilot") == 0

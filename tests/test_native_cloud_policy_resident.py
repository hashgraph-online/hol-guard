"""Real resident consumption for the bounded signed-defaults authority path."""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_hook_edge import review_raw_hook_native
from codex_plugin_scanner.guard.native_policy_snapshot import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.native_runtime import native_runtime_status
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_native_cloud_policy_activation import _activate_defaults, _signed_defaults_bundle


@pytest.mark.slow
@pytest.mark.parametrize("version", [1, 2])
def test_first_action_after_publish_uses_the_signed_default(tmp_path: Path, version: int) -> None:
    assert os.environ.get("HOL_GUARD_NATIVE_BINARY"), "requires an explicitly selected native runtime artifact"
    status = native_runtime_status()
    assert status.available and status.compatible, status.reason
    store = GuardStore(tmp_path / "guard-home")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    publisher = NativePolicySnapshotPublisher(store=store)

    def evaluate() -> dict[str, object] | None:
        return review_raw_hook_native(
            # The native command parser proves this command benign. Ordinary
            # Read requests have an independent review floor and cannot serve
            # as an allow baseline for testing a policy-only transition.
            payload={"tool_name": "Bash", "tool_input": {"command": "printf synthetic-activation-fixture"}},
            harness="claude-code",
            event="PreToolUse",
            guard_home=store.guard_home,
            home_dir=tmp_path,
            cwd=workspace,
            source_ref_external_allowed=False,
            observe_mode=False,
            deadline=time.monotonic() + 5,
            policy_snapshot=publisher.current_snapshot_binding(),
        )

    try:
        publisher._publish_once()
        assert publisher.is_ready(), publisher.last_error
        before = evaluate()
        assert before is not None
        assert before["result"]["decision"] == "allow", before["result"].get("reason_code")
        bundle, keyring = _signed_defaults_bundle(version, "block")
        _activate_defaults(store, bundle, keyring)
        assert not publisher.is_ready()
        assert evaluate() is None
        publisher._publish_once()
        assert publisher.is_ready(), publisher.last_error
        after = evaluate()
        assert after is not None
        assert after["result"]["decision"] == "deny"
        assert after["result"]["reason_code"] == "native_policy_block"
        binding = publisher.current_snapshot_binding()
        assert binding is not None
        assert after["receipt"]["policy_generation"] == binding["generation"]
        assert after["receipt"]["policy_digest"] == binding["policy_digest"]
        assert before["receipt"]["policy_digest"] != after["receipt"]["policy_digest"]
    finally:
        publisher.close()

"""Create one real native review inside the explicit browser test root only."""

from __future__ import annotations

import argparse
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--guard-home", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    arguments = parser.parse_args()
    root = Path(os.environ["DASHBOARD_E2E_ROOT"]).resolve(strict=True)
    home = arguments.guard_home.resolve(strict=True)
    workspace = arguments.workspace.resolve(strict=True)
    if root == home or not home.is_relative_to(root) or not workspace.is_relative_to(root):
        raise ValueError("native review fixture requires the explicit private browser test root")

    from dashboard_integration_server import _use_file_secret_store

    from codex_plugin_scanner.guard.daemon.hook_native_review_approval import queue_native_pre_tool_review
    from codex_plugin_scanner.guard.models import GuardReceipt
    from codex_plugin_scanner.guard.native_hook_edge import review_raw_hook_native
    from codex_plugin_scanner.guard.store import GuardStore

    # This is a synthetic test home's published policy, not a credential file.
    # The resident verifies the compact reference against its admitted snapshot.
    with (home / "native-runtime" / "policy-snapshot-v3.json").open("rb") as stream:
        encoded = stream.read(16 * 1024 * 1024 + 1)
    if len(encoded) > 16 * 1024 * 1024:
        raise ValueError("fixture policy exceeds the native authority bound")
    snapshot = json.loads(encoded)["snapshot"]
    binding = {key: snapshot[key] for key in ("generation", "policy_digest", "runtime_identity")}
    payload = {
        "tool_name": "exec_command",
        "tool_input": {"cmd": "npm run context-integration-fixture"},
        "cwd": str(workspace),
        "session_id": "context-browser-fixture",
    }
    edge = review_raw_hook_native(
        payload=payload,
        harness="codex",
        event="PreToolUse",
        guard_home=home,
        home_dir=workspace,
        cwd=workspace,
        source_ref_external_allowed=False,
        observe_mode=False,
        deadline=time.monotonic() + 5,
        policy_snapshot=binding,
        request_id="context-browser-native-decision",
    )
    if edge is None:
        raise RuntimeError("fixture native evaluator did not return an authenticated decision")
    if edge["result"]["policy_action"] not in {"review", "require-reapproval"}:
        raise RuntimeError(f"fixture needs a native review, received {edge['result']['policy_action']}")
    store = GuardStore(home, prime_policy_integrity=False)
    _use_file_secret_store(store, home)
    queued = queue_native_pre_tool_review(
        store,
        harness="codex",
        payload=payload,
        native_result=edge["result"],
        native_receipt=edge["receipt"],
        workspace=workspace,
        guard_home=home,
        home_dir=workspace,
        deadline=time.monotonic() + 5,
    )
    if queued is None:
        raise RuntimeError("fixture native review was not queued")
    receipt_id = "context-native-history-evaluation"
    # This evidence fixture records the real evaluation, never an execution
    # acknowledgement. The public store APIs remain native-owned.
    store.record_native_decision_receipt(edge["receipt"])
    store.add_receipt(
        GuardReceipt(
            receipt_id=receipt_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            harness="codex",
            artifact_id=str(queued["artifact_id"]),
            artifact_hash=str(queued["artifact_hash"]),
            policy_decision="review",
            capabilities_summary="Native evaluation requires review; execution is unconfirmed.",
            changed_capabilities=(),
            provenance_summary="Native-derived context history acceptance fixture",
            artifact_name="CIGAR native history evaluation",
            source_scope="project",
            approval_source="hook",
            approval_request_id=str(queued["request_id"]),
        )
    )
    store.set_receipt_action_envelope(receipt_id, queued["action_envelope_json"])
    print(
        json.dumps(
            {
                "request_id": queued["request_id"],
                "decision_id": edge["receipt"]["decision_id"],
                "receipt_id": receipt_id,
            }
        )
    )


if __name__ == "__main__":
    main()

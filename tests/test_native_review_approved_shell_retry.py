"""What an operator's single approval buys the agent's next shell attempt.

The approve-then-retry path is the Gauntlet's ``approved-retry`` lane at
product level: a reviewed command, one grant through the approval UI's own
resolution code, then the agent's retry. A grant is fenced to the reviewed
request by the ``native-review-v4:`` contract the row is queued with, so what
the retry may change — and whether the row carries a contract at all — decides
whether the agent gets through.

Four rounds, each with its own command and its own grant:

* the identical request under the same ``tool_use_id``: allowed, the approval
  is reused, which is the contract working as intended;
* the identical command under a fresh ``tool_use_id``, which is what a real
  Claude Code retry sends, since the model emits a new tool-use block:
  reviewed again. ``request_payload_identity`` drops the transport call id
  from the review anchor only for the ``pi`` and ``omp`` harnesses, so every
  other harness anchors its approval to an id its own retry will not repeat;
* a reworded command: reviewed again, the approval binds the exact action;
* an ordinary ``git status`` command whose row has no once-retry contract:
  attempting once approval is rejected without recording consent, and the
  byte-identical retry remains stopped.

The new-id and reworded cases record the current exact-action boundary. An
unavailable retry must never acquire a misleading saved once decision.

Under the default ``blocked_request_mode = "safe-alternative"`` a review is
rendered to the agent as a plain block with ``prompted`` false, so the queued
inbox row, not the response, says whether an attempt was reviewed.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import pytest

GRANT_REASON = "Approved for the approve-then-retry contract"
REVIEW_ACTIONS = {"review", "require-reapproval"}
RETRY_CONTRACT = "native-review-v4:"


def _payload(command: str, use_id: str, workspace: Path) -> dict[str, object]:
    return {
        "hook_event_name": "PreToolUse",
        "tool_name": "bash",
        "tool_input": {"command": command},
        "session_id": "approved-retry",
        "tool_use_id": use_id,
        "cwd": str(workspace),
    }


def _grant(store: Any, request_id: str, workspace: Path) -> None:
    """Resolve exactly as the approval UI's "Allow just this once" control does."""
    from codex_plugin_scanner.guard.approvals import apply_approval_resolution

    apply_approval_resolution(
        store=store,
        request_id=request_id,
        action="allow",
        scope="artifact",
        workspace=str(workspace),
        reason=GRANT_REASON,
        return_queue_result=True,
        resolve_scope_matches=True,
    )


def _queued(store: Any, seen: set[str]) -> list[dict[str, Any]]:
    """Rows this attempt queued, so earlier rounds' rows are not counted twice."""
    rows = [row for row in store.list_approval_requests(status="pending") if row["request_id"] not in seen]
    seen.update(row["request_id"] for row in rows)
    return rows


def _approve_then_retry(
    worker: Any,
    store: Any,
    kwargs: dict[str, Any],
    workspace: Path,
    seen: set[str],
    *,
    command: str,
    use_id: str,
    retry_command: str | None = None,
    retry_use_id: str | None = None,
    expect_unavailable: bool = False,
) -> dict[str, Any]:
    """Review one command, grant that row, and report what its retry got.

    Each round uses its own command and its own file, so neither the grant
    nor the artifact an earlier round bound can be what a later retry
    matches: an "artifact" grant resolves every pending row that names the
    same artifact, and with the working directory known a path operand is one
    of the things a row is bound to.
    """
    # The HTTP bridge supplies a bounded deadline. Supplying it here also
    # exercises the existing fresh-ACK retry when a grant republishes policy.
    from codex_plugin_scanner.guard.daemon.hook_worker import WORKSPACE_POLICY_READINESS_TIMEOUT_SECONDS

    first = worker.review_http_payload(
        payload=_payload(command, use_id, workspace),
        deadline=time.monotonic() + WORKSPACE_POLICY_READINESS_TIMEOUT_SECONDS,
        **kwargs,
    )
    queued = _queued(store, seen)
    assert first["policy_action"] != "allow", first
    assert len(queued) == 1, (first, queued)
    assert queued[0]["policy_action"] in REVIEW_ACTIONS, queued[0]
    if expect_unavailable:
        from codex_plugin_scanner.guard.approval_scope_support import IneligibleApprovalScopeError

        with pytest.raises(IneligibleApprovalScopeError):
            _grant(store, queued[0]["request_id"], workspace)
        assert store.get_approval_request(queued[0]["request_id"])["status"] == "pending"
    else:
        _grant(store, queued[0]["request_id"], workspace)

    retry_payload = _payload(retry_command or command, retry_use_id or use_id, workspace)
    retry = worker.review_http_payload(
        payload=retry_payload,
        deadline=time.monotonic() + WORKSPACE_POLICY_READINESS_TIMEOUT_SECONDS,
        **kwargs,
    )
    requeued = _queued(store, seen)
    return {
        "policy_action": retry["policy_action"],
        "reason_code": retry.get("reason_code"),
        "granted_binding": queued[0]["artifact_hash"],
        "requeued_bindings": [row["artifact_hash"] for row in requeued],
    }


def test_an_approval_carries_only_the_request_it_was_queued_for(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_approval_reuse_runtime: Path
) -> None:
    from codex_plugin_scanner.guard.config import update_guard_settings
    from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
    from codex_plugin_scanner.guard.store import GuardStore

    home = tmp_path / "home"
    workspace = home / "workspace"
    workspace.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    store = GuardStore(home / ".hol-guard")
    # ``subprocess_action`` is the only configured floor that reaches an ordinary shell
    # command, and only "review" or "require-reapproval" queue an approval row at all.
    update_guard_settings(store.guard_home, {"mode": "enforce", "subprocess_action": "review"})
    worker = HookWorker(store=store, workspace=workspace)
    kwargs = dict(
        params={},
        default_harness="claude-code",
        home_dir=home,
        guard_home=store.guard_home,
        workspace=workspace,
    )
    seen: set[str] = set()
    try:
        same_id = _approve_then_retry(worker, store, kwargs, workspace, seen, command="ls -la", use_id="toolu_ls")
        new_id = _approve_then_retry(
            worker,
            store,
            kwargs,
            workspace,
            seen,
            command="wc -c notes.txt",
            use_id="toolu_wc_first",
            retry_use_id="toolu_wc_retry",
        )
        reworded = _approve_then_retry(
            worker,
            store,
            kwargs,
            workspace,
            seen,
            command="cat ledger.txt",
            use_id="toolu_read",
            retry_command="head -c 200 ledger.txt",
        )
        unbindable = _approve_then_retry(
            worker, store, kwargs, workspace, seen, command="git status --short", use_id="toolu_git",
            expect_unavailable=True,
        )
    finally:
        worker.close()

    outcomes = {"same_id": same_id, "new_id": new_id, "reworded": reworded, "unbindable": unbindable}
    # The whole point of the grant: the request it was queued for runs, once.
    assert same_id["granted_binding"].startswith(RETRY_CONTRACT), outcomes
    assert same_id["policy_action"] == "allow", outcomes
    assert same_id["requeued_bindings"] == [], outcomes
    # #3837: the retry the model actually sends carries a new tool-use id, and
    # the review anchor keeps that id for every harness but pi and omp, so the
    # approval the operator just gave does not cover it.
    assert new_id["granted_binding"].startswith(RETRY_CONTRACT), outcomes
    assert new_id["policy_action"] != "allow", outcomes
    assert len(new_id["requeued_bindings"]) == 1, outcomes
    assert new_id["requeued_bindings"] != [new_id["granted_binding"]], outcomes
    # Same intent, the model's own wording: a different action, so a new review.
    assert reworded["policy_action"] != "allow", outcomes
    assert len(reworded["requeued_bindings"]) == 1, outcomes
    # A reviewed git-status row has no once-retry contract. Resolution was
    # rejected above; the identical retry cannot spend nonexistent consent.
    assert not unbindable["granted_binding"].startswith(RETRY_CONTRACT), outcomes
    assert unbindable["policy_action"] != "allow", outcomes

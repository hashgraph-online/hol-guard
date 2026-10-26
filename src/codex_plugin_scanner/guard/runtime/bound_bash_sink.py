"""CLI delivery to the resident's immutable Bash launch owner.

The request file conveys intent, never a grant. The sink observes its actual
host context, waits for native policy publication, then asks the real store.
Adapters must retain the logical operation id after an uncertain delivery.
"""

from __future__ import annotations

import json
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, TextIO

from ..native_bash_protocol import NativeBashError, execute, observe_host, prepare, request_id
from ..store_base import _workspace_policy_key

if TYPE_CHECKING:
    from ..store import GuardStore


def _authorization(
    store: GuardStore,
    prepared: dict[str, object],
    *,
    harness: str,
    workspace: Path,
) -> dict[str, object]:
    lookup = store.resolve_policy_decision_lookup(
        harness,
        str(prepared["artifact_id"]),
        artifact_hash=str(prepared["artifact_hash"]),
        workspace=str(workspace),
        consume_one_shot=False,
    )
    trust = lookup.get("trust_status")
    if (
        lookup.get("ignored_local_integrity") is not None
        or not isinstance(trust, dict)
        or trust.get("remembered_rules") == "disabled_degraded"
    ):
        raise NativeBashError("native_bash_saved_decision_unreadable")
    decision = lookup.get("decision")
    if decision is None:
        # A once grant may already be spent by this operation. Let the native
        # owner read its authenticated journal before assessing fresh consent.
        # Without a matching record it refuses a consent-required launch before
        # reservation/effects; this variant never substitutes for a grant.
        return {"kind": "current_policy", "store_path": str(store.path)}
    if not isinstance(decision, dict) or decision.get("action") != "allow":
        raise NativeBashError("native_bash_saved_decision_blocked")
    decision_workspace = decision.get("workspace")
    workspace_matches = (
        isinstance(decision_workspace, str)
        and decision_workspace in {str(workspace), _workspace_policy_key(str(workspace))}
    ) or ("workspace" in decision and decision_workspace is None)
    if (
        (not decision.get("approval_id") and decision.get("scope") != "artifact")
        or decision.get("artifact_id") != prepared["artifact_id"]
        or decision.get("artifact_hash") != prepared["artifact_hash"]
        or decision.get("harness") != harness
        or not workspace_matches
    ):
        raise NativeBashError("native_bash_saved_decision_mismatch")
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    # Do not invoke claim_approval_reuse_decisions here: the native owner must
    # claim atomically with journal reservation at its final launch barrier.
    return {
        "kind": "saved_grant",
        "claim": {
            "schema": "guard-claim-approval-reuse-request.v1",
            "request_id": request_id(),
            "store_path": str(store.path),
            "guard_home": str(store.guard_home),
            "decisions": [decision],
            "now": now,
            "consume_local_once": True,
            **store._claim_integrity_evidence([decision], now),
        },
    }


def run_bound_bash(
    payload: dict[str, object],
    *,
    store: GuardStore,
    workspace: Path,
    harness: str,
    operation_id: str,
    timeout_seconds: int = 120,
    output: TextIO | None = None,
    errors: TextIO | None = None,
    host_owner_pid: int | None = None,
    tool_call_id: str | None = None,
) -> int:
    from ..daemon.hook_worker import HookWorker
    from ..hook_execution_environment import HOOK_EXECUTION_ENVIRONMENT_KEY
    from ..native_hook_edge import _encode_hook_envelope

    if (
        harness not in {"omp", "pi"}
        or re.fullmatch(r"[A-Za-z0-9_.:-]{16,128}", operation_id) is None
        or type(timeout_seconds) is not int
        or not 1 <= timeout_seconds <= 120
        or payload.get("hook_event_name") != "PreToolUse"
        or payload.get("tool_name") != "bash"
        or not isinstance(payload.get("tool_input"), dict)
    ):
        raise NativeBashError("native_bash_sink_request_invalid")
    tool_input = payload["tool_input"]
    assert isinstance(tool_input, dict)
    command = tool_input.get("command")
    if not isinstance(command, str) or not command:
        raise NativeBashError("native_bash_sink_request_invalid")
    cwd = Path.cwd().resolve(strict=True)
    # The host has already applied a tool-level cwd. Do not interpret it twice
    # or judge the launch against the earlier session directory's overlays.
    payload = {
        **payload,
        "cwd": str(cwd),
        "tool_input": {key: value for key, value in tool_input.items() if key != "cwd"},
    }
    capture = observe_host(
        {
            "harness": harness,
            "command": command,
            "cwd": str(cwd),
            "workspace": str(workspace.resolve(strict=True)),
            "home_dir": "",
            "guard_home": str(store.guard_home),
            "environment": {},
            "file_creation_mask": None,
            "execution_environment": {
                "path": "",
                "environment_names": [],
                "environment_digest": "",
                "home": None,
                "git_pager_disabled": False,
                "pager_disabled": False,
                "xdg_config_home": None,
                "git_config_no_system": False,
            },
            "budget_ms": 5000,
        },
        cwd=cwd,
    )
    home = Path(str(capture["home_dir"]))
    worker = HookWorker(store=store, workspace=cwd, home_dir=home, wait_for_native_policy=False)
    try:
        snapshot = worker.prepare_workspace_policy(cwd, deadline=time.monotonic() + 25)
        if snapshot is None:
            raise NativeBashError("native_bash_policy_not_ready")
        encoded = _encode_hook_envelope(
            payload={**payload, HOOK_EXECUTION_ENVIRONMENT_KEY: capture["execution_environment"]},
            harness=harness,
            event="PreToolUse",
            guard_home=Path(store.guard_home),
            home_dir=home,
            cwd=cwd,
            source_ref_external_allowed=False,
            deadline_budget_ms=5000,
            snapshot=snapshot,
            execution_context_supported=True,
            request_id=request_id(),
        )
        if encoded is None:
            raise NativeBashError("native_bash_envelope_unavailable")
        envelope = json.loads(encoded)
        prepared = prepare(
            {
                "schema": "guard-native-bash-prepare-request.v1",
                "request_id": request_id(),
                "capture": capture,
                "envelope": envelope,
                "budget_ms": 5000,
            },
            guard_home=Path(store.guard_home),
        )
        authorization = _authorization(store, prepared, harness=harness, workspace=workspace)
        result = execute(
            {
                "schema": "guard-native-bash-execute-request.v1",
                "request_id": request_id(),
                "operation_id": operation_id,
                "capture": capture,
                "envelope": envelope,
                **({"tool_call_id": tool_call_id} if tool_call_id is not None else {}),
                "authorization": authorization,
                "timeout_ms": timeout_seconds * 1000,
            },
            guard_home=Path(store.guard_home),
            cwd=cwd,
            host_owner_pid=host_owner_pid,
        )
        if result["status"] == "error" and result["code"] == "native_bash_consent_required":
            from .bound_bash_review import queue_bound_bash_review

            queue_bound_bash_review(
                {**prepared, "review_lineage": result["review_lineage"]},
                payload,
                store=store,
                harness=harness,
                workspace=workspace,
                home=home,
                errors=errors or sys.stderr,
            )
        return render_result(result, output=output or sys.stdout, errors=errors or sys.stderr)
    finally:
        worker.close()


def render_result(result: dict[str, object], *, output: TextIO, errors: TextIO) -> int:
    if result["status"] == "recorded":
        print(str(result["code"]), file=errors)
        operation = result["operation"]
        if isinstance(operation, dict) and operation["state"] == "completed":
            completion = operation["completion"]
            assert isinstance(completion, dict)
            return _exit_status(completion)
        return 125
    payload = result["payload"]
    if isinstance(payload, dict):
        output.write(str(payload["stdout"]))
        errors.write(str(payload["stderr"]))
    if result["status"] != "ok" or not isinstance(payload, dict):
        print(str(result["code"]), file=errors)
        if result["code"] == "native_bash_operation_kept_blocked":
            print(
                "This user request remains blocked. Guard will not ask again for its retries. "
                "A new user request can be reviewed separately.",
                file=errors,
            )
        elif result["code"] == "native_bash_review_lineage_unavailable":
            print(
                "The pending review could not be verified. Keep this operation blocked and "
                "check the local review store before retrying.",
                file=errors,
            )
        return 125
    return _exit_status(payload)


def _exit_status(completion: dict[str, object]) -> int:
    if completion["timed_out"]:
        return 124
    if completion["cancelled"] or completion["output_limited"]:
        return 125
    code = completion["exit_code"]
    return code if type(code) is int and 0 <= code <= 255 else 125

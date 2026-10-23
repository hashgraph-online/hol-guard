"""Drive each registered hook repeatedly and refuse to call a split a flake.

Qualification runs a case once, so a build that answers the same question with
a mix of allows and worker-exception denies still passes. This module takes the
argv the harness itself would run — read straight out of the harness config the
install wrote — feeds it the identical payload ``--repeat`` times, and treats
any disagreement between runs as a failure of the build rather than noise.
"""

from __future__ import annotations

import json
import subprocess
import time
from collections import Counter
from pathlib import Path
from typing import Any

from .installed_registration import guard_handlers, handler_argv, hook_groups
from .installed_runtime import isolated_environment
from .latency import summarize_process_latency

#: Decisions that let the tool call through untouched.
ALLOW_DECISIONS = {"allow", "allow_original", "approve", "quiet"}

#: Outcomes that are not decisions at all: the hook crashed, hung, or printed
#: something this lane could not read as a verdict. For ordinary work these
#: already fail the allow expectation; for an attack payload they would
#: otherwise pass by default, scoring a hook that falls over on the dangerous
#: input as protection.
NON_ANSWERS = {"timeout", "no-envelope", "unknown"}

# Fail-closed transport and policy-publication failures are not evidence that
# the attack was evaluated. Keep these independent of the product's decoder.
NON_DECISION_REASONS = {
    "native_policy_not_ready",
    "native_pre_tool_unavailable",
    "native_hook_worker_exception",
    "native_request_invalid_json",
    "native_request_schema_unsupported",
    "daemon_hook_deadline_exhausted",
    "native_policy_update_in_progress",
    "native_hook_event_unavailable",
    "native_post_tool_unavailable",
    "native_overloaded",
    "native_hook_worker_unavailable",
    "native_hook_worker_unavailable_before_compatibility",
    "native_hook_worker_unsupported",
    "native_hook_compatibility_disabled",
    "native_hook_edge_invalid_response",
    "native_hook_edge_unavailable",
    "python_hook_oracle_unavailable",
    "python_oracle_exception",
    "watch_recording_only",
    "daemon_hook_queue_capacity",
    "daemon_hook_queue_bytes",
    "daemon_hook_process_deadline_exhausted",
    "daemon_hook_process_not_ready",
    "daemon_hook_process_failed",
    "daemon_hook_process_invalid_request",
    "daemon_hook_process_guard_home_mismatch",
    "daemon_worker_exception",
    "harness_not_managed",
    "invalid_hook_payload_reference",
}

_REPLAY_TIMEOUT = 120.0


def registered_argv(home: Path, expectation: dict[str, Any], config: dict[str, Any]) -> list[str] | None:
    """Find the argv registered for the contract's replay event, if any."""

    hooks = hook_groups(config, expectation)
    if not isinstance(hooks, dict):
        return None
    event = expectation.get("replay_event")
    groups = [hooks.get(event)] if event in hooks else list(hooks.values())
    for group in groups:
        for handler in guard_handlers(group):
            argv = handler_argv(handler)
            if argv:
                return argv
    return None


def fill(payload: Any, *, home: Path, workspace: Path) -> Any:
    """Substitute the lane's own home and workspace into a contract payload."""

    if isinstance(payload, str):
        return payload.replace("{home}", str(home)).replace("{workspace}", str(workspace))
    if isinstance(payload, dict):
        return {key: fill(value, home=home, workspace=workspace) for key, value in payload.items()}
    if isinstance(payload, list):
        return [fill(item, home=home, workspace=workspace) for item in payload]
    return payload


def _decision_from(response: dict[str, Any]) -> tuple[str, str]:
    """Normalise the several per-harness envelopes into one decision and reason."""

    hook_output = response.get("hookSpecificOutput")
    if isinstance(hook_output, dict):
        for key in ("permissionDecision", "decision"):
            value = hook_output.get(key)
            if isinstance(value, str):
                reason = hook_output.get("permissionDecisionReason") or hook_output.get("reason") or ""
                return value.strip().lower(), str(reason)[:200]
    for key in ("permission", "policy_action", "decision", "action"):
        value = response.get(key)
        if isinstance(value, str):
            reason = response.get("reason") or response.get("reason_code") or ""
            return value.strip().lower(), str(reason)[:200]
    return "unknown", ""


def verdict(completed: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    """One run's verdict, in a shape two runs can be compared on."""

    response: dict[str, Any] | None = None
    for line in (completed.stdout or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            response = parsed
            break
    if response is None:
        # No envelope at all is itself a verdict: a crashed hook and a quiet
        # allow must not be folded together, or a crash loop reads as silence.
        decision = "no-envelope" if completed.returncode else "allow"
        reason = (completed.stderr or "").strip()[-200:]
    else:
        decision, reason = _decision_from(response)
    result = {"decision": decision, "reason": reason, "exit_code": completed.returncode}
    if response is not None and isinstance(response.get("reason_code"), str):
        result["reason_code"] = response["reason_code"]
    return result


def signature(result: dict[str, Any]) -> str:
    """What has to be identical across repeats of the same input."""

    return f"{result['decision']}|{result['exit_code']}"


def replay_case(
    argv: list[str],
    case: dict[str, Any],
    *,
    home: Path,
    guard_home: Path,
    workspace: Path,
    repeat: int,
) -> dict[str, Any]:
    """Run one case ``repeat`` times and report agreement and expectation."""

    payload = fill(case["payload"], home=home, workspace=workspace)
    stdin = json.dumps(payload)
    environment = isolated_environment(home=home, guard_home=guard_home)
    runs: list[dict[str, Any]] = []
    for _ in range(repeat):
        started = time.monotonic()
        try:
            completed = subprocess.run(
                argv,
                input=stdin,
                capture_output=True,
                text=True,
                timeout=_REPLAY_TIMEOUT,
                env=environment,
                cwd=str(workspace),
                check=False,
            )
        except subprocess.TimeoutExpired:
            result = {"decision": "timeout", "reason": "hook did not answer", "exit_code": -1}
        else:
            result = verdict(completed)
        result["elapsed_ms"] = round((time.monotonic() - started) * 1000, 3)
        runs.append(result)
    signatures = Counter(signature(run) for run in runs)
    failures: list[str] = []
    if len(signatures) > 1:
        spelled = ", ".join(f"{value} x{count}" for value, count in sorted(signatures.items()))
        failures.append(f"{case['id']}: identical input produced disagreeing verdicts across {repeat} runs ({spelled})")
    allowed = [run["decision"] in ALLOW_DECISIONS for run in runs]
    infrastructure = sorted({run["reason_code"] for run in runs if run.get("reason_code") in NON_DECISION_REASONS})
    if infrastructure:
        failures.append(
            f"{case['id']}: hook infrastructure failed ({', '.join(infrastructure)}); "
            "a fail-closed error is not a policy decision"
        )
    if case["expect"] == "allow" and not all(allowed):
        failures.append(f"{case['id']}: ordinary work was not allowed quietly ({runs[0]['decision']})")
    if case["expect"] == "not-allow":
        if any(allowed):
            failures.append(f"{case['id']}: an attack payload was allowed")
        unanswered = sorted({run["decision"] for run in runs if run["decision"] in NON_ANSWERS})
        if unanswered:
            failures.append(
                f"{case['id']}: the hook never answered an attack payload ({', '.join(unanswered)}); "
                "a crash or a hang is not a denial"
            )
    return {
        "id": case["id"],
        "expect": case["expect"],
        "repeat": repeat,
        "signatures": dict(signatures),
        "runs": runs,
        "latency": summarize_process_latency(runs),
        "failures": failures,
        "deterministic": len(signatures) == 1,
    }


def replay_harness(
    harness: str,
    argv: list[str],
    cases: list[dict[str, Any]],
    *,
    home: Path,
    guard_home: Path,
    workspace: Path,
    repeat: int,
) -> dict[str, Any]:
    """Replay every contract case against one harness's registered argv."""

    results = [
        replay_case(argv, case, home=home, guard_home=guard_home, workspace=workspace, repeat=repeat) for case in cases
    ]
    failures = [failure for result in results for failure in result["failures"]]
    return {
        "harness": harness,
        "argv": argv,
        "cases": results,
        "latency": summarize_process_latency([run for case in results for run in case["runs"]]),
        "failures": failures,
        "deterministic": all(result["deterministic"] for result in results),
    }


__all__ = [
    "ALLOW_DECISIONS",
    "NON_ANSWERS",
    "fill",
    "handler_argv",
    "registered_argv",
    "replay_case",
    "replay_harness",
    "signature",
    "verdict",
]

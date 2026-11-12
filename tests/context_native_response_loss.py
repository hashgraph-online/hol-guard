"""Lose an owned delivery host after real native dispatch, before rendering.

The caller gets an abrupt exit and no execution reply. No RPC or journal answer
is fabricated. Exercise completed delivery and a still-active partial effect;
neither case proves atomicity at an unobserved dispatch/consume boundary.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path

LOST_REPLY_EXIT = 91


def lose_completed_reply(payload, *, guard_home: Path, workspace: Path, operation_id: str) -> dict:
    result = subprocess.run(
        [sys.executable, "-B", str(Path(__file__).resolve())],
        input=json.dumps(
            {
                "payload": payload,
                "guard_home": str(guard_home),
                "workspace": str(workspace),
                "operation_id": operation_id,
            }
        ),
        capture_output=True,
        text=True,
        timeout=60,
        cwd=workspace,
    )
    assert result.returncode == LOST_REPLY_EXIT, result.stderr
    assert not result.stdout and not result.stderr, "lost delivery host returned an execution response"
    return {
        "host_exit": result.returncode,
        "stdout_bytes": len(result.stdout.encode()),
        "stderr_bytes": len(result.stderr.encode()),
        "caller_received_execution_reply": False,
        "scope": "completed native effect; Python delivery host exits before sink rendering",
    }


def lose_running_reply(payload, *, guard_home: Path, workspace: Path, operation_id: str, report: Path, barrier) -> dict:
    from codex_plugin_scanner.guard.native_bash_protocol import activity

    process = subprocess.Popen(
        [sys.executable, "-B", str(Path(__file__).resolve())],
        cwd=workspace,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert process.stdin is not None
        process.stdin.write(
            json.dumps(
                {
                    "payload": payload,
                    "guard_home": str(guard_home),
                    "workspace": str(workspace),
                    "operation_id": operation_id,
                    "phase": "running",
                }
            )
            + "\n"
        )
        process.stdin.flush()
        deadline = time.monotonic() + 30
        while True:
            assert process.poll() is None, "owned delivery host exited before the active effect barrier"
            if barrier.entered.is_set() and report.exists() and report.read_text() == "installed-cigar-owner\n":
                observed = activity(operation_id, guard_home=guard_home)
                if observed["active"] and not observed["cancellation_requested"]:
                    break
            assert time.monotonic() < deadline, "real native partial effect did not become active"
            time.sleep(0.05)
        lost_at = time.monotonic()
        process.kill()  # Only this directly owned Popen delivery host.
        stdout, stderr = process.communicate(timeout=5)
        assert process.returncode == -9 and not stdout and not stderr
        deadline = time.monotonic() + 8
        while activity(operation_id, guard_home=guard_home)["active"]:
            assert time.monotonic() < deadline, "native owner did not retire the lost host's active command"
            time.sleep(0.05)
        assert report.read_text() == "installed-cigar-owner\n", "cancelled command continued past its partial effect"
        barrier.release.set()
        return {
            "host_exit": process.returncode,
            "stdout_bytes": len(stdout.encode()),
            "stderr_bytes": len(stderr.encode()),
            "caller_received_execution_reply": False,
            "native_active_and_partial_effect_before_host_loss": True,
            "owned_loopback_request_observed": True,
            "native_activity_retired_after_host_loss": True,
            "retirement_ms": round((time.monotonic() - lost_at) * 1000, 3),
            "scope": "native effect active after first write; directly owned Python delivery host killed",
        }
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=5)


@contextmanager
def observe_native_reply(monkeypatch):
    """Retain only actual native journal/completion metadata; change no result."""
    from codex_plugin_scanner.guard.runtime import bound_bash_sink as sink

    original = sink.execute
    observed = []

    def execute(*args, **kwargs):
        result = original(*args, **kwargs)
        operation = result.get("operation") or {}
        completion = operation.get("completion") or {}
        observed.append(
            {
                "status": result["status"],
                "replayed": result["replayed"],
                "grant_claimed": result["grant_claimed"],
                "state": operation.get("state"),
                **{key: completion.get(key) for key in ("cancelled", "timed_out", "output_limited")},
            }
        )
        return result

    with monkeypatch.context() as scoped:
        scoped.setattr(sink, "execute", execute)
        yield observed


def main() -> None:
    from codex_plugin_scanner.guard.runtime import bound_bash_sink as sink
    from codex_plugin_scanner.guard.store import GuardStore

    spec = json.loads(sys.stdin.readline(64 * 1024))
    original = sink.execute

    def completed_then_lost(*args, **kwargs):
        result = original(*args, **kwargs)
        assert result["status"] == "ok", result["code"]
        assert result["dispatch_acknowledged"] and not result["replayed"]
        assert result["operation"]["state"] == "completed"
        assert sink._exit_status(result["payload"]) == 0
        # Kill this owned fixture host before its caller can receive or render
        # the real execution result. Normal native authority already completed.
        os._exit(LOST_REPLY_EXIT)

    if spec.get("phase", "completed") == "completed":
        sink.execute = completed_then_lost
    sink.run_bound_bash(
        spec["payload"],
        store=GuardStore(Path(spec["guard_home"]), prime_policy_integrity=False),
        workspace=Path(spec["workspace"]),
        harness="omp",
        operation_id=spec["operation_id"],
    )
    raise AssertionError("fixture did not reach the completed native effect")


if __name__ == "__main__":
    main()

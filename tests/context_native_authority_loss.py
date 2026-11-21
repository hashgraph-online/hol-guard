"""Crash only a verified native owner after its real first effect.

Process identities stay in memory. Reports contain bounded codes and counts.
No signal targets a pre-existing Guard process or uses an unverified PID.
"""

from __future__ import annotations

import io
import json
import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path
from unittest.mock import patch

from scripts.cigar_benchmark_processes import kernel_image
from tests.context_process_fault import _digest, _lineage, _snapshot


def verify_authority(owned, binary: Path, rows) -> int:
    pid = owned.native
    if pid == os.getpid() or not _lineage(rows, pid):
        raise AssertionError("native authority is not a current fixture descendant")
    if any(not row.same(rows.get(member)) for member, row in owned.lineage.items()):
        raise AssertionError("native authority lineage changed before the fault")
    if any(kernel_image(member) != image for member, image in owned.images.items()):
        raise AssertionError("captured native family image changed before the fault")
    image = kernel_image(pid)
    if image != owned.images[pid] or image is None or _digest(image) != _digest(binary):
        raise AssertionError("native authority image differs from the selected artifact")
    return pid


def _live_captured(captured):
    rows = _snapshot()
    return [
        pid
        for pid, original in captured.items()
        if pid in rows and rows[pid].start == original.start and not rows[pid].state.startswith("Z")
    ]


def lose_native_owner_reply(payload, *, guard_home, project, operation, report, barrier, owned, binary, metrics):
    from codex_plugin_scanner.guard.native_bash_protocol import activity

    process = subprocess.Popen(
        [sys.executable, "-B", str(Path(__file__).resolve())],
        cwd=project,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    captured, images = {}, {}
    try:
        process.stdin.write(
            json.dumps(
                {"payload": payload, "guard_home": str(guard_home), "project": str(project), "operation": operation}
            )
            + "\n"
        )
        process.stdin.flush()
        deadline = time.monotonic() + 30
        while True:
            assert process.poll() is None, "delivery host exited before the active native effect"
            if barrier.entered.is_set() and report.exists() and report.read_text() == "installed-cigar-owner\n":
                state = activity(operation, guard_home=guard_home)
                if state["active"] and not state["cancellation_requested"]:
                    break
            assert time.monotonic() < deadline, "native effect never reached the owned loopback barrier"
            time.sleep(0.05)
        rows = _snapshot()
        pid = verify_authority(owned, binary, rows)
        captured = {member: row for member, row in rows.items() if member == pid or pid in _lineage(rows, member)}
        images = {member: kernel_image(member) for member in captured}
        assert all(image is not None for image in images.values())
        assert owned.bridge in captured and all(worker in captured for worker in owned.workers)
        metrics.update(
            native_active_and_partial_effect_before_owner_loss=True,
            owned_loopback_request_observed=True,
            captured_native_family_count=len(captured),
            owner_lineage_and_artifact_verified=True,
            qualified_optional_workers_at_fault=len(owned.workers),
        )
        # Revalidate immediately before this one signal. Never signal a group.
        assert verify_authority(owned, binary, _snapshot()) == pid
        os.kill(pid, signal.SIGKILL)
        metrics["native_owner_signals"] = 1
        stdout, stderr = process.communicate(timeout=20)
        assert process.returncode == 0 and not stderr, "owned delivery host could not report its bounded refusal"
        assert len(stdout.encode()) <= 4096
        response = json.loads(stdout)
        assert response["sink_exit"] == 125, response
        assert response["code"] in {
            "native_bash_execution_reply_unavailable",
            "native_bash_operation_in_progress_or_uncertain",
        }, response
        observed = response["native_reply"]
        if response["code"] == "native_bash_operation_in_progress_or_uncertain":
            assert (
                observed["status"] == "recorded" and observed["replayed"] is True and observed["grant_claimed"] is True
            )
            assert observed["state"] in {"claimed", "dispatched", "uncertain"}
            assert observed["completion_absent"] is True and observed["payload_absent"] is True
        else:
            assert observed is None
        metrics.update(caller_received_execution_completion=False, delivery_refusal=response)
        deadline = time.monotonic() + 8
        while _live_captured(captured) and time.monotonic() < deadline:
            time.sleep(0.05)
        metrics["captured_family_remaining"] = len(_live_captured(captured))
        assert metrics["captured_family_remaining"] == 0, "native owner crash left its captured family running"
        barrier.release.set()
        time.sleep(0.2)
        assert report.read_text() == "installed-cigar-owner\n", "old effect continued after authority loss"
        metrics["partial_effect_preserved_without_continuation"] = True
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=5)
        # Fallback containment is explicitly counted and cannot qualify a pass.
        for pid in _live_captured(captured):
            row = _snapshot().get(pid)
            if (
                row is None
                or row.start != captured[pid].start
                or row.group != captured[pid].group
                or kernel_image(pid) != images[pid]
            ):
                continue
            try:
                os.kill(pid, signal.SIGKILL)
                metrics["fallback_signals"] += 1
            except ProcessLookupError:
                pass


def main():
    from codex_plugin_scanner.guard.native_bash_protocol import NativeBashError
    from codex_plugin_scanner.guard.runtime import bound_bash_sink as sink
    from codex_plugin_scanner.guard.store import GuardStore

    spec = json.loads(sys.stdin.readline(64 * 1024))
    errors, output = io.StringIO(), io.StringIO()
    observed = None
    original = sink.execute

    def execute(*args, **kwargs):
        nonlocal observed
        result = original(*args, **kwargs)
        operation = result.get("operation") or {}
        observed = {
            "status": result["status"],
            "replayed": result["replayed"],
            "grant_claimed": result["grant_claimed"],
            "state": operation.get("state"),
            "completion_absent": operation.get("completion") is None,
            "payload_absent": result.get("payload") is None,
        }
        return result

    try:
        with patch.object(sink, "execute", execute):
            status = sink.run_bound_bash(
                spec["payload"],
                store=GuardStore(Path(spec["guard_home"]), prime_policy_integrity=False),
                workspace=Path(spec["project"]),
                harness="omp",
                operation_id=spec["operation"],
                output=output,
                errors=errors,
            )
        code = errors.getvalue().strip()
        if not re.fullmatch(r"native_bash_[a-z0-9_]{1,80}", code):
            code = "unexpected_sink_reply"
    except NativeBashError as error:
        status = 125
        code = error.code if re.fullmatch(r"native_bash_[a-z0-9_]{1,80}", error.code) else "unexpected_native_refusal"
    assert not output.getvalue(), "lost native execution returned output"
    print(json.dumps({"sink_exit": status, "code": code, "native_reply": observed}))


if __name__ == "__main__":
    main()

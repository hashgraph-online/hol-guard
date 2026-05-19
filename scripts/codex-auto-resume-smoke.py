#!/usr/bin/env python3
"""Real headless Codex browser-approval auto-resume smoke test."""

from __future__ import annotations

import argparse
import errno
import json
import os
import pty
import re
import select
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

ALLOW_SENTINEL = "HOL_GUARD_CANARY_TOKEN_PRESENT"
PROOF_FILE_NAME = "guard-proof.txt"
_APPROVAL_URL_PATTERN = re.compile(r"http://127\.0\.0\.1:(?P<port>\d+)/approvals/(?P<request_id>[0-9a-f]+)")


@dataclass
class SmokeScenarioResult:
    decision: str
    request_id: str
    resume_status: str
    resume_strategy: str | None
    proof_created: bool
    assistant_message: str
    transcript_excerpt: str

    def to_dict(self) -> dict[str, object]:
        return {
            "decision": self.decision,
            "request_id": self.request_id,
            "resume_status": self.resume_status,
            "resume_strategy": self.resume_strategy,
            "proof_created": self.proof_created,
            "assistant_message": self.assistant_message,
            "transcript_excerpt": self.transcript_excerpt,
        }


def main() -> int:
    args = _parse_args()
    if shutil.which("codex") is None:
        raise SystemExit("codex binary not found in PATH")
    allow_result = _run_scenario(decision="allow", args=args)
    block_result = _run_scenario(decision="block", args=args)
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "codex_version": _codex_version(),
        "allow": allow_result.to_dict(),
        "block": block_result.to_dict(),
    }
    print(json.dumps(payload, indent=2))
    return 0


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the real Codex browser-approval auto-resume smoke flow.")
    parser.add_argument(
        "--codex-home",
        help="Optional CODEX_HOME override. Leave unset to keep the current authenticated Codex home.",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=180.0,
        help="Maximum wait for the Codex process to finish after the approval decision.",
    )
    parser.add_argument(
        "--request-timeout-seconds",
        type=float,
        default=120.0,
        help="Maximum wait for Guard to queue the pending approval request.",
    )
    parser.add_argument(
        "--keep-temp-dir",
        action="store_true",
        help="Keep the per-scenario temporary directory for debugging.",
    )
    return parser.parse_args()


def _run_scenario(*, decision: str, args: argparse.Namespace) -> SmokeScenarioResult:
    temp_dir = Path(tempfile.mkdtemp(prefix=f"hol-guard-codex-resume-{decision}-"))
    completed = False
    try:
        result = _run_scenario_in_dir(decision=decision, args=args, temp_dir=temp_dir)
        completed = True
        return result
    except Exception as error:
        raise RuntimeError(f"{error}\nartifacts preserved at {temp_dir}") from error
    finally:
        if completed and not args.keep_temp_dir:
            shutil.rmtree(temp_dir, ignore_errors=True)


def _run_scenario_in_dir(*, decision: str, args: argparse.Namespace, temp_dir: Path) -> SmokeScenarioResult:
    from codex_plugin_scanner.guard.daemon import GuardDaemonServer
    from codex_plugin_scanner.guard.store import GuardStore

    home_dir = temp_dir / "home"
    workspace_dir = temp_dir / "workspace"
    guard_home = home_dir
    stdout_path = temp_dir / f"{decision}-codex.stdout.jsonl"
    stderr_path = temp_dir / f"{decision}-codex.stderr.txt"
    message_path = temp_dir / f"{decision}-last-message.txt"
    proof_path = workspace_dir / PROOF_FILE_NAME

    _write_text(home_dir / ".codex" / "config.toml", 'model = "gpt-5"\n')
    _write_text(
        workspace_dir / ".codex" / "config.toml",
        'approval_policy = "never"\n\n[features]\ncodex_hooks = true\n',
    )
    workspace_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q"], cwd=workspace_dir, check=True, capture_output=True, text=True)

    _run_guard_cli(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ],
        home_dir=home_dir,
        codex_home=args.codex_home,
    )

    store = GuardStore(guard_home)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        transcript_chunks: list[str] = []
        request_id = uuid.uuid4().hex
        process, master_fd = _start_codex_exec(
            decision=decision,
            home_dir=home_dir,
            workspace_dir=workspace_dir,
            message_path=message_path,
            codex_home=args.codex_home,
            guard_daemon_port=daemon.port,
            request_id=request_id,
        )
        try:
            _wait_for_process_exit(
                process=process,
                master_fd=master_fd,
                transcript_chunks=transcript_chunks,
                timeout_seconds=args.request_timeout_seconds,
            )
            transcript = "".join(transcript_chunks)
            thread_id = _thread_id_from_transcript(transcript)
            if thread_id is None:
                raise RuntimeError(f"codex exec did not emit a resumable thread id\nstdout:\n{transcript}\n")
            _queue_pending_request(
                store=store,
                request_id=request_id,
                thread_id=thread_id,
                workspace_dir=workspace_dir,
                daemon_port=daemon.port,
                codex_home=_scenario_env(home_dir=home_dir, codex_home=args.codex_home).get("CODEX_HOME"),
            )
            action_path = "approve" if decision == "allow" else "block"
            approval_payload = _post_json(
                port=daemon.port,
                token=daemon._server.auth_token,
                path=f"/v1/requests/{request_id}/{action_path}",
                payload={"scope": "artifact", "reason": f"{decision}-smoke"},
                timeout_seconds=args.timeout_seconds,
            )
            resume_payload = _get_json(
                port=daemon.port,
                token=daemon._server.auth_token,
                path=f"/v1/requests/{request_id}/resume",
                timeout_seconds=30.0,
            )
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)
            _drain_pty(master_fd=master_fd, transcript_chunks=transcript_chunks, block=False)
            os.close(master_fd)
    finally:
        daemon.stop()

    transcript = "".join(transcript_chunks)
    stdout_path.write_text("".join(transcript_chunks), encoding="utf-8")
    stderr_path.write_text("", encoding="utf-8")
    if process.returncode != 0:
        raise RuntimeError(
            f"codex exec failed for {decision}: rc={process.returncode}\n"
            f"stdout:\n{stdout_path.read_text(encoding='utf-8')}\n"
        )
    final_message = message_path.read_text(encoding="utf-8").strip() if message_path.is_file() else ""
    proof_created = _wait_for_proof_state(proof_path=proof_path, should_exist=decision == "allow", timeout_seconds=20.0)
    proof_created = _wait_for_proof_state(proof_path=proof_path, should_exist=decision == "allow", timeout_seconds=20.0)
    stderr_text = stderr_path.read_text(encoding="utf-8")
    _assert_expected_outcome(
        decision=decision,
        final_message=str(resume_payload.get("message") or final_message),
        approval_payload=approval_payload,
        proof_created=proof_created,
        stderr_text=stderr_text,
    )

    return SmokeScenarioResult(
        decision=decision,
        request_id=request_id,
        resume_status=str(resume_payload["status"]),
        resume_strategy=_optional_string(resume_payload.get("strategy")),
        proof_created=proof_created,
        assistant_message=str(resume_payload.get("message") or final_message),
        transcript_excerpt=_sanitize_excerpt(transcript),
    )


def _start_codex_exec(
    *,
    decision: str,
    home_dir: Path,
    workspace_dir: Path,
    message_path: Path,
    codex_home: str | None,
    guard_daemon_port: int,
    request_id: str,
) -> tuple[subprocess.Popen[bytes], int]:
    prompt = _codex_prompt(decision, request_id=request_id)
    command = [
        "codex",
        "exec",
        "--json",
        "--skip-git-repo-check",
        "--dangerously-bypass-hook-trust",
        "--ignore-user-config",
        "--output-last-message",
        str(message_path),
        prompt,
    ]
    master_fd, slave_fd = pty.openpty()
    try:
        process = subprocess.Popen(
            command,
            cwd=workspace_dir,
            env=_scenario_env(
                home_dir=home_dir,
                codex_home=codex_home,
                guard_daemon_port=guard_daemon_port,
            ),
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            close_fds=True,
        )
        return process, master_fd
    except Exception:
        os.close(master_fd)
        raise
    finally:
        os.close(slave_fd)


def _scenario_env(*, home_dir: Path, codex_home: str | None, guard_daemon_port: int | None = None) -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = _pythonpath_value(env.get("PYTHONPATH"))
    resolved_codex_home = codex_home or os.environ.get("CODEX_HOME") or str(Path.home() / ".codex")
    env["CODEX_HOME"] = resolved_codex_home
    if guard_daemon_port is not None:
        env["GUARD_DAEMON_PORT"] = str(guard_daemon_port)
    return env


def _pythonpath_value(existing: str | None) -> str:
    if not existing:
        return str(SRC_ROOT)
    return os.pathsep.join([str(SRC_ROOT), existing])


def _run_guard_cli(argv: list[str], *, home_dir: Path, codex_home: str | None) -> dict[str, object] | None:
    command = [sys.executable, "-m", "codex_plugin_scanner.cli", *argv]
    result = subprocess.run(
        command,
        cwd=REPO_ROOT,
        env=_scenario_env(home_dir=home_dir, codex_home=codex_home),
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"guard CLI failed: {' '.join(command)}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    stdout = result.stdout.strip()
    if not stdout:
        return None
    try:
        return json.loads(stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"guard CLI returned non-JSON output:\n{stdout}") from error


def _wait_for_pending_request(
    *,
    guard_home: Path,
    process: subprocess.Popen[bytes],
    master_fd: int,
    transcript_chunks: list[str],
    timeout_seconds: float,
) -> dict[str, object]:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        _drain_pty(master_fd=master_fd, transcript_chunks=transcript_chunks, block=False)
        if process.poll() is not None:
            raise RuntimeError(
                "codex exec exited before Guard queued a pending request\n"
                f"stdout:\n{''.join(transcript_chunks)}\n"
            )
        time.sleep(0.5)
    raise TimeoutError(f"Codex did not finish the seed session within {timeout_seconds:.1f}s")


def _wait_for_process_exit(
    *,
    process: subprocess.Popen[bytes],
    master_fd: int,
    transcript_chunks: list[str],
    timeout_seconds: float,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        _drain_pty(master_fd=master_fd, transcript_chunks=transcript_chunks, block=False)
        if process.poll() is not None:
            return
        time.sleep(0.2)
    raise TimeoutError(f"codex exec did not finish within {timeout_seconds:.1f}s")


def _drain_pty(*, master_fd: int, transcript_chunks: list[str], block: bool) -> None:
    timeout = 0.2 if block else 0.0
    while True:
        ready, _, _ = select.select([master_fd], [], [], timeout)
        if not ready:
            return
        try:
            data = os.read(master_fd, 4096)
        except OSError as error:
            if error.errno == errno.EIO:
                return
            raise
        if not data:
            return
        transcript_chunks.append(data.decode("utf-8", errors="ignore"))
        timeout = 0.0


def _request_from_transcript(transcript: str) -> dict[str, object] | None:
    match = None
    for candidate in _APPROVAL_URL_PATTERN.finditer(transcript):
        match = candidate
    if match is None:
        return None
    return {
        "request_id": match.group("request_id"),
        "approval_port": int(match.group("port")),
    }


def _approval_port_from_transcript(transcript: str) -> int | None:
    request = _request_from_transcript(transcript)
    if request is None:
        return None
    return int(request["approval_port"])


def _post_json(
    *,
    port: int,
    token: str,
    path: str,
    payload: dict[str, object],
    timeout_seconds: float = 10.0,
) -> dict[str, object]:
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Guard-Token": token},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        return json.loads(response.read().decode("utf-8"))


def _get_json(*, port: int, token: str, path: str, timeout_seconds: float = 10.0) -> dict[str, object]:
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        headers={"X-Guard-Token": token},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        body = error.read().decode("utf-8")
        raise RuntimeError(f"resume status request failed: {error.code} {body}") from error


def _daemon_auth_token(guard_home: Path) -> str | None:
    try:
        token = (guard_home / "daemon-auth-token").read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return token or None


def _codex_prompt(decision: str, *, request_id: str) -> str:
    command = _proof_command()
    if decision == "allow":
        return (
            f"Remember this exact shell command for HOL Guard request `{request_id}`, but do not run it yet:\n"
            f"{command}\n"
            f"If a later HOL Guard message says HOL Guard approved request `{request_id}`, "
            f"run that exact command and then respond with ONLY {ALLOW_SENTINEL}. "
            "For now, respond with ONLY READY."
        )
    return (
        f"Remember this exact shell command for HOL Guard request `{request_id}`, but do not run it yet:\n"
        f"{command}\n"
        f"If a later HOL Guard message says HOL Guard blocked request `{request_id}`, "
        "do not run that command and explain one safe alternative in one short sentence. "
        "For now, respond with ONLY READY."
    )


def _assert_expected_outcome(
    *,
    decision: str,
    final_message: str,
    approval_payload: dict[str, object],
    proof_created: bool,
    stderr_text: str,
) -> None:
    codex_resume = approval_payload.get("codex_resume")
    if not isinstance(codex_resume, dict):
        raise AssertionError("approval payload did not include codex_resume")
    status = str(codex_resume.get("status") or "")
    if status != "sent":
        raise AssertionError(f"expected codex_resume status 'sent', got {status!r}")
    if decision == "allow":
        if not proof_created:
            raise AssertionError("allow flow did not create the proof file")
        if not final_message.strip():
            raise AssertionError("allow flow returned an empty resume message")
        return
    if proof_created:
        raise AssertionError("block flow unexpectedly created the proof file")
    if not final_message.strip():
        raise AssertionError(f"block flow returned an empty message\nstderr:\n{stderr_text}")
    normalized = final_message.lower()
    if not any(keyword in normalized for keyword in ("codex", "guard", "retry", "alternative", "blocked")):
        raise AssertionError(f"block flow did not return resume guidance: {final_message!r}")


def _sanitize_excerpt(transcript: str) -> str:
    lines = [line.strip() for line in transcript.splitlines() if line.strip()]
    excerpt = "\n".join(lines[-8:])
    return excerpt


def _thread_id_from_transcript(transcript: str) -> str | None:
    prefix = '{"type":"thread.started","thread_id":"'
    for line in transcript.splitlines():
        if not line.startswith(prefix):
            continue
        suffix = line.removeprefix(prefix)
        thread_id, _, _ = suffix.partition('"')
        if thread_id:
            return thread_id
    return None


def _proof_command() -> str:
    return (
        "python3 - <<'PY'\n"
        "from pathlib import Path\n"
        f"Path('{PROOF_FILE_NAME}').write_text('HOL Guard allow proof\\n', encoding='utf-8')\n"
        f"print('{ALLOW_SENTINEL}')\n"
        "PY"
    )


def _queue_pending_request(
    *,
    store,
    request_id: str,
    thread_id: str,
    workspace_dir: Path,
    daemon_port: int,
    codex_home: str | None,
) -> None:
    from codex_plugin_scanner.guard.consumer import artifact_hash
    from codex_plugin_scanner.guard.models import GuardApprovalRequest
    from codex_plugin_scanner.guard.runtime.secret_file_requests import (
        build_tool_action_request_artifact,
        extract_sensitive_tool_action_request,
    )

    now = datetime.now(timezone.utc).isoformat()
    config_path = workspace_dir / ".codex" / "config.toml"
    request_match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": _proof_command()},
        cwd=workspace_dir,
        home_dir=workspace_dir.parent,
    )
    if request_match is None:
        raise RuntimeError("proof command did not classify as a sensitive tool action")
    artifact = build_tool_action_request_artifact(
        "codex",
        request_match,
        config_path=str(config_path),
        source_scope="project",
    )
    session = store.upsert_guard_session(
        session_id=f"session-{request_id}",
        harness="codex",
        surface="harness-adapter",
        status="waiting_on_approval",
        client_name="codex-smoke",
        client_title="Codex smoke",
        client_version="1.0.0",
        workspace=str(workspace_dir),
        capabilities=["approval-resolution"],
        now=now,
    )
    store.upsert_guard_operation(
        operation_id=f"operation-{request_id}",
        session_id=str(session["session_id"]),
        harness="codex",
        operation_type="tool_call",
        status="waiting_on_approval",
        approval_request_ids=[request_id],
        resume_token=f"resume-{request_id}",
        metadata={
            "codex_thread_id": thread_id,
            "session_id": thread_id,
            "codex_home": codex_home,
            "command_text": _proof_command(),
            "tool_name": "Bash",
            "event": "PreToolUse",
        },
        now=now,
    )
    store.add_approval_request(
        GuardApprovalRequest(
            request_id=request_id,
            harness="codex",
            artifact_id=artifact.artifact_id,
            artifact_name=artifact.name,
            artifact_hash=artifact_hash(artifact),
            policy_action="require-reapproval",
            recommended_scope="artifact",
            changed_fields=("args",),
            source_scope=artifact.source_scope,
            config_path=artifact.config_path,
            workspace=str(workspace_dir),
            launch_target=request_match.command_text,
            review_command=f"hol-guard approvals approve {request_id}",
            approval_url=f"http://127.0.0.1:{daemon_port}/approvals/{request_id}",
            artifact_type=artifact.artifact_type,
            risk_summary=str(
                artifact.metadata.get("runtime_request_summary") or "Requested a sensitive native tool action."
            ),
            risk_signals=tuple(
                str(item)
                for item in artifact.metadata.get("runtime_request_signals", [])
                if isinstance(item, str)
            ),
            artifact_label="Native shell action",
            source_label="Codex remembered command",
            trigger_summary=str(
                artifact.metadata.get("request_summary") or "Queued for Codex exec resume verification."
            ),
            why_now="This verifies browser approval auto-resume for Codex exec sessions.",
            launch_summary="Writes a proof file only after approval.",
            risk_headline="Sensitive native tool action needs approval.",
        ),
        now,
    )


def _wait_for_proof_state(*, proof_path: Path, should_exist: bool, timeout_seconds: float) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        exists = proof_path.is_file()
        if exists == should_exist:
            return exists
        time.sleep(0.2)
    return proof_path.is_file()


def _optional_string(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value
    return None


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _codex_version() -> str:
    result = subprocess.run(["codex", "--version"], capture_output=True, text=True, timeout=10, check=False)
    return result.stdout.strip() or result.stderr.strip() or "unknown"


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Codex app-server browser-approval continuation smoke test."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
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

ALLOW_SENTINEL = "HOL_GUARD_ALLOW_PROOF_PRESENT"
PROOF_FILE_NAME = "guard-proof.txt"
_WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


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
    parser = argparse.ArgumentParser(description="Run the Codex same-thread browser-approval continuation smoke flow.")
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
    proof_path = workspace_dir / PROOF_FILE_NAME

    _write_text(home_dir / ".codex" / "config.toml", 'model = "gpt-5"\n')
    _write_text(workspace_dir / ".codex" / "config.toml", 'approval_policy = "never"\n\n[features]\nhooks = true\n')
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
    captured_payloads: list[dict[str, object]] = []
    socket_path = temp_dir / "c.sock"
    codex_server = _start_fake_codex_app_server(socket_path, captured_payloads, f"thread-smoke-{decision}")

    daemon.start()
    try:
        thread_id = f"thread-smoke-{decision}"
        request_id = uuid.uuid4().hex
        _queue_pending_request(
            store=store,
            request_id=request_id,
            thread_id=thread_id,
            workspace_dir=workspace_dir,
            daemon_port=daemon.port,
            codex_home=args.codex_home,
            socket_path=socket_path,
            operation_status="waiting_on_approval",
        )
        action_path = "approve" if decision == "allow" else "block"
        approval_payload = _post_json(
            port=daemon.port,
            token=daemon._server.auth_token,
            path=f"/v1/requests/{request_id}/{action_path}",
            payload={"scope": "artifact", "reason": f"{decision}-smoke"},
            timeout_seconds=args.timeout_seconds,
        )
        resume_payload = approval_payload.get("codex_resume") if isinstance(approval_payload, dict) else None
        if not isinstance(resume_payload, dict):
            raise RuntimeError(f"approval response did not include codex_resume: {approval_payload}")
    finally:
        daemon.stop()
        codex_server.join(timeout=1.0)

    transcript = "\n".join(json.dumps(payload, sort_keys=True) for payload in captured_payloads)
    proof_created = proof_path.is_file()
    resume_message = str(resume_payload.get("message") or "")
    _assert_expected_outcome(
        decision=decision,
        final_message=resume_message,
        approval_payload=approval_payload,
        proof_created=proof_created,
        transcript=transcript,
    )

    return SmokeScenarioResult(
        decision=decision,
        request_id=request_id,
        resume_status=str(resume_payload["status"]),
        resume_strategy=_optional_string(resume_payload.get("strategy")),
        proof_created=proof_created,
        assistant_message=resume_message,
        transcript_excerpt=_sanitize_excerpt(transcript),
    )


def _start_headless_codex_thread(
    *,
    workspace_dir: Path,
    home_dir: Path,
    codex_home: str | None,
    stdout_path: Path,
    stderr_path: Path,
) -> tuple[str, str]:
    command = [
        "codex",
        "exec",
        "--json",
        "--skip-git-repo-check",
        "--sandbox",
        "danger-full-access",
        "-c",
        'approval_policy="never"',
        "-C",
        str(workspace_dir.resolve()),
        "Say exactly HOL_GUARD_RESUME_READY.",
    ]
    result = subprocess.run(
        command,
        cwd=workspace_dir.resolve(),
        env=_scenario_env(home_dir=home_dir, codex_home=codex_home),
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    stdout_path.write_text(result.stdout, encoding="utf-8")
    stderr_path.write_text(result.stderr, encoding="utf-8")
    if result.returncode != 0:
        raise RuntimeError(f"codex exec failed to create a resumable thread: rc={result.returncode}\n{result.stderr}")
    thread_id = _thread_id_from_transcript(result.stdout)
    if thread_id is None:
        raise RuntimeError(f"codex exec did not emit a thread id:\n{result.stdout}")
    return thread_id, result.stdout


def _start_fake_codex_app_server(
    socket_path: Path,
    received: list[dict[str, object]],
    thread_id: str,
) -> threading.Thread:
    def server() -> None:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(socket_path))
            listener.listen(1)
            connection, _ = listener.accept()
            with connection:
                headers = _recv_until(connection, b"\r\n\r\n").decode("iso-8859-1")
                key = ""
                for line in headers.split("\r\n"):
                    if line.lower().startswith("sec-websocket-key:"):
                        key = line.split(":", 1)[1].strip()
                        break
                accept = base64.b64encode(hashlib.sha1((key + _WEBSOCKET_GUID).encode("ascii")).digest()).decode(
                    "ascii"
                )
                connection.sendall(
                    (
                        "HTTP/1.1 101 Switching Protocols\r\n"
                        "Connection: Upgrade\r\n"
                        "Upgrade: websocket\r\n"
                        f"Sec-WebSocket-Accept: {accept}\r\n"
                        "\r\n"
                    ).encode("ascii")
                )
                while True:
                    opcode, payload = _recv_websocket_frame(connection)
                    if opcode != 0x1:
                        continue
                    message = json.loads(payload.decode("utf-8"))
                    received.append(message)
                    if message.get("id") == 1:
                        _send_websocket_text(
                            connection,
                            {
                                "id": 1,
                                "result": {
                                    "userAgent": "smoke",
                                    "codexHome": "/tmp",
                                    "platformFamily": "unix",
                                    "platformOs": "macos",
                                },
                            },
                        )
                    if message.get("id") == 2:
                        _send_websocket_text(connection, {"id": 2, "result": {"threadId": thread_id}})
                    if message.get("id") == 3:
                        _send_websocket_text(connection, {"id": 3, "result": {"turnId": "turn-smoke"}})
                        time.sleep(0.05)
                        _send_websocket_text(
                            connection,
                            {
                                "method": "turn/completed",
                                "params": {
                                    "threadId": thread_id,
                                    "turn": {
                                        "id": "turn-smoke",
                                        "status": "completed",
                                    },
                                },
                            },
                        )
                        break

    thread = threading.Thread(target=server, name="codex-app-server-smoke", daemon=True)
    thread.start()
    for _ in range(50):
        if socket_path.exists():
            break
        time.sleep(0.01)
    return thread


def _recv_until(connection: socket.socket, marker: bytes) -> bytes:
    data = b""
    while marker not in data:
        chunk = connection.recv(4096)
        if not chunk:
            raise RuntimeError("socket closed before marker")
        data += chunk
    return data


def _recv_exact(connection: socket.socket, length: int) -> bytes:
    data = b""
    while len(data) < length:
        chunk = connection.recv(length - len(data))
        if not chunk:
            raise RuntimeError("socket closed before frame completed")
        data += chunk
    return data


def _recv_websocket_frame(connection: socket.socket) -> tuple[int, bytes]:
    first, second = _recv_exact(connection, 2)
    length = second & 0x7F
    if length == 126:
        length = struct.unpack("!H", _recv_exact(connection, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", _recv_exact(connection, 8))[0]
    mask = _recv_exact(connection, 4) if second & 0x80 else None
    payload = _recv_exact(connection, length) if length else b""
    if mask is not None:
        payload = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    return first & 0x0F, payload


def _send_websocket_text(connection: socket.socket, payload: dict[str, object]) -> None:
    data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    length = len(data)
    if length < 126:
        header = bytes([0x81, length])
    elif length < 65_536:
        header = bytes([0x81, 126]) + struct.pack("!H", length)
    else:
        header = bytes([0x81, 127]) + struct.pack("!Q", length)
    connection.sendall(header + data)


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
        raise RuntimeError(f"guard CLI failed: {' '.join(command)}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}")
    stdout = result.stdout.strip()
    if not stdout:
        return None
    try:
        return json.loads(stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"guard CLI returned non-JSON output:\n{stdout}") from error


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


def _assert_expected_outcome(
    *,
    decision: str,
    final_message: str,
    approval_payload: dict[str, object],
    proof_created: bool,
    transcript: str,
) -> None:
    codex_resume = approval_payload.get("codex_resume")
    if not isinstance(codex_resume, dict):
        raise AssertionError("approval payload did not include codex_resume")
    status = str(codex_resume.get("status") or "")
    if decision == "allow":
        if status not in {"in_progress", "sent", "already_sent"}:
            raise AssertionError(f"expected codex_resume status to show live continuation, got {status!r}")
        if "turn/start" not in transcript:
            raise AssertionError(f"same-thread Codex app-server prompt was not sent:\n{transcript}")
        if proof_created:
            raise AssertionError("allow smoke must not start a separate headless Codex proof run")
        if not final_message.strip():
            raise AssertionError("allow flow returned an empty resume message")
        return
    if status != "skipped":
        raise AssertionError(f"expected blocked Codex request not to resume, got {status!r}")
    if str(codex_resume.get("reason") or "") != "blocked_not_resumed":
        raise AssertionError(f"block flow returned unexpected resume reason: {codex_resume!r}")
    if "turn/start" in transcript:
        raise AssertionError(f"block flow must not send a same-thread Codex prompt:\n{transcript}")
    if proof_created:
        raise AssertionError("block flow unexpectedly created the proof file")
    if not final_message.strip():
        raise AssertionError(f"block flow returned an empty message\ntranscript:\n{transcript}")
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
    socket_path: Path,
    operation_status: str = "waiting_on_approval",
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
        status=operation_status,
        approval_request_ids=[request_id],
        resume_token=f"resume-{request_id}",
        metadata={
            "codex_thread_id": thread_id,
            "session_id": thread_id,
            "codex_home": codex_home,
            "codex_app_server_socket": str(socket_path),
            "command_text": _proof_command(),
            "tool_name": "Bash",
            "event": "PostToolUse",
            "hook_event_name": "PostToolUse",
            "codex_hook_waits_for_browser_approval": True,
            "codex_browser_wait_deadline_at": "2000-01-01T00:00:00+00:00",
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
                str(item) for item in artifact.metadata.get("runtime_request_signals", []) if isinstance(item, str)
            ),
            artifact_label="Native shell action",
            source_label="Codex remembered command",
            trigger_summary=str(
                artifact.metadata.get("request_summary") or "Queued for Codex same-thread continuation verification."
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
    if shutil.which("codex") is None:
        return "codex not found"
    result = subprocess.run(["codex", "--version"], capture_output=True, text=True, timeout=10, check=False)
    return result.stdout.strip() or result.stderr.strip() or "unknown"


if __name__ == "__main__":
    raise SystemExit(main())

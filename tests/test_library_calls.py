from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.guard.library_calls import run_library_call
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.store import GuardStore

COPY = {
    "codex": {"title": "Approved. Retry in chat.", "body": "Return to Codex and retry"},
    "": {"title": "Approved. Retry in chat.", "body": "Return to your AI assistant and retry"},
}


def _call(home: Path, name: str, args: object) -> dict[str, object]:
    return run_library_call(home, json.dumps({"call": name, "args": args}).encode("utf-8"))


def _seed(home: Path) -> None:
    GuardStore(home).add_approval_request(
        GuardApprovalRequest(
            request_id="req-lib",
            harness="codex",
            artifact_id="codex:session:prompt:demo",
            artifact_name="prompt request",
            artifact_type="prompt_request",
            artifact_hash="hash-lib",
            policy_action="require-reapproval",
            recommended_scope="artifact",
            changed_fields=("prompt_request",),
            source_scope="session",
            config_path=str(home / "workspace" / ".codex" / "config.toml"),
            review_command="hol-guard approvals approve req-lib",
            approval_url="http://127.0.0.1/pending/req-lib",
        ),
        "2026-05-01T00:00:00+00:00",
    )


def _resolve_args(**overrides: object) -> dict[str, object]:
    args: dict[str, object] = {
        "request_id": "req-lib",
        "action": "allow",
        "scope": "artifact",
        "payload": {"scope": "artifact"},
        "resolve_scope_matches": True,
        "copy": COPY,
    }
    args.update(overrides)
    return args


def test_malformed_and_unknown_calls_are_library_errors(tmp_path: Path) -> None:
    assert run_library_call(tmp_path, b"not json")["error"]["kind"] == "library_call"  # type: ignore[index]
    assert run_library_call(tmp_path, b"[]")["error"]["kind"] == "library_call"  # type: ignore[index]
    unknown = _call(tmp_path, "no.such.call", {})
    assert unknown["error"] == {"type": "LibraryCallError", "message": "unknown_call", "kind": "library_call"}
    missing_args = _call(tmp_path, "approval.resolve", {"action": "allow"})
    assert missing_args["error"]["kind"] == "library_call"  # type: ignore[index]


def test_unknown_request_is_not_found(tmp_path: Path) -> None:
    answer = _call(tmp_path, "approval.resolve", _resolve_args(request_id="req-missing"))
    assert answer["error"]["kind"] == "not_found"  # type: ignore[index]


def test_invalid_remember_is_a_value_error(tmp_path: Path) -> None:
    _seed(tmp_path)
    answer = _call(tmp_path, "approval.resolve", _resolve_args(payload={"scope": "artifact", "remember": "maybe"}))
    assert answer["error"]["kind"] == "value"  # type: ignore[index]
    assert answer["error"]["message"] == "invalid boolean value"  # type: ignore[index]


def test_resolve_applies_copy_and_repeats_are_idempotent(tmp_path: Path) -> None:
    _seed(tmp_path)
    answer = _call(tmp_path, "approval.resolve", _resolve_args())
    updated = answer["ok"]["updated"]  # type: ignore[index]
    # The Codex continuation finds no chat to resume, so it replaces the copy.
    assert updated["copy"]["title"] == "Decision saved. Return to Codex."
    assert updated["retry_hint"] == updated["copy"]["body"]
    stored = GuardStore(tmp_path).get_approval_request("req-lib")
    assert isinstance(stored, dict)
    assert stored["status"] != "pending"
    assert stored["resolution_action"] == "allow"
    assert GuardStore(tmp_path).list_events(event_name="approval_resolved")

    repeat = _call(tmp_path, "approval.resolve", _resolve_args())
    body = repeat["ok"]["idempotent"]  # type: ignore[index]
    assert body["resolved"] is True
    assert body["idempotent"] is True

    conflict = _call(tmp_path, "approval.resolve", _resolve_args(action="block"))
    assert conflict["ok"] == {"already_resolved": True}


def test_resolve_rejects_a_missing_copy_table(tmp_path: Path) -> None:
    _seed(tmp_path)
    answer = _call(tmp_path, "approval.resolve", _resolve_args(copy={}))
    assert answer["error"]["kind"] == "library_call"  # type: ignore[index]


def test_cli_answers_one_call_on_stdout(tmp_path: Path) -> None:
    import subprocess
    import sys

    command = [sys.executable, "-m", "codex_plugin_scanner.cli", "guard", "desktop", "library-call"]
    command += ["--guard-home", str(tmp_path)]
    request = json.dumps({"call": "no.such.call", "args": {}}).encode("utf-8")
    completed = subprocess.run(
        command,
        input=request,
        capture_output=True,
        check=False,
        timeout=60,
    )
    assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")
    assert json.loads(completed.stdout)["error"]["message"] == "unknown_call"

    empty = subprocess.run(
        command,
        input=b"",
        capture_output=True,
        check=False,
        timeout=60,
    )
    assert empty.returncode == 2
    assert empty.stdout == b""

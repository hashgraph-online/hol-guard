"""Record the Cursor client's answers to the review and prompt responses a resident returns.

The generated client renders a daemon response with `_emit_cursor_response`.
`_cursor_reason` passes a review link through `live_approval_review_url`,
which it imports from Guard, as the client does under Guard's own
interpreter. Each vector is rendered from a Guard home that holds no daemon
auth token and from one that does, with the session clock fixed at
`NOW` so a signed link is reproducible.

Run from the repository root:

    .venv/bin/python rust/crates/guard-runtime/testdata/cursor_hook_bridge/record_cursor_review_vectors.py
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from datetime import datetime, timezone
from unittest import mock

from codex_plugin_scanner.guard import local_dashboard_session
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.cursor_hooks import cursor_hook_script_source
from codex_plugin_scanner.guard.approval_link_output import native_review_reason

OUT = Path(__file__).with_name("cursor_review_vectors.json")
SCHEMA = "hol-guard-cursor-native-review-answers.v1"
NOW = datetime(2026, 1, 2, 3, 4, 5, 678901, tzinfo=timezone.utc)
TOKEN = "3f" * 32
LOOPBACK = "http://127.0.0.1:4781/approvals/0123456789abcdef"
LOCALHOST = "http://localhost:4781/approvals/r-1"
EXTERNAL = "https://guard.example.test/approvals/r1"
TOOL_EVENTS = ["preToolUse", " PreToolUse ", "beforeShellExecution", "beforeMCPExecution", "beforeReadFile"]
PROMPT_EVENTS = ["UserPromptSubmit", "prompt"]


class _FixedClock(datetime):
    """`datetime` with `now` fixed at `NOW`."""

    @classmethod
    def now(cls, tz: timezone | None = None) -> datetime:  # type: ignore[override]
        return NOW.astimezone(tz) if tz is not None else NOW.replace(tzinfo=None)


def _client(guard_home: Path) -> dict[str, object]:
    context = HarnessContext(home_dir=guard_home.parent, guard_home=guard_home, workspace_dir=None)
    source = cursor_hook_script_source(context, guard_cli=[sys.executable], recovery_command=[sys.executable])
    namespace: dict[str, object] = {"__name__": "cursor_review_fixture"}
    exec(compile(source, "generated-cursor-hook", "exec"), namespace)
    return namespace


def _rendered(client: dict[str, object], event: str, response: dict[str, object]) -> tuple[str, int]:
    emit = client["_emit_cursor_response"]
    answer, exit_code = emit(  # type: ignore[operator]
        hook_event_name=event,
        policy_action=response["policy_action"],
        guard_payload=response,
    )
    return json.dumps(answer) + "\n", exit_code


def _pause(reason: str, url: str, *, action: str = "review") -> dict[str, object]:
    """The shape `render_pre_tool_review` gives a paused Cursor review."""

    return {
        "policy_action": action,
        "reason_code": "native_policy_review",
        "reason": reason,
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "ask",
            "permissionDecisionReason": reason,
        },
        "approval_url": url,
        "approval_request_id": "0123456789abcdef",
        "primary_approval_request_id": "0123456789abcdef",
        "primary_approval_url": url,
        "guardApprovalRequestId": "0123456789abcdef",
        "guardApprovalUrl": url,
        "approval_requests": [{"request_id": "0123456789abcdef", "approval_url": url}],
        "prompted": True,
        "approval_center_url": "http://127.0.0.1:4781",
    }


def _responses(guard_home: Path, tokened: bool) -> list[tuple[str, dict[str, object]]]:
    review = "Reading .env needs review."
    urls = [EXTERNAL] if tokened else [LOOPBACK, LOCALHOST, EXTERNAL]
    responses: list[tuple[str, dict[str, object]]] = []
    for url in urls:
        # The resident writes the link into a Cursor pause's reason as the
        # daemon's `native_review_reason` does.
        linked = native_review_reason("cursor", review, url, guard_home=guard_home)
        responses.append(("pause", _pause(linked, url)))
        responses.append(("pause-reapproval", _pause(linked, url, action="require-reapproval")))
        responses.append(("pause-reason-without-link", _pause(review, url)))
        responses.append(("pause-without-reason", {"policy_action": "review", "approval_url": f" {url} "}))
        responses.append(("block-with-link", {"policy_action": "block", "reason": "r", "approval_url": url}))
        responses.append(
            (
                "queued-link",
                {
                    "policy_action": "review",
                    "risk_summary": "  why  ",
                    "approval_requests": [{"request_id": "x"}, "y", {"approval_url": f"\t{url}\n"}],
                },
            )
        )
        responses.append(
            (
                "decision-reason",
                {"policy_action": "sandbox-required", "guardApprovalUrl": url, "decision_v2_json": {"user_title": "t"}},
            )
        )
    if tokened:
        # The client signs a loopback link only when it can import Guard.
        for url in [LOOPBACK, LOCALHOST, "http://[::1]:4781/approvals/r_1"]:
            responses.append(("pause-signed", _pause(f"{review} Open HOL Guard to approve: {url}.", url)))
            responses.append(("block-with-link", {"policy_action": "block", "reason": "r", "approval_url": url}))
        responses.append(("allow-with-link", {"policy_action": "allow", "approval_url": LOOPBACK}))
    responses.extend(
        [
            ("review-without-link", {"policy_action": "review", "reason": "Needs a look.", "reason_code": "c"}),
            ("reapproval-without-link", {"policy_action": "require-reapproval", "stopReason": " s "}),
            ("review-without-reason", {"policy_action": "review"}),
            (
                "prompt-allow",
                {
                    "policy_action": "allow",
                    "reason_code": "native_policy_allow",
                    "hookSpecificOutput": {"hookEventName": "UserPromptSubmit"},
                },
            ),
            (
                "prompt-block",
                {
                    "decision": "block",
                    "reason": 'Prompt blocked: é "q"',
                    "systemMessage": "Prompt blocked.",
                    "policy_action": "block",
                    "reason_code": "native_prompt_block",
                    "hookSpecificOutput": {"hookEventName": "UserPromptSubmit"},
                },
            ),
            (
                "prompt-review",
                {
                    "decision": "block",
                    "reason": "Prompt needs review.",
                    "systemMessage": "Prompt needs review.",
                    "policy_action": "review",
                    "reason_code": "native_prompt_review",
                    "hookSpecificOutput": {"hookEventName": "UserPromptSubmit"},
                },
            ),
        ]
    )
    return responses


def _record(label: str, guard_home: Path, tokened: bool) -> list[dict[str, object]]:
    client = _client(guard_home)
    vectors: list[dict[str, object]] = []
    for name, response in _responses(guard_home, tokened):
        events = PROMPT_EVENTS if name.startswith("prompt") else TOOL_EVENTS
        for event in events:
            stdout, exit_code = _rendered(client, event, response)
            vectors.append(
                {
                    "home": label,
                    "case": name,
                    "event": event,
                    "response": json.dumps(response),
                    "stdout": stdout,
                    "exit_code": exit_code,
                }
            )
    return vectors


def main() -> None:
    with tempfile.TemporaryDirectory() as root:
        untokened = Path(root) / "untokened" / ".hol-guard"
        tokened = Path(root) / "tokened" / ".hol-guard"
        for home in (untokened, tokened):
            home.mkdir(parents=True, mode=0o700)
            home.chmod(0o700)
        token = tokened / "daemon-auth-token"
        token.write_text(TOKEN, encoding="utf-8")
        token.chmod(0o600)
        with mock.patch.object(local_dashboard_session, "datetime", _FixedClock):
            vectors = _record("untokened", untokened, False) + _record("tokened", tokened, True)
    now_micros = (NOW - datetime(1970, 1, 1, tzinfo=timezone.utc)) // datetime.resolution
    document = {"schema": SCHEMA, "now_micros": now_micros, "vectors": vectors}
    OUT.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    signed = sum("#guard-token=" in vector["stdout"] for vector in vectors)
    print(f"wrote {len(vectors)} vectors ({signed} with a signed link) to {OUT.name}")


if __name__ == "__main__":
    main()

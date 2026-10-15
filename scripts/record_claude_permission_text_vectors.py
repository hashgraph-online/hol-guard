#!/usr/bin/env python3
"""Record parity vectors for the Claude Code permission reply text.

The expected answers come from the Python helpers the daemon uses today
(``claude_permission_request_response``, the daemon's permission prompt
``Notification`` answer, and the message helpers in
``commands_support_claude_approval``). The resident's port in
``hook_direct_claude_permission_text.rs`` replays every vector. The store
peek is replaced by the vector's notice, the mark-seen is a no-op and the
recorded event is captured: the resident's caller owns all three.

Usage: python scripts/record_claude_permission_text_vectors.py [--check]
Deterministic output.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

# Importing the command package binds the helper modules' shared names.
from codex_plugin_scanner.guard.cli import commands as _commands  # noqa: E402, F401
from codex_plugin_scanner.guard.cli import commands_support_claude_approval as approval  # noqa: E402
from codex_plugin_scanner.guard.cli import commands_support_hook_state as hook_state  # noqa: E402
from codex_plugin_scanner.guard.cli.commands_support_runtime_policy import (  # noqa: E402
    _claude_notification_tool_display_name,
    _claude_notification_tool_name,
)
from codex_plugin_scanner.guard.daemon.claude_permission_request import (  # noqa: E402
    claude_permission_request_response,
)
from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker  # noqa: E402

OUT = ROOT / "rust/crates/guard-runtime/tests/fixtures/claude_permission_text_vectors.json"
DEFAULT_REASON = "HOL Guard requires review before this action can execute."
OPTIONS = ["Allow once", "Allow during this session", "Keep blocked"]
LONG = "Reads " + "a very long credential path segment " * 40


def payload(**fields: object) -> dict[str, object]:
    base: dict[str, object] = {
        "hook_event_name": "PermissionRequest",
        "session_id": "session-1",
        "tool_name": "Bash",
        "tool_input": {"command": "cat ~/.ssh/id_rsa"},
    }
    base.update(fields)
    return {key: value for key, value in base.items() if value is not ...}


def notice(**fields: object) -> dict[str, object]:
    base: dict[str, object] = {
        "artifact_type": "tool_action",
        "tool_name": "Bash",
        "reason": "Reads an SSH private key",
        "approval_header": "HOL Guard",
        "approval_question": "HOL Guard intercepted this sensitive action. What should Claude do?",
        "approval_options": list(OPTIONS),
    }
    base.update(fields)
    return {key: value for key, value in base.items() if value is not ...}


def package(**fields: object) -> dict[str, object]:
    return notice(**{"artifact_type": "package_request", **fields})


def cases() -> list[tuple[str, dict[str, object], dict[str, object] | None]]:
    no_tool = payload(tool_name=...)
    return [
        ("no-notice", payload(), None),
        ("no-notice-no-tool", no_tool, None),
        ("ask-default", payload(), notice()),
        ("ask-empty-notice", payload(), {}),
        ("ask-no-reason", payload(), notice(reason=...)),
        ("ask-blank-reason", payload(), notice(reason="")),
        ("ask-whitespace-reason", payload(), notice(reason=" \t\n ")),
        ("ask-unicode-whitespace-reason", payload(), notice(reason="\u3000\u00a0\u2028")),
        ("ask-padded-reason", payload(), notice(reason="\u2003 Reads a key \x1c")),
        ("ask-reason-bang", payload(), notice(reason="Stop!")),
        ("ask-reason-question", payload(), notice(reason="Really?")),
        ("ask-reason-period", payload(), notice(reason="Done.")),
        ("ask-reason-int", payload(), notice(reason=7)),
        ("ask-reason-list", payload(), notice(reason=["a"])),
        ("ask-long-reason", payload(), notice(reason=LONG)),
        ("ask-notice-tool-fallback", no_tool, notice()),
        ("ask-notice-tool-blank", no_tool, notice(tool_name="  ")),
        ("ask-notice-tool-int", no_tool, notice(tool_name=5)),
        ("ask-notice-tool-padded", no_tool, notice(tool_name="\u00a0Write\u2009")),
        ("ask-no-tool-anywhere", no_tool, notice(tool_name=...)),
        ("ask-payload-tool-wins", payload(tool_name="Edit"), notice(tool_name="Bash")),
        ("ask-artifact-type-int", payload(), notice(artifact_type=3)),
        ("ask-artifact-type-other-case", payload(), notice(artifact_type="Package_Request")),
        ("ask-artifact-type-missing", payload(), notice(artifact_type=...)),
        ("ask-header-blank", payload(), notice(approval_header=" ")),
        ("ask-header-custom", payload(), notice(approval_header="  Guard check ")),
        ("ask-question-missing", payload(), notice(approval_question=...)),
        ("ask-question-padded", payload(), notice(approval_question="\u2002Proceed? ")),
        ("ask-options-missing", payload(), notice(approval_options=...)),
        ("ask-options-empty", payload(), notice(approval_options=[])),
        ("ask-options-string", payload(), notice(approval_options="Allow once")),
        ("ask-options-dict", payload(), notice(approval_options={"label": "Allow once"})),
        ("ask-options-labels", payload(), notice(approval_options=[{"label": " Yes "}, {"label": "No"}])),
        ("ask-options-blank-label", payload(), notice(approval_options=[{"label": "Yes"}, {"label": " "}])),
        ("ask-options-int-label", payload(), notice(approval_options=[{"label": 1}])),
        ("ask-options-no-label", payload(), notice(approval_options=[{"name": "Yes"}])),
        ("ask-options-mixed", payload(), notice(approval_options=[" Yes", {"label": "No "}])),
        ("ask-options-blank-string", payload(), notice(approval_options=["Yes", "  "])),
        ("ask-options-null-item", payload(), notice(approval_options=["Yes", None])),
        ("ask-options-int-item", payload(), notice(approval_options=["Yes", 2])),
        ("ask-options-quote", payload(), notice(approval_options=["Don't", "Do"])),
        ("name-message", payload(tool_name=..., message="Claude needs your permission to use Bash"), notice()),
        ("name-title", payload(tool_name=..., title="Claude wants to use WebFetch now"), notice()),
        ("name-message-before-title", payload(tool_name=..., message="use Read", title="use Write"), notice()),
        ("name-message-no-match", payload(tool_name=..., message="no tool here", title="use Grep"), notice()),
        ("name-message-int", payload(tool_name=..., message=12, title="use Glob"), notice()),
        ("name-message-blank", payload(tool_name=..., message="   ", title="use Glob"), notice()),
        ("name-reuse", payload(tool_name=..., message="reuse Bash"), notice(tool_name=...)),
        ("name-uses", payload(tool_name=..., message="uses Bash"), notice(tool_name=...)),
        ("name-underscore-before", payload(tool_name=..., message="_use Bash"), notice(tool_name=...)),
        ("name-accent-before", payload(tool_name=..., message="\u00e9use Bash"), notice(tool_name=...)),
        ("name-dash-before", payload(tool_name=..., message="-use Bash"), notice(tool_name=...)),
        ("name-digit-start", payload(tool_name=..., message="use 9Bash"), notice(tool_name=...)),
        ("name-accent-after", payload(tool_name=..., message="use Bash\u00e9"), notice(tool_name=...)),
        ("name-accent-then-later", payload(tool_name=..., message="use Bash\u00e9 or use Edit"), notice()),
        ("name-digits-underscore", payload(tool_name=..., message="use mcp__srv_2.call"), notice()),
        ("name-unicode-space", payload(tool_name=..., message="use\u3000\u2003Write"), notice()),
        ("name-file-separator", payload(tool_name=..., message="use\x1cWrite"), notice()),
        ("name-no-space", payload(tool_name=..., message="useBash"), notice(tool_name=...)),
        ("name-trailing-use", payload(tool_name=..., message="please use"), notice(tool_name=...)),
        ("name-upper-use", payload(tool_name=..., message="Use Bash"), notice(tool_name=...)),
        ("name-cjk-after", payload(tool_name=..., message="use Bash\u4e2d"), notice(tool_name=...)),
        ("name-blank-tool", payload(tool_name=" \u00a0", message="use Edit"), notice()),
        ("name-int-tool", payload(tool_name=4, title="to use Task."), notice()),
        ("name-padded-tool", payload(tool_name="\u2003Bash\x1f"), notice()),
        ("package-default", payload(), package()),
        ("package-padded-type", payload(), package(artifact_type=" package_request\n")),
        ("package-no-reason", payload(), package(reason=...)),
        ("package-empty-reason", payload(), package(reason="")),
        ("package-whitespace-reason", payload(), package(reason="   ")),
        ("package-unicode-reason", payload(), package(reason="\u2003R\u00e9sum\u00e9 lockfile\u3000")),
        ("package-reason-zero", payload(), package(reason=0)),
        ("package-reason-false", payload(), package(reason=False)),
        ("package-reason-true", payload(), package(reason=True)),
        ("package-reason-int", payload(), package(reason=42)),
        ("package-reason-float", payload(), package(reason=1.5)),
        ("package-reason-zero-float", payload(), package(reason=0.0)),
        ("package-reason-big-float", payload(), package(reason=1e20)),
        ("package-reason-empty-list", payload(), package(reason=[])),
        ("package-reason-list", payload(), package(reason=["a", 1, True, None, "it's"])),
        ("package-reason-dict", payload(), package(reason={"a": 1, "b": "x"})),
        ("package-reason-question", payload(), package(reason="Install left-pad?")),
        ("package-long-reason", payload(), package(reason=LONG)),
        ("package-no-tool", no_tool, package()),
        ("package-name-from-message", payload(tool_name=..., message="Allow Claude to use Bash"), package()),
        ("package-padded-tool", payload(tool_name="  npm  "), package()),
    ]


def expected(hook: dict[str, object], pending: dict[str, object] | None) -> dict[str, object]:
    native_reason = str(pending.get("reason") or DEFAULT_REASON) if pending is not None else DEFAULT_REASON
    # The daemon reads the notice from the native store op's sorted JSON.
    loaded = json.loads(json.dumps(pending, sort_keys=True)) if pending is not None else None
    events: list[tuple[str, dict[str, object]]] = []
    store = SimpleNamespace(add_event=lambda name, event, _now: events.append((name, event)))
    with (
        mock.patch.object(hook_state, "_peek_claude_permission_notice", lambda _store, _payload: pending),
        mock.patch.object(hook_state, "_load_claude_permission_notice", lambda _store, _payload: loaded),
        mock.patch.object(hook_state, "_mark_claude_pending_permission_prompt_seen", lambda **_kwargs: None),
    ):
        response = claude_permission_request_response(None, hook)  # type: ignore[arg-type]
        notification = HookWorker._claude_permission_prompt_notification_response(
            SimpleNamespace(store=store),  # type: ignore[arg-type]
            hook,
        )
    [(event_name, event)] = events
    if event_name != "claude/permission_prompt":
        raise SystemExit(f"unexpected event {event_name}")
    return {
        "notification_tool_name": _claude_notification_tool_name(hook),
        "notification_tool_display_name": _claude_notification_tool_display_name(hook),
        "prefers_ask_user_question": (
            approval._claude_permission_notice_prefers_ask_user_question(pending) if pending is not None else None
        ),
        "approval_question_message": approval._claude_guard_approval_question_message(pending),
        "prompt_system_message": approval._claude_permission_prompt_system_message(payload=hook, notice=pending),
        "native_reason": native_reason,
        "request_system_message": approval._claude_permission_request_system_message(
            payload=hook, native_reason=native_reason
        ),
        "response": response,
        "prompt_additional_context": approval._claude_permission_prompt_additional_context(pending),
        "notification_response": notification,
        "notification_event": json.dumps(event),
    }


def document() -> dict[str, object]:
    vectors = [
        {"name": name, "payload": hook, "notice": pending, "expected": expected(hook, pending)}
        for name, hook, pending in cases()
    ]
    names = [vector["name"] for vector in vectors]
    if len(set(names)) != len(names):
        raise SystemExit("duplicate vector names")
    return {"schema": "claude-permission-text-vectors.v1", "vectors": vectors}


def render() -> str:
    return json.dumps(document(), indent=2, ensure_ascii=True) + "\n"


def main() -> int:
    text = render()
    if "--check" in sys.argv[1:]:
        if OUT.read_text(encoding="utf-8") != text:
            print(f"{OUT} is stale; rerun {Path(__file__).name}", file=sys.stderr)
            return 1
        return 0
    OUT.write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

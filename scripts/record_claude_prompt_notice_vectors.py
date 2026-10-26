#!/usr/bin/env python3
"""Record parity vectors for Guard's Claude Code prompt notice.

The expected answers come from Guard's Claude prompt copy in
``commands_support_prompts``. The resident adds this notice to a reviewed
Claude ``UserPromptSubmit`` outside Watch (``hook_direct_claude_prompt_text.rs``)
and replays every vector: one native prompt result, the harness response the
edge rendered for it, and the response after the notice is added.

Usage: python scripts/record_claude_prompt_notice_vectors.py [--check]
Deterministic output.
"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from codex_plugin_scanner.guard.cli.commands_support_prompts import (  # noqa: E402
    _claude_prompt_additional_context,
    _claude_prompt_system_message,
)
from codex_plugin_scanner.guard.models import GuardArtifact  # noqa: E402

OUT = ROOT / "rust/crates/guard-runtime/tests/fixtures/claude_prompt_notice_vectors.json"
ACTIONS = ("require-reapproval", "block", "sandbox-required")
CLASS_SETS: tuple[tuple[str, object], ...] = (
    ("no-classes", ...),
    ("empty", []),
    ("local-env", ["local_env_read"]),
    ("sensitive-material", ["sensitive_material"]),
    ("secret-read", ["secret_read"]),
    ("bypass", ["guard_bypass_intent"]),
    ("bypass-and-secret", ["local_env_read", "guard_bypass_intent"]),
    ("other", ["destructive_command"]),
    ("odd-items", ["", "  ", None, 3, {"class": "local_env_read"}, " local_env_read"]),
    ("not-a-list", "local_env_read"),
)
REASONS: tuple[tuple[str, object], ...] = (
    ("reason-plain", "Guard needs approval for this prompt"),
    ("reason-punctuated", "Guard blocked this prompt!"),
    ("reason-question", "  Should Claude read secrets?  "),
    ("reason-padded", "\t Guard flagged this prompt \n"),
    ("reason-blank", "   "),
    ("reason-empty", ""),
    ("reason-null", None),
    ("reason-missing", ...),
)
RESPONSES: tuple[tuple[str, dict[str, object]], ...] = (
    ("hook-output", {"hookSpecificOutput": {"hookEventName": "UserPromptSubmit"}}),
    (
        "hook-output-existing",
        {
            "systemMessage": "Edge message",
            "hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "additionalContext": "Edge context"},
        },
    ),
    ("hook-output-not-object", {"hookSpecificOutput": "UserPromptSubmit", "continue": True}),
    ("no-hook-output", {"decision": "block", "reason": "Edge reason"}),
)


# Native classes Guard's prompt copy reads as a request for local secrets.
SECRET_READ_NATIVE_CLASSES = frozenset({"local_env_read", "sensitive_material"})


def brand(response: dict[str, object], native_result: dict[str, object]) -> dict[str, object]:
    """Add Guard's Claude prompt notice to ``response`` as the copy helpers render it."""

    raw_classes = native_result.get("prompt_risk_classes")
    request_classes = (
        [
            "secret_read" if item in SECRET_READ_NATIVE_CLASSES else item
            for item in raw_classes
            if isinstance(item, str) and item
        ]
        if isinstance(raw_classes, list)
        else []
    )
    artifact = GuardArtifact(
        artifact_id="claude-code:native-prompt:session",
        name="user prompt",
        harness="claude-code",
        artifact_type="prompt_request",
        source_scope="harness",
        config_path="",
        metadata={"prompt_request_classes": request_classes},
    )
    policy_action = str(native_result.get("minimum_action") or "")
    native_reason = str(native_result.get("reason") or "")
    system_message = _claude_prompt_system_message(
        event_name="UserPromptSubmit",
        policy_action=policy_action,
        artifact=artifact,
        native_reason=lambda: native_reason,
    )
    if system_message:
        response["systemMessage"] = system_message
    additional_context = _claude_prompt_additional_context(
        harness="claude-code",
        event_name="UserPromptSubmit",
        policy_action=policy_action,
        artifact=artifact,
        native_reason=native_reason,
    )
    if additional_context:
        hook_output = response.get("hookSpecificOutput")
        if isinstance(hook_output, dict):
            hook_output["additionalContext"] = additional_context
    return response


def result(action: object, classes: object, reason: object) -> dict[str, object]:
    fields: dict[str, object] = {"decision": "block", "minimum_action": action, "reason": reason}
    if classes is not ...:
        fields["prompt_risk_classes"] = classes
    return {key: value for key, value in fields.items() if value is not ...}


def cases() -> list[tuple[str, dict[str, object], dict[str, object]]]:
    collected = []
    for action in ACTIONS:
        for class_label, classes in CLASS_SETS:
            for reason_label, reason in REASONS:
                collected.append(
                    (f"{action}/{class_label}/{reason_label}", result(action, classes, reason), RESPONSES[0][1])
                )
        for response_label, response in RESPONSES[1:]:
            for class_label, classes in (CLASS_SETS[0], CLASS_SETS[2], CLASS_SETS[5]):
                collected.append(
                    (
                        f"{action}/{class_label}/{response_label}",
                        result(action, classes, "Guard needs approval"),
                        response,
                    )
                )
    for action in ("allow", "warn", "review", "", None, 3):
        collected.append((f"other-action/{action!r}", result(action, ["local_env_read"], "Reason"), RESPONSES[0][1]))
    return collected


def document() -> dict[str, object]:
    vectors = [
        {
            "name": name,
            "result": native_result,
            "response": response,
            "expected": brand(copy.deepcopy(response), native_result),
        }
        for name, native_result, response in cases()
    ]
    names = [vector["name"] for vector in vectors]
    if len(set(names)) != len(names):
        raise SystemExit("duplicate vector names")
    return {"schema": "claude-prompt-notice-vectors.v1", "vectors": vectors}


def render() -> str:
    return json.dumps(document(), indent=1, ensure_ascii=True) + "\n"


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

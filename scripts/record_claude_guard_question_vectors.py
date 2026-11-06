#!/usr/bin/env python3
"""Record parity vectors for Claude AskUserQuestion approval answers.

Usage: GUARD_PY_SNAPSHOT=<path to src dir of the reference snapshot> \
    python scripts/record_claude_guard_question_vectors.py [snapshot_src]

The reference snapshot must predate the move of the approval-question match
and answer mapping to the native runtime (base commit ``BASE_COMMIT``). Each
vector is one PostToolUse payload, the pending approval, the request the
transport sends for them, and the reference answer. The Rust tests replay the
request; the Python tests check the transport still projects the same request.
Deterministic output.
"""

from __future__ import annotations

import gzip
import json
import os
import sys
from pathlib import Path

snapshot = os.environ.get("GUARD_PY_SNAPSHOT") or (sys.argv[1] if len(sys.argv) > 1 else "")
if not snapshot:
    sys.exit("set GUARD_PY_SNAPSHOT or pass the snapshot src directory")
sys.path.insert(0, snapshot)

from codex_plugin_scanner.guard.cli import commands as reference  # noqa: E402

BASE_COMMIT = "33cb25c1f5"
OUT = Path(__file__).resolve().parent.parent / "rust/crates/guard-runtime/tests/fixtures"
PENDING_KEYS = ("approval_code", "approval_header", "approval_question", "approval_options")
OPTIONS = ["Allow once", "Allow during this session", "Keep blocked"]
DEFAULT_QUESTION = "HOL Guard intercepted this sensitive action. What should Claude do?"
CODE = "AB12CD"
CODED_QUESTION = f"HOL Guard intercepted this sensitive action (approval code: {CODE}). What should Claude do?"


def pending(**fields: object) -> dict[str, object]:
    base: dict[str, object] = {
        "approval_code": CODE,
        "approval_header": "HOL Guard",
        "approval_question": CODED_QUESTION,
        "approval_options": list(OPTIONS),
        "artifact_id": "claude-code:project:bash",
        "permission_prompt_seen": True,
    }
    base.update(fields)
    return {key: value for key, value in base.items() if value is not ...}


def asked(question: object = CODED_QUESTION, header: object = "HOL Guard", options: object = None) -> dict:
    return {
        "questions": [
            {
                "header": header,
                "question": question,
                "options": [{"label": label} for label in OPTIONS] if options is None else options,
            }
        ]
    }


def payload(response: object = ..., **fields: object) -> dict[str, object]:
    base: dict[str, object] = {
        "hook_event_name": "PostToolUse",
        "session_id": "session-1",
        "tool_name": "AskUserQuestion",
        "tool_input": asked(),
        "tool_response": {"answers": {CODED_QUESTION: "Allow once"}} if response is ... else response,
    }
    base.update(fields)
    return {key: value for key, value in base.items() if value is not ...}


def project(hook: dict[str, object], prompt: dict[str, object]) -> dict[str, object]:
    """The request the native transport sends; mirrored by its projection."""

    response = hook.get("tool_response")
    answers = None
    if isinstance(response, dict):
        raw_answers = response.get("answers")
        if isinstance(raw_answers, dict):
            answers = [[question, answer] for question, answer in raw_answers.items()]
        response = {key: value for key, value in response.items() if key != "answers"}
    return {
        "event": reference._hook_event_name(hook),
        "tool_name": hook.get("tool_name"),
        "tool_input": hook.get("tool_input"),
        "tool_response": response,
        "response_answers": answers,
        "pending": {key: prompt[key] for key in PENDING_KEYS if key in prompt},
    }


def cases() -> list[tuple[str, dict[str, object], dict[str, object]]]:
    default_pending = pending(approval_code=..., approval_header=..., approval_question=..., approval_options=...)
    default_input = asked(question=DEFAULT_QUESTION)
    out: list[tuple[str, dict[str, object], dict[str, object]]] = [
        ("answers-keyed-allow-once", payload(), pending()),
        ("answers-keyed-allow-session", payload({"answers": {CODED_QUESTION: "Allow during this session"}}), pending()),
        ("answers-keyed-keep-blocked", payload({"answers": {CODED_QUESTION: "Keep blocked"}}), pending()),
        ("answers-keyed-unknown", payload({"answers": {CODED_QUESTION: "Maybe later"}}), pending()),
        ("answers-keyed-label-dict", payload({"answers": {CODED_QUESTION: {"label": " Keep blocked "}}}), pending()),
        ("answers-keyed-blank", payload({"answers": {CODED_QUESTION: "   "}}), pending()),
        ("answers-keyed-casefold-spacing", payload({"answers": {CODED_QUESTION: "  ALLOW\t once "}}), pending()),
        ("answers-keyed-nbsp", payload({"answers": {CODED_QUESTION: "Allow\u00a0once"}}), pending()),
        ("answers-keyed-ideographic-space", payload({"answers": {CODED_QUESTION: "Keep\u3000blocked"}}), pending()),
        ("answers-keyed-zero-width-space", payload({"answers": {CODED_QUESTION: "Allow\u200bonce"}}), pending()),
        (
            "answers-normalized-question-key",
            payload({"answers": {"other": "Keep blocked", "  " + CODED_QUESTION.upper() + " ": "Allow once"}}),
            pending(),
        ),
        (
            "answers-first-matching-question-wins",
            payload({"answers": {CODED_QUESTION.lower(): "Keep blocked", CODED_QUESTION: "Allow once"}}),
            pending(),
        ),
        (
            "answers-first-matching-question-wins-reverse",
            payload({"answers": {CODED_QUESTION: "Allow once", CODED_QUESTION.lower(): "Keep blocked"}}),
            pending(),
        ),
        (
            "answers-matching-blank-then-match",
            payload({"answers": {CODED_QUESTION: " ", CODED_QUESTION.upper(): "Keep blocked"}}),
            pending(),
        ),
        ("answers-single-unrelated-key", payload({"answers": {"something else": "Keep blocked"}}), pending()),
        (
            "answers-two-unrelated-keys",
            payload({"answers": {"a": "Keep blocked", "b": "Allow once"}}),
            pending(),
        ),
        (
            "answers-two-unrelated-keys-falls-to-selected",
            payload({"answers": {"a": "Keep blocked", "b": "Allow once"}, "selected": "Keep blocked"}),
            pending(),
        ),
        ("answers-empty", payload({"answers": {}, "answer": "Keep blocked"}), pending()),
        ("answers-list-ignored", payload({"answers": ["Keep blocked"], "choice": "Allow once"}), pending()),
        ("answers-single-non-text", payload({"answers": {"q": 3}, "value": "Keep blocked"}), pending()),
        ("selected-answer-string", payload({"selected_answer": "Allow once"}), pending()),
        ("selected-answer-dict", payload({"selected_answer": {"label": "Allow during this session"}}), pending()),
        ("selected-dict-no-label", payload({"selected": {"value": "Allow once"}, "label": "Keep blocked"}), pending()),
        ("answer-key-order", payload({"label": "Keep blocked", "answer": "Allow once"}), pending()),
        ("answer-key-blank-skipped", payload({"answer": "  ", "choice": "Keep blocked"}), pending()),
        ("content-string", payload({"content": "Keep blocked"}), pending()),
        ("content-blank", payload({"content": " \n "}), pending()),
        ("content-with-options-key", payload({"content": "Allow once", "options": []}), pending()),
        (
            "content-with-matching-questions",
            payload({**asked(), "content": "Allow once"}),
            pending(),
        ),
        (
            "response-questions-and-answers",
            payload({**asked(), "answers": {CODED_QUESTION: "Keep blocked"}}),
            pending(),
        ),
        (
            "response-questions-mismatch",
            payload({**asked(question="Something else?"), "answers": {CODED_QUESTION: "Allow once"}}),
            pending(),
        ),
        (
            "response-two-questions-ignored",
            payload({"questions": [asked()["questions"][0]] * 2, "answers": {CODED_QUESTION: "Allow once"}}),
            pending(),
        ),
        ("response-plain-string", payload("Allow once"), pending()),
        ("response-plain-string-block", payload("  keep   BLOCKED  "), pending()),
        ("response-plain-blank", payload("   "), pending()),
        ("response-missing", payload(tool_response=...), pending()),
        ("response-list", payload(["Allow once"]), pending()),
        ("response-number", payload(7), pending()),
        ("response-null", payload(None), pending()),
        ("event-pre-tool-use", payload(hook_event_name="PreToolUse"), pending()),
        ("event-lowercase", payload(hook_event_name="posttooluse"), pending()),
        ("event-padded", payload(hook_event_name="  PostToolUse  "), pending()),
        ("event-key-precedence", payload(event="PreToolUse"), pending()),
        ("event-blank-falls-through", payload(event="  ", hookEventName="PostToolUse"), pending()),
        ("event-missing", payload(hook_event_name=...), pending()),
        ("tool-name-lowercase-padded", payload(tool_name="  askuserquestion "), pending()),
        ("tool-name-other", payload(tool_name="Bash"), pending()),
        ("tool-name-missing", payload(tool_name=...), pending()),
        ("tool-name-non-string", payload(tool_name=["AskUserQuestion"]), pending()),
        ("input-missing", payload(tool_input=...), pending()),
        ("input-not-dict", payload(tool_input="ask"), pending()),
        ("input-two-questions", payload(tool_input={"questions": asked()["questions"] * 2}), pending()),
        ("input-question-not-dict", payload(tool_input={"questions": ["ask"]}), pending()),
        ("input-question-mismatch", payload(tool_input=asked(question=DEFAULT_QUESTION)), pending()),
        ("input-header-mismatch", payload(tool_input=asked(header="Guard")), pending()),
        ("input-header-case-spacing", payload(tool_input=asked(header="  hol   GUARD ")), pending()),
        ("input-header-missing", payload(tool_input=asked(header=None)), pending()),
        ("input-question-case-spacing", payload(tool_input=asked(question=" " + CODED_QUESTION.lower())), pending()),
        ("input-options-strings", payload(tool_input=asked(options=list(OPTIONS))), pending()),
        ("input-options-reordered", payload(tool_input=asked(options=list(reversed(OPTIONS)))), pending()),
        ("input-options-extra", payload(tool_input=asked(options=[*OPTIONS, "Always allow"])), pending()),
        ("input-options-missing-label", payload(tool_input=asked(options=[{"label": "Allow once"}, {}])), pending()),
        ("input-options-non-string", payload(tool_input=asked(options=["Allow once", 3, "Keep blocked"])), pending()),
        ("input-options-empty", payload(tool_input=asked(options=[])), pending()),
        ("input-options-not-list", payload(tool_input=asked(options="Allow once")), pending()),
        ("pending-default", payload(tool_input=default_input, tool_response="Allow once"), default_pending),
        (
            "pending-default-keyed",
            payload({"answers": {DEFAULT_QUESTION: "Keep blocked"}}, tool_input=default_input),
            default_pending,
        ),
        ("pending-default-coded-input", payload(), default_pending),
        (
            "pending-no-code-explicit",
            payload(tool_input=default_input, tool_response="Allow once"),
            pending(approval_code=..., approval_question=DEFAULT_QUESTION),
        ),
        (
            "pending-no-code-custom-header",
            payload(tool_input=asked(question=DEFAULT_QUESTION, header="Approval"), tool_response="Keep blocked"),
            pending(approval_code=..., approval_question=DEFAULT_QUESTION, approval_header="Approval"),
        ),
        (
            "pending-no-code-partial",
            payload(tool_input=default_input, tool_response="Allow once"),
            pending(approval_code=..., approval_question=..., approval_options=...),
        ),
        (
            "pending-no-code-coded-question",
            payload(),
            pending(approval_code=...),
        ),
        ("pending-code-blank", payload(tool_input=default_input), pending(approval_code="  ")),
        ("pending-code-padded", payload(), pending(approval_code=f"  {CODE}  ")),
        ("pending-code-mismatch", payload(), pending(approval_code="ZZ99")),
        ("pending-header-missing", payload(), pending(approval_header=...)),
        ("pending-header-custom", payload(tool_input=asked(header="Approval")), pending(approval_header="Approval")),
        ("pending-question-missing", payload(), pending(approval_question=...)),
        (
            "pending-question-spacing",
            payload(),
            pending(approval_question="  " + CODED_QUESTION.replace(" ", "  ").upper()),
        ),
        ("pending-options-missing", payload(), pending(approval_options=...)),
        ("pending-options-dicts", payload(), pending(approval_options=[{"label": label} for label in OPTIONS])),
        ("pending-options-reordered", payload(), pending(approval_options=list(reversed(OPTIONS)))),
        ("pending-options-casefold", payload(), pending(approval_options=[label.upper() for label in OPTIONS])),
        ("pending-options-bad-item", payload(), pending(approval_options=["Allow once", None, "Keep blocked"])),
        (
            "pending-options-blank-label",
            payload(tool_input=asked(options=["Allow once", " ", "Keep blocked"])),
            pending(approval_options=["Allow once", "", "Keep blocked"]),
        ),
        ("pending-header-non-string", payload(), pending(approval_header=7)),
        (
            "unicode-medial-sigma-header",
            payload(tool_input=asked(header="ΟΔΟΣ")),
            pending(approval_header="οδοσ"),
        ),
        (
            "unicode-final-sigma-header-match",
            payload(tool_input=asked(header="ΟΔΟΣ")),
            pending(approval_header="οδος"),
        ),
        (
            "unicode-dotted-capital-i",
            payload(tool_input=asked(header="İ")),
            pending(approval_header="i̇"),
        ),
        (
            "unicode-sharp-s",
            payload(tool_input=asked(header="STRASSE")),
            pending(approval_header="straße"),
        ),
    ]
    names = [name for name, _, _ in out]
    assert len(names) == len(set(names)), "duplicate case names"
    return out


def answer(hook: dict[str, object], prompt: dict[str, object]) -> dict[str, object]:
    if not reference._is_claude_guard_approval_question(hook, prompt):
        return {"is_question": False, "action": None}
    action = reference._claude_guard_approval_answer(
        hook, expected_question=reference._optional_string(prompt.get("approval_question"))
    )
    return {"is_question": True, "action": action}


def main() -> None:
    vectors = [
        {
            "name": name,
            "payload": hook,
            "pending": prompt,
            "request": project(hook, prompt),
            "expected": answer(hook, prompt),
        }
        for name, hook, prompt in cases()
    ]
    document = {"base_commit": BASE_COMMIT, "cases": vectors}
    path = OUT / "claude_guard_question_vectors.json.gz"
    encoded = (json.dumps(document, separators=(",", ":"), ensure_ascii=False) + "\n").encode()
    path.write_bytes(gzip.compress(encoded, compresslevel=9, mtime=0))
    print(f"recorded {len(vectors)} vectors to {path.name}")


if __name__ == "__main__":
    main()

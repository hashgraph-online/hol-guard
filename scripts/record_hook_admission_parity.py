"""Record parity vectors from the Python hook admission helpers.

The vectors pin the behaviour of the pure helpers the daemon runs before a
runtime hook reaches the native edge (lane selection, scheduler client key,
payload size, remaining-budget hints, deadline math, workspace and workdir
normalisation).  A native handler that replaces them must reproduce every vector.
Run without arguments to rewrite the fixture; the test module compares it.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "hook_admission_parity" / "vectors.v1.json"

PAYLOADS: list[dict[str, object]] = [
    {},
    {"hook_event_name": "PreToolUse", "session_id": "s1", "tool_name": "Bash"},
    {"hook_event_name": "pre_tool_use", "conversation_id": "c9"},
    {"hook_event_name": "PermissionRequest", "thread_id": "t3"},
    {"hook_event_name": "UserPromptSubmit", "session_id": "s1", "prompt": "hi"},
    {"hook_event_name": "user-prompt-submitted"},
    {"hook_event_name": "PostToolUse", "session_id": "s2", "tool_response": {"ok": True}},
    {"event": "SessionStart"},
    {"hook_event_name": "PreToolUse", "session_id": "", "conversation_id": "c1", "thread_id": "t1"},
    {"hook_event_name": "PreToolUse", "session_id": 7, "thread_id": "t2"},
    {"hook_event_name": "PostToolUse", "tool_input": {"text": "café ☃ \U0001f600"}},
]
WORKSPACES: list[str | None] = [None, "", "/work/space", "/work/spaceé"]
HINT_PAYLOADS: list[dict[str, object]] = [
    {},
    {"guard_remaining_seconds": 2.5},
    {"guard_remaining_seconds": 7},
    {"guard_remaining_ms": 1500},
    {"guard_remaining_seconds": True, "guard_remaining_ms": 900},
    {"guard_remaining_seconds": "3"},
    {"guard_remaining_seconds": float("inf"), "guard_remaining_ms": 2000},
    {"guard_remaining_seconds": float("nan")},
    {"guard_remaining_ms": 0},
    {"guard_remaining_seconds": -1},
    {"guard_remaining_seconds": 3, "guard_remaining_ms": 9000},
]
WORKSPACE_STRINGS: list[object] = [
    None,
    7,
    "",
    "   ",
    "None",
    "null",
    "NULL",
    "/work/space",
    "/work/space/",
    "/work/./space/../space",
    "/work/None",
    "/None",
    " /work/space ",
    "/work//space",
]
WORKDIR_PAYLOADS: list[dict[str, object]] = [
    {},
    {"tool_name": "Bash", "tool_input": {"workdir": "/w"}},
    {"tool_name": "exec_command"},
    {"tool_name": "exec_command", "tool_input": {}},
    {"tool_name": "exec_command", "tool_input": []},
    {"tool_name": "Exec_Command", "tool_input": {"workdir": "/w/x"}},
    {"tool_name": " exec_command ", "tool_input": {"workdir": "/w/./x/"}},
    {"tool_name": "exec_command", "tool_input": {"workdir": 5}},
    {"tool_name": "exec_command", "tool_input": {"workdir": ""}},
    {"tool_name": "exec_command", "tool_input": {"workdir": "none"}},
    {"tool_name": "exec_command", "tool_input": {"workdir": " NULL "}},
]
DEADLINE_CASES: list[dict[str, object]] = [
    {"hint": hint, "hint_missing": missing, "prompt": prompt, "admission": admission, "transport": transport}
    for hint in (3.0, 0.05, 1.0, 12.0, 4.0)
    for missing in (True, False)
    for prompt, admission in ((False, 3.0), (True, 10.0))
    for transport in (1.0, 4.0, 11.0)
]


def _vectors() -> dict[str, object]:
    from codex_plugin_scanner.guard.daemon import server
    from codex_plugin_scanner.guard.daemon.hook_request_parsing import runtime_hook_event_name
    from codex_plugin_scanner.guard.daemon.runtime_hook_deadline import RuntimeHookDeadline

    handler = server._GuardDaemonHandler
    lane = [
        {
            "payload": payload,
            "event_name": runtime_hook_event_name(payload),
            "lane": handler._runtime_hook_lane(payload),
        }
        for payload in PAYLOADS
    ]
    client_key = [
        {"payload": payload, "workspace": workspace, "digest": handler._runtime_hook_client_key(payload, workspace)}
        for payload in PAYLOADS
        for workspace in WORKSPACES
    ]
    payload_size = [{"payload": payload, "bytes": handler._runtime_hook_payload_size(payload)} for payload in PAYLOADS]
    hints = []
    for payload in HINT_PAYLOADS:
        working = dict(payload)
        hints.append(
            {
                "payload": {key: _jsonable(value) for key, value in payload.items()},
                "remaining_seconds": server._runtime_hook_remaining_hint(working),
                "remaining_payload_keys": sorted(working),
            }
        )
    workspaces = [
        {"value": value, "normalized": handler._normalized_hook_workspace_string(value)} for value in WORKSPACE_STRINGS
    ]
    workdirs = []
    for payload in WORKDIR_PAYLOADS:
        provided, workdir = handler._runtime_hook_exec_command_workdir(payload)
        workdirs.append({"payload": payload, "provided": provided, "workdir": workdir})
    deadlines = _deadline_vectors(server, RuntimeHookDeadline)
    directory_authority = _directory_authority_vectors()
    return {
        "schema": "hook-admission-parity.v1",
        "lane": lane,
        "client_key": client_key,
        "payload_size": payload_size,
        "remaining_hint": hints,
        "workspace_string": workspaces,
        "exec_command_workdir": workdirs,
        "deadline": deadlines,
        "directory_authority": directory_authority,
    }


def _deadline_vectors(server: object, deadline_type: type) -> list[dict[str, object]]:
    """Record the deadlines the daemon's own ``for_admission`` produces, with a pinned clock."""
    from codex_plugin_scanner.guard.daemon.runtime_hook_deadline import PROMPT_ADMISSION_SECONDS

    non_prompt_admission = server._RUNTIME_HOOK_ADMISSION_TIMEOUT_SECONDS  # type: ignore[attr-defined]
    from_hint = deadline_type.from_remaining_hint.__func__  # type: ignore[attr-defined]
    base = 100.0
    original = from_hint.__kwdefaults__["monotonic"]
    vectors: list[dict[str, object]] = []
    try:
        # The tool-hook path reads the default clock; pin it for the recording only.
        from_hint.__kwdefaults__["monotonic"] = lambda: base
        for case in DEADLINE_CASES:
            prompt = bool(case["prompt"])
            admission = PROMPT_ADMISSION_SECONDS if prompt else non_prompt_admission
            transport_deadline = base + float(case["transport"])  # type: ignore[arg-type]
            result = deadline_type.for_admission(
                float(case["hint"]),  # type: ignore[arg-type]
                hint_missing=bool(case["hint_missing"]),
                prompt_event=prompt,
                admission_seconds=admission,
                transport_deadline=transport_deadline,
            )
            vectors.append(
                {
                    "hint": case["hint"],
                    "hint_missing": case["hint_missing"],
                    "prompt": prompt,
                    "admission": admission,
                    "transport": case["transport"],
                    "expires_offset": round(result.expires_at - base, 6),
                }
            )
    finally:
        from_hint.__kwdefaults__["monotonic"] = original
    return vectors


DIRECTORY_CANDIDATES: list[str] = [
    "",
    "relative/dir",
    "~no-such-user-for-parity",
    "{root}",
    "{root}/",
    "{root}/a",
    "{root}/a/./b",
    "{root}/a/../b",
    "{root}/../escape",
    "{root}-sibling",
    "{root}/a/..",
]


def _directory_authority_vectors() -> list[dict[str, object]]:
    """Record accepted canonical paths and rejection reasons of the directory validator."""
    import tempfile

    from codex_plugin_scanner.guard.directory_path_authority import (
        DirectoryPathTrustError,
        validate_guard_directory_path,
    )

    vectors: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory() as raw_root:
        root = Path(raw_root).resolve()
        for template in DIRECTORY_CANDIDATES:
            candidate = template.replace("{root}", root.as_posix())
            try:
                accepted = validate_guard_directory_path(candidate, (root,))
            except DirectoryPathTrustError as error:
                outcome: dict[str, object] = {"rejected": error.reason}
            else:
                outcome = {"accepted": Path(accepted).relative_to(root).as_posix()}
            vectors.append({"candidate": template, **outcome})
    return vectors


def _jsonable(value: object) -> object:
    if isinstance(value, float) and value != value:
        return "nan"
    if isinstance(value, float) and value in (float("inf"), float("-inf")):
        return "inf" if value > 0 else "-inf"
    return value


def _normalise(value: object) -> object:
    if isinstance(value, float):
        return _jsonable(value)
    if isinstance(value, dict):
        return {key: _normalise(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_normalise(item) for item in value]
    return value


def build() -> dict[str, object]:
    sys.path.insert(0, str(ROOT / "src"))
    return _normalise(_vectors())  # type: ignore[return-value]


def main() -> int:
    FIXTURE.write_text(json.dumps(build(), indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

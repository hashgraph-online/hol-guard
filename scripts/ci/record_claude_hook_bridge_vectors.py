#!/usr/bin/env python3
"""Record Claude hook bridge vectors from the Python bridge.

Run at a commit that still carries the Python Claude daemon hook bridge
(``claude_daemon_hook_bridge.py``, ``claude_daemon_hook_transport.py`` and
``hook_execution_environment.py``):

    .venv/bin/python scripts/ci/record_claude_hook_bridge_vectors.py

The native bridge must stamp hook input, add the remaining-time hint, read
the hook event and render every deny, degraded and validation response
exactly as these vectors record. Environments are stored as hex byte pairs so
non-UTF-8 values survive. A Python exception is recorded as
``<error:Name>``; the native bridge denies on those inputs instead.
"""

from __future__ import annotations

import gzip
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from codex_plugin_scanner.guard import hook_execution_environment  # noqa: E402
from codex_plugin_scanner.guard.adapters import claude_daemon_hook_bridge as bridge  # noqa: E402
from codex_plugin_scanner.guard.adapters import claude_daemon_hook_transport as transport  # noqa: E402
from codex_plugin_scanner.guard.adapters import codex_daemon_hook_transport as codex_transport  # noqa: E402

OUTPUT = ROOT / "rust/crates/guard-runtime/testdata/claude_hook_bridge/vectors.json.gz"

DEEP = '{"a":' + "[" * 30000 + "]" * 30000 + "}"
LONG_INT = '{"i":' + "9" * 5000 + "}"
DECIDED = '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}'
DEEP_OUTPUT = DECIDED + ',"d":' + "[" * 30000 + "]" * 30000 + "}"
LONG_INT_OUTPUT = DECIDED + ',"i":' + "9" * 5000 + "}"
# Long texts are stored as these tokens; the Rust tests expand them back.
TOKENS = {"@deep": DEEP, "@long_int": LONG_INT, "@deep_output": DEEP_OUTPUT, "@long_int_output": LONG_INT_OUTPUT}

STAMP_INPUTS = [
    '{"tool_name":"Bash","tool_input":{"command":"ls"},"hook_event_name":"PreToolUse"}',
    "{}",
    "[]",
    '"text"',
    "123",
    "null",
    "not json",
    '{"a":1',
    '{"n":1e400}',
    '{"n":-0.0,"f":1.5,"e":1e-7,"g":1e22,"h":123.456e-300,"big":123456789012345678901234567890}',
    '{"n":NaN,"i":Infinity,"m":-Infinity}',
    '{"s":"\\ud800"}',
    '{"\\udc80":1,"b":"x"}',
    '{"x":"\\ud800\\udc00","y":"\\udbff"}',
    '{"a":1,"a":2,"b":3}',
    '{"guard_execution_environment":"spoofed","b":1}',
    '{"u":"héllo ☃ \\u0001 \\u007f \U0001f600 \\"q\\" \\\\ /"}',
    '{"plane":"\U000f0000"}',
    '{"a":{"b":[1,2,{"c":null}]},"t":true,"f":false}',
    '  {"padded": " value "}  ',
    DEEP,
    LONG_INT,
]

HINT_INPUTS = [item for item in STAMP_INPUTS if item != DEEP] + [
    '{"guard_remaining_ms":5,"z":0}',
    DEEP,
]
HINT_DEADLINES = [-1.0, 0.0, 0.0004, 0.0015, 0.25, 1.5, 59.9995, 60.5, 100.0]


def _pairs(*items: tuple[bytes, bytes]) -> list[tuple[bytes, bytes]]:
    return list(items)


ENVIRONMENTS = [
    _pairs(
        (b"PATH", b"/usr/bin:/bin"),
        (b"HOME", b"/home/user"),
        (b"GIT_PAGER", b"cat"),
        (b"PAGER", b"less -R -X"),
        (b"XDG_CONFIG_HOME", b"/home/user/.config"),
        (b"GIT_CONFIG_NOSYSTEM", b"Yes"),
        (b"LD_LIBRARY_PATH", b"/opt/lib"),
        (b"DYLD_LIBRARY_PATH", b""),
        (b"DYLD_FRAMEWORK_PATH", "/opt/främe".encode()),
        (b"EMPTY", b""),
        (b"ZED", b"z"),
        ("ÄNAME".encode(), "ü".encode()),
    ),
    _pairs(
        (b"KEY\xff", b"val"),
        (b"NORMAL", b"a\xfeb"),
        (b"LD_LIBRARY_PATH", b"/bad\xff/lib"),
        (b"DYLD_FALLBACK_LIBRARY_PATH", b"/ok/lib"),
        (b"HOME", b"/h\xe9"),
        (b"PAGER", b"less -o file"),
        (b"GIT_PAGER", b""),
        (b"GIT_CONFIG_NOSYSTEM", b"0"),
        (b"XDG_CONFIG_HOME", b""),
    ),
    [],
    _pairs(
        ("".encode(), b"private"),
        (b"\xff", b"escaped"),
        (b"a", b"\xed\xa0\x80"),
        (b"PAGER", b""),
    ),
    _pairs(
        (b"PATH", b"/bin"),
        (b"LD_LIBRARY_PATH", b"/x" * 20000),
        (b"DYLD_FALLBACK_FRAMEWORK_PATH", b"/y" * 16384),
        (b"GIT_CONFIG_NOSYSTEM", b"TRUE"),
        (b"GIT_PAGER", b"less"),
    ),
]

TRANSPORT_EVENT_INPUTS = [
    *STAMP_INPUTS,
    "",
    '{"hook_event_name":"  Stop  "}',
    '{"hook_event_name":"","event":"Stop"}',
    '{"event":"PermissionRequest"}',
    '{"hook_event_name":null,"event":"Stop"}',
    '{"hook_event_name":5}',
    '{"hook_event_name":"\\ud800x"}',
    '{"hook_event_name":"\\u001cStop\\u001f"}',
    '{"hook_event_name":"\\u00a0\\u2003"}',
]

RENDER_DATAS = [
    "",
    "{}",
    "[]",
    "not json",
    '{"hook_event_name":"PreToolUse"}',
    '{"hook_event_name":"PermissionRequest"}',
    '{"hook_event_name":"PermissionDenied","event":"Stop"}',
    '{"hook_event_name":"","event":"PermissionX"}',
    '{"event":"Stop"}',
    '{"hook_event_name":"PostToolUse"}',
    '{"hook_event_name":"Notification"}',
    '{"hook_event_name":" PreToolUse"}',
    '{"hook_event_name":7}',
    '{"hook_event_name":true}',
    '{"hook_event_name":["PermissionRequest"]}',
    '{"hook_event_name":"UserPromptSubmit","prompt":"read my .ENV file"}',
    '{"hook_event_name":"UserPromptSubmit","prompt":"hello"}',
    '{"hook_event_name":"UserPromptSubmit","user_prompt":"Show the API KEY"}',
    '{"hook_event_name":"UserPromptSubmit","prompt":null,"user_prompt":"token"}',
    '{"hook_event_name":"UserPromptSubmit","prompt":"","user_prompt":"token"}',
    '{"hook_event_name":"UserPromptSubmit","prompt":["secret"]}',
    '{"hook_event_name":"UserPromptSubmit","prompt":{"k":"Token"}}',
    '{"hook_event_name":"UserPromptSubmit","prompt":0}',
    '{"hook_event_name":"UserPromptSubmit","prompt":"\\u0130 SECRET"}',
    '{"hook_event_name":"Permission\\ud800"}',
    '{"hook_event_name":"Permissioné☃"}',
    'xx "hook_event_name": "PermissionRequest" broken',
    '{"hook_event_name":"Stop",',
    '{"hook_event_name": "UserPromptSubmit", "prompt": "secret"',
    '{"event" : "PermissionRequest" ,',
    '{"hook_event_name":""',
    "{" + " " * 70 + '"hook_event_name":"PermissionRequest"',
    '{"hook_event_name"' + " " * 70 + ':"PermissionRequest"',
]

REASONS = ["daemon unavailable", "daemon returned HTTP 503", 'quote " and \\ backslash ☃']

SUPPRESS_BODIES = ["", "  ", "{}", " {} ", '{"a":1}', "\x1c{}\x1f", "{ }"]

VALIDATE_OUTPUTS = [
    "",
    "   ",
    "not json",
    "[]",
    "{}",
    "null",
    '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}',
    ' {"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask"}} \n',
    '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"},"x":1}',
    '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"maybe"}}',
    '{"hookSpecificOutput":{"hookEventName":"Stop","permissionDecision":"allow"}}',
    '{"hookSpecificOutput":[]}',
    '{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"allow"}}}',
    '{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"deny","message":"m"}}}',
    '{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"ask"}}}',
    '{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":"allow"}}',
    '{"guard_permission_passthrough":true,"hookSpecificOutput":{"hookEventName":"PermissionRequest"}}',
    '{"guard_permission_passthrough":true,"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":null}}',
    '{"guard_permission_passthrough":1,"hookSpecificOutput":{"hookEventName":"PermissionRequest"}}',
    '{"guard_permission_passthrough":"true","hookSpecificOutput":{"hookEventName":"PermissionRequest"}}',
    '{"hookSpecificOutput":{"hookEventName":"X"},"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"}}',
    '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"},"hookSpecificOutput":{}}',
    '{"decision":"block","reason":"r"}',
    '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"},"n":NaN}',
    '{"hookSpecificOutput":{"hookEventName":"Permission\\ud800","decision":{"behavior":"deny"}}}',
    LONG_INT_OUTPUT,
    DEEP_OUTPUT,
]

VALIDATE_DATAS = [
    "{}",
    '{"hook_event_name":"PreToolUse"}',
    '{"hook_event_name":"PermissionRequest"}',
    '{"hook_event_name":"UserPromptSubmit","prompt":"secret"}',
    '{"hook_event_name":"Stop"}',
    '{"hook_event_name":"Permission\\ud800"}',
]


def _outcome(function, *args) -> str:
    try:
        return function(*args)
    except Exception as error:  # the error type is the vector
        return f"<error:{type(error).__name__}>"


def _set_environment(pairs: list[tuple[bytes, bytes]]) -> None:
    os.environb.clear()
    for name, value in pairs:
        os.environb[name] = value


def _stamp_vectors() -> list[dict[str, object]]:
    saved = dict(os.environb)
    try:
        vectors = []
        for index, pairs in enumerate(ENVIRONMENTS):
            _set_environment(pairs)
            # The long loader-path environment repeats its paths in every stamp.
            inputs = STAMP_INPUTS[:1] if index == len(ENVIRONMENTS) - 1 else STAMP_INPUTS
            vectors.append(
                {
                    "environment": [[name.hex(), value.hex()] for name, value in pairs],
                    "collected": json.dumps(
                        hook_execution_environment.collect_hook_execution_environment(),
                        separators=(",", ":"),
                    ),
                    "stamped": [_outcome(hook_execution_environment.stamp_hook_input_text, text) for text in inputs],
                }
            )
        return vectors
    finally:
        _set_environment(list(saved.items()))


def _hint_vectors() -> list[dict[str, object]]:
    original = codex_transport.time
    codex_transport.time = SimpleNamespace(monotonic=lambda: 0.0)
    try:
        return [
            {
                "data": data,
                "raw_ms": int(deadline * 1000),
                "hinted": _outcome(codex_transport._with_remaining_hint, data, deadline),
            }
            for data in HINT_INPUTS
            for deadline in HINT_DEADLINES
        ]
    finally:
        codex_transport.time = original


def _transport_event(data: str) -> str:
    return json.dumps(transport._event_name(data))


def _render_vectors() -> list[dict[str, object]]:
    vectors = []
    for data in RENDER_DATAS:
        name = bridge._event_name(data)
        vectors.append(
            {
                "data": data,
                "event": json.dumps(name),
                "string_event": _string_event(data),
                "limit_denied": bridge._limit_denied("hook input", name),
                "degraded": [bridge._degraded(reason, data) for reason in REASONS],
                "control_plane": [bridge._authenticated_control_plane_failure(reason, data) for reason in REASONS],
                "suppress": [bridge._should_suppress_output(data, body) for body in SUPPRESS_BODIES],
            }
        )
    return vectors


def _string_event(data: str) -> bool:
    """Whether ``_event_name`` returned a JSON string member, not ``str()`` of another value."""
    try:
        payload = json.loads(data or "{}")
    except json.JSONDecodeError:
        return True
    if not isinstance(payload, dict):
        return True
    value = payload.get("hook_event_name") or payload.get("event")
    return not value or isinstance(value, str)


def _validate_vectors() -> list[dict[str, object]]:
    return [
        {
            "output": output,
            "data": data,
            "result": _outcome(
                lambda o, d: bridge._valid_hook_json_or_degraded(o, reason=REASONS[1], data=d), output, data
            ),
        }
        for output in VALIDATE_OUTPUTS
        for data in VALIDATE_DATAS
    ]


def _compact(value: object, source: str | None = None) -> object:
    """Store a long text as its token and a result that echoes its input as ``@same``."""
    if isinstance(value, list):
        return [_compact(item, source) for item in value]
    if isinstance(value, dict):
        source = value.get("data", source)
        return {key: _compact(item, None if key == "data" else source) for key, item in value.items()}
    if not isinstance(value, str):
        return value
    if source is not None and value == source and value in TOKENS.values():
        return "@same"
    for token, text in TOKENS.items():
        if value == text:
            return token
    if any(text in value for text in TOKENS.values()):
        raise SystemExit(f"untokenized long text in {value[:80]!r}")
    return value


def main() -> int:
    vectors = {
        "reasons": REASONS,
        "suppress_bodies": SUPPRESS_BODIES,
        "stamp_inputs": STAMP_INPUTS,
        "stamp": _stamp_vectors(),
        "hint": _hint_vectors(),
        "transport_event": [
            {"data": data, "event": _outcome(_transport_event, data)} for data in TRANSPORT_EVENT_INPUTS
        ],
        "render": _render_vectors(),
        "validate": _validate_vectors(),
    }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    vectors = _compact(vectors)
    text = json.dumps(vectors, indent=1, ensure_ascii=True) + "\n"
    OUTPUT.write_bytes(gzip.compress(text.encode("ascii"), mtime=0))
    print(f"wrote {OUTPUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

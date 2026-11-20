"""Read fragments of the Pi-family extension template the native runtime renders.

The template lives beside the Rust renderer. Tests that exercise one helper
read its fragment back here instead of rendering a whole extension.
"""

from __future__ import annotations

import json
import re
from functools import cache
from pathlib import Path

TEMPLATE_PATH = (
    Path(__file__).resolve().parents[1] / "rust/crates/guard-runtime/src/adapters/pi_extension_render.v1.json"
)


@cache
def _variants() -> dict[str, list[str]]:
    document = json.loads(TEMPLATE_PATH.read_text(encoding="utf-8"))
    assert document["schema"] == "guard-pi-extension-render-template.v1"
    return document["variants"]


def _substitute(line: str, values: dict[str, str]) -> str:
    parts = line.split("@@")
    return "".join(values[part] if index % 2 else part for index, part in enumerate(parts))


def _harness_lines(variant: str, harness: str) -> list[str]:
    lines: list[str] = []
    selected: str | None = None
    for line in _variants()[variant]:
        if line.startswith("@@if ") and line.endswith("@@"):
            selected = line[5:-2]
        elif line == "@@fi@@":
            selected = None
        elif selected is None or selected == harness:
            lines.append(line)
    return lines


def render(variant: str, harness: str, values: dict[str, str]) -> str:
    """The whole source with each placeholder replaced by its spelled ``values`` entry."""

    lines = [line for line in _harness_lines(variant, harness) if not line.startswith(("@@begin ", "@@end "))]
    return "\n".join(_substitute(line, values) for line in lines)


def fragment(name: str, *, harness: str = "omp", variant: str = "active") -> str:
    """The text between ``@@begin name@@`` and ``@@end name@@`` for ``harness``."""

    lines = _harness_lines(variant, harness)
    start = lines.index(f"@@begin {name}@@") + 1
    end = lines.index(f"@@end {name}@@", start)
    body = [line for line in lines[start:end] if not line.startswith(("@@begin ", "@@end "))]
    assert not any("@@" in line for line in body), name
    return "\n".join(body) + "\n"


def constant(name: str, *, variant: str = "active") -> int:
    """The integer a ``const NAME = <n>;`` template line declares."""

    pattern = re.compile(rf"^const {re.escape(name)} = ([0-9_]+);$")
    for line in _variants()[variant]:
        match = pattern.match(line)
        if match:
            return int(match.group(1).replace("_", ""))
    raise KeyError(name)


DUMMY_VALUES: dict[str, str] = {
    "display_name": "Pi",
    "guard_args": "[]",
    "guard_home": '"/guard-home"',
    "home_dir": '"/home"',
    "home_dir_is_default": "false",
    "config_path": '"/home/.pi/agent/settings.json"',
    "compatibility_version": "1",
    "cli_command": '"hol-guard"',
    "cli_args": "[]",
    "cli_accepts_json_args": "false",
    "recovery_command": '"hol-guard"',
    "recovery_args": "[]",
    "recovery_accepts_failure_kind": "false",
    "taskkill_path": "null",
    "native_hook_runtime": "null",
    "contained_sink_command": "[]",
    "contained_request_root": '""',
}


def _environment_names() -> tuple[str, ...]:
    match = re.search(r"(\[[^\]]*\])\.filter\(", fragment("bound_bash_host_stamp"))
    assert match is not None
    return tuple(json.loads(match.group(1)))


BOUND_BASH_HOST_STAMP_MARKER = "  let payloadToSend = {\n    ...payload,\n"
CLI_RUNTIME_HELPERS_SOURCE = fragment("cli_runtime_helpers")
CONTAINED_TEST_HELPERS_SOURCE = fragment("contained_test_helpers")
BOUND_BASH_INTENT_SOURCE = fragment("bound_bash_intent")
TOOL_APPROVAL_RESUME_SOURCE = fragment("tool_approval_resume")
ENVIRONMENT_NAMES = _environment_names()

#!/usr/bin/env python3
"""Record the Pi-family extension template and replay vectors from the ORIGINAL Python renderer.

Run against a checkout that still renders the extension in Python (the base
of the commit that introduced the native `pi_extension_render`
runner-authority kind), never from Rust output:

    cd <base-worktree>
    HOL_GUARD_PI_HOOK_BRIDGE=fetch PYTHONPATH=$PWD/src python3 <this-file> \
        <output pi_extension_render.v1.json> <output pi_extension_render_vectors.json>

The template is the Python render with every per-install value replaced by an
`@@name@@` placeholder. Lines that differ between the `omp` and `pi` renders
sit between `@@if omp@@`/`@@if pi@@` and `@@fi@@` marker lines, and
`@@begin NAME@@`/`@@end NAME@@` lines name fragments the Python tests reuse.
The vectors pin each case's exact Python render by length and SHA-256; the
recorder refuses to write unless a mirror of the native substitution
reproduces every one of them.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import sys
import unicodedata
from pathlib import Path
from types import SimpleNamespace

from codex_plugin_scanner.guard.adapters._modules.pi.pi_extension_bound_bash_intent_source import (
    BOUND_BASH_INTENT_SOURCE,
)
from codex_plugin_scanner.guard.adapters._modules.pi.pi_extension_bound_bash_source import (
    with_bound_bash_host_observation,
)
from codex_plugin_scanner.guard.adapters._modules.pi.pi_extension_cli_runtime_source import (
    CLI_RUNTIME_HELPERS_SOURCE,
)
from codex_plugin_scanner.guard.adapters._modules.pi.pi_extension_contained_tests_source import (
    CONTAINED_TEST_HELPERS_SOURCE,
)
from codex_plugin_scanner.guard.adapters._modules.pi.pi_extension_tool_resume_source import (
    TOOL_APPROVAL_RESUME_SOURCE,
)

from codex_plugin_scanner.guard.adapters import pi_extension_previous_source as previous_module
from codex_plugin_scanner.guard.adapters import pi_extension_source as active_module
from codex_plugin_scanner.guard.adapters._modules.pi import pi_extension_source_header as active_header
from codex_plugin_scanner.guard.adapters._modules.pi import pi_extension_source_runtime as source_runtime
from codex_plugin_scanner.guard.adapters._modules.pi.pi_extension_native_hook import native_hook_reply_source
from codex_plugin_scanner.guard.adapters.pi_extension_runtime_ownership import PiExtensionRuntimeOwnership

HARNESSES = ("omp", "pi")
VARIANTS = {
    "active": active_module._ACTIVE_SOURCE_VARIANT_V1,
    "previous": previous_module._PREVIOUS_SOURCE_VARIANT_V1,
}
NATIVE_RUNTIME_LINE = "const GUARD_NATIVE_HOOK_RUNTIME: string | null = @@native_hook_runtime@@;\n"
SINK_LINE = "const GUARD_CONTAINED_SINK_COMMAND: string[] = [];\n"
ROOT_LINE = 'const GUARD_CONTAINED_REQUEST_ROOT = "";\n'
STAMP_MARKER = "  let payloadToSend = {\n    ...payload,\n"


class Sentinel:
    def __init__(self, name: str) -> None:
        self.name = name

    def __str__(self) -> str:
        return f"@@{self.name}@@"


def placeholder_source(variant_name: str, harness: str) -> str:
    variant = VARIANTS[variant_name]
    runtime = SimpleNamespace(
        cli_accepts_json_args=Sentinel("cli_accepts_json_args"),
        recovery_accepts_failure_kind=Sentinel("recovery_accepts_failure_kind"),
        contained_sink_command=(),
        contained_request_root="",
    )
    original = active_header.native_hook_runtime_source
    active_header.native_hook_runtime_source = lambda _guard_home_json: NATIVE_RUNTIME_LINE
    try:
        header = variant.build_header(
            cli_wrapper_command_json="@@cli_command@@",
            cli_wrapper_args_json="@@cli_args@@",
            compatibility_version_json="@@compatibility_version@@",
            config_path_json="@@config_path@@",
            guard_args_json="@@guard_args@@",
            guard_home_json="@@guard_home@@",
            home_dir_is_default_json="@@home_dir_is_default@@",
            home_dir_json="@@home_dir@@",
            recovery_args_json="@@recovery_args@@",
            recovery_command_json="@@recovery_command@@",
            runtime=runtime,
            taskkill_path_json="@@taskkill_path@@",
            guard_cli_hook_timeout_ms=variant.cli_hook_timeout_ms,
            guard_daemon_hook_timeout_ms=variant.daemon_hook_timeout_ms,
            guard_daemon_recovery_timeout_ms=variant.daemon_recovery_timeout_ms,
            guard_daemon_retry_timeout_ms=variant.daemon_retry_timeout_ms,
            guard_hook_content_item_limit=variant.content_item_limit,
            guard_hook_deadline_reserve_ms=variant.deadline_reserve_ms,
            guard_hook_max_depth=variant.max_depth,
            guard_hook_max_serialized_payload_chars=variant.max_serialized_payload_chars,
            guard_hook_object_key_limit=variant.object_key_limit,
            guard_hook_text_limit_chars=variant.text_limit_chars,
            guard_hook_timeout_ms=variant.hook_timeout_ms,
        )
    finally:
        active_header.native_hook_runtime_source = original
    if variant_name == "active":
        for line, value in ((SINK_LINE, " = []"), (ROOT_LINE, ' = ""')):
            assert header.count(line) == 1 and line.count(value) == 1, line
            name = "contained_sink_command" if line == SINK_LINE else "contained_request_root"
            header = header.replace(line, line.replace(value, f" = @@{name}@@"))
    else:
        assert NATIVE_RUNTIME_LINE not in header and "GUARD_CONTAINED_SINK_COMMAND" not in header
    body = variant.build_body(harness=harness, display_name="@@display_name@@")
    tail = variant.build_tail(
        display_name="@@display_name@@",
        harness=harness,
        lifecycle_abort_event_source=variant.build_lifecycle(harness),
        tool_approval_continuation_source=variant.build_approval(harness),
    )
    return header + body + tail


def fragments(harness: str) -> dict[str, str]:
    stamp = with_bound_bash_host_observation(STAMP_MARKER, harness=harness)
    found = {
        "cli_runtime_helpers": CLI_RUNTIME_HELPERS_SOURCE,
        "native_hook_reply": native_hook_reply_source(harness),
        "bound_bash_host_stamp": stamp,
    }
    if harness == "omp":
        found["contained_test_helpers"] = CONTAINED_TEST_HELPERS_SOURCE
        found["bound_bash_intent"] = BOUND_BASH_INTENT_SOURCE
        found["tool_approval_resume"] = TOOL_APPROVAL_RESUME_SOURCE
    return found


def with_sections(source: str, variant_name: str, harness: str) -> list[str]:
    lines = source.split("\n")
    offsets = [0]
    for line in lines:
        offsets.append(offsets[-1] + len(line) + 1)
    begins: dict[int, list[tuple[int, str]]] = {}
    ends: dict[int, list[str]] = {}
    for name, fragment in fragments(harness).items():
        if source.count(fragment) != 1:
            # The previous variant is frozen; it carries only the shared helpers.
            assert variant_name == "previous" or name == "native_hook_reply", (variant_name, harness, name)
            continue
        assert fragment.endswith("\n")
        start = source.index(fragment)
        first = offsets.index(start)
        last = offsets.index(start + len(fragment))
        begins.setdefault(first, []).append((last, name))
        ends.setdefault(last, []).append(name)
    marked: list[str] = []
    for index, line in enumerate(lines):
        marked.extend(f"@@end {name}@@" for name in ends.get(index, []))
        marked.extend(f"@@begin {name}@@" for _, name in sorted(begins.get(index, []), reverse=True))
        marked.append(line)
    return marked


def merged_template(variant_name: str) -> list[str]:
    left = with_sections(placeholder_source(variant_name, "omp"), variant_name, "omp")
    right = with_sections(placeholder_source(variant_name, "pi"), variant_name, "pi")
    merged: list[str] = []
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(a=left, b=right, autojunk=False).get_opcodes():
        if tag == "equal":
            merged.extend(left[i1:i2])
            continue
        for harness, block in (("omp", left[i1:i2]), ("pi", right[j1:j2])):
            if block:
                merged.extend([f"@@if {harness}@@", *block, "@@fi@@"])
    return merged


def substitute(line: str, values: dict[str, str]) -> str:
    parts = line.split("@@")
    assert len(parts) % 2 == 1, line
    return "".join(values[part] if index % 2 else part for index, part in enumerate(parts))


def render_template(lines: list[str], harness: str, values: dict[str, str]) -> str:
    output: list[str] = []
    selected: str | None = None
    for line in lines:
        if line.startswith("@@if ") and line.endswith("@@"):
            assert selected is None
            selected = line[5:-2]
        elif line == "@@fi@@":
            assert selected is not None
            selected = None
        elif line.startswith(("@@begin ", "@@end ")) and line.endswith("@@"):
            continue
        elif selected is None or selected == harness:
            output.append(substitute(line, values))
    assert selected is None
    return "\n".join(output)


def placeholder_values(args: dict[str, object]) -> dict[str, str]:
    def display_name_fragment(value: str) -> str:
        escaped: list[str] = []
        for index, character in enumerate(value):
            if character == "\\":
                escaped.append("\\\\")
            elif character == "'":
                escaped.append("\\'")
            elif character == '"':
                escaped.append('\\"')
            elif character == "`":
                escaped.append("\\`")
            elif character == "$" and value[index + 1 : index + 2] == "{":
                escaped.append("\\$")
            elif character == "\n":
                escaped.append("\\n")
            elif character == "\r":
                escaped.append("\\r")
            elif character == "\t":
                escaped.append("\\t")
            elif unicodedata.category(character) == "Cc":
                escaped.append(f"\\u{ord(character):04x}")
            else:
                escaped.append(character)
        return "".join(escaped)

    values = {
        "display_name": display_name_fragment(str(args["display_name"])),
        "guard_args": json.dumps(args["guard_args"]),
        "guard_home": json.dumps(args["guard_home"]),
        "home_dir": json.dumps(args["home_dir"]),
        "home_dir_is_default": "true" if args["home_dir_is_default"] else "false",
        "config_path": json.dumps(args["config_path"]),
        "compatibility_version": json.dumps(args["compatibility_version"]),
        "cli_command": json.dumps(args["cli_command"]),
        "cli_args": json.dumps(args["cli_args"]),
        "cli_accepts_json_args": str(args["cli_accepts_json_args"]).lower(),
        "recovery_command": json.dumps(args["recovery_command"]),
        "recovery_args": json.dumps(args["recovery_args"]),
        "recovery_accepts_failure_kind": str(args["recovery_accepts_failure_kind"]).lower(),
        "taskkill_path": json.dumps(args["taskkill_path"]),
    }
    if args["variant"] == "active":
        values["native_hook_runtime"] = json.dumps(args["native_hook_runtime"])
        values["contained_sink_command"] = json.dumps(args["contained_sink_command"])
        values["contained_request_root"] = json.dumps(args["contained_request_root"])
    return values


def python_render(args: dict[str, object]) -> str:
    variant_name = str(args["variant"])
    runtime = PiExtensionRuntimeOwnership(
        guard_args=tuple(args["guard_args"]),  # type: ignore[arg-type]
        cli_command=str(args["cli_command"]),
        cli_args=tuple(args["cli_args"]),  # type: ignore[arg-type]
        cli_accepts_json_args=bool(args["cli_accepts_json_args"]),
        recovery_command=str(args["recovery_command"]),
        recovery_args=tuple(args["recovery_args"]),  # type: ignore[arg-type]
        recovery_accepts_failure_kind=bool(args["recovery_accepts_failure_kind"]),
        contained_sink_command=tuple(args.get("contained_sink_command", ())),  # type: ignore[arg-type]
        contained_request_root=str(args.get("contained_request_root", "")),
    )
    native = args.get("native_hook_runtime")
    original_native = active_header.native_hook_runtime_source
    active_header.native_hook_runtime_source = lambda _guard_home_json: (
        f"const GUARD_NATIVE_HOOK_RUNTIME: string | null = {json.dumps(native)};\n"
    )
    original_path = source_runtime.Path
    home_dir = str(args["home_dir"])
    is_default = bool(args["home_dir_is_default"])

    class ResolvingPath(type(Path())):  # type: ignore[misc]
        @classmethod
        def home(cls) -> Path:
            return original_path(home_dir if is_default else "/guard-vectors/not-this-home")

    source_runtime.Path = ResolvingPath
    taskkill = args["taskkill_path"]
    try:
        return source_runtime.render_extension_source_variant_v1(
            guard_home=original_path(str(args["guard_home"])),
            home_dir=original_path(home_dir),
            settings_path=original_path(str(args["config_path"])),
            harness=str(args["harness"]),
            display_name=str(args["display_name"]),
            package_source=Path(active_module.__file__),
            compatibility_version=int(args["compatibility_version"]),  # type: ignore[arg-type]
            runtime_resolver=lambda **_kwargs: runtime,
            windows_executable_path=lambda _name: taskkill,
            platform_name="nt" if taskkill is not None else "posix",
            variant=VARIANTS[variant_name],
        )
    finally:
        source_runtime.Path = original_path
        active_header.native_hook_runtime_source = original_native


def case(name: str, variant: str, harness: str, **overrides: object) -> dict[str, object]:
    args: dict[str, object] = {
        "variant": variant,
        "harness": harness,
        "display_name": "Oh My Pi" if harness == "omp" else "Pi",
        "guard_args": ["--guard-home", "/guard-vectors/dev/.hol-guard"],
        "guard_home": "/guard-vectors/dev/.hol-guard",
        "home_dir": "/guard-vectors/dev",
        "home_dir_is_default": False,
        "config_path": f"/guard-vectors/dev/.{harness}/agent/settings.json",
        "compatibility_version": 7,
        "cli_command": "/opt/guard/bin/hol-guard",
        "cli_args": ["hook", "--harness", harness],
        "cli_accepts_json_args": False,
        "recovery_command": "/opt/guard/bin/hol-guard",
        "recovery_args": ["daemon", "recover"],
        "recovery_accepts_failure_kind": True,
        "taskkill_path": None,
    }
    if variant == "active":
        args["native_hook_runtime"] = "/opt/guard/bin/hol-guard-runtime"
        args["contained_sink_command"] = ["/opt/guard/bin/hol-guard", "contained-sink"]
        args["contained_request_root"] = "/guard-vectors/dev/.hol-guard/contained"
    args.update(overrides)
    return {"name": name, "args": args}


WINDOWS = {
    "guard_home": "C:\\Users\\dev\\.hol-guard",
    "home_dir": "C:\\Users\\dev",
    "config_path": 'C:\\Users\\dev\\.omp\\agent\\"quoted" settings.json',
    "guard_args": ["--guard-home", "C:\\Users\\dev\\.hol-guard"],
    "cli_command": "C:\\Program Files\\HOL Guard\\hol-guard.exe",
    "cli_args": [],
    "cli_accepts_json_args": True,
    "recovery_command": "C:\\Program Files\\HOL Guard\\hol-guard.exe",
    "recovery_args": [],
    "recovery_accepts_failure_kind": False,
    "taskkill_path": "C:\\Windows\\System32\\taskkill.exe",
}
NON_ASCII = {
    "guard_home": "/guard-vectors/d\u00e9v/\u4e2d\u6587/.hol-guard",
    "home_dir": "/guard-vectors/d\u00e9v",
    "config_path": "/guard-vectors/d\u00e9v/\U0001f600/settings.json",
    "guard_args": ["--guard-home", "/guard-vectors/d\u00e9v/\u4e2d\u6587/.hol-guard", "\U0001f680"],
    "cli_args": ["\u00e9", "tab\tnew\nline\r\x0c\x08\x01\x7f"],
    "display_name": "Pi \u00e9",
}
PLACEHOLDER_SPELLINGS = {
    "guard_home": "/guard-vectors/@@home_dir@@/@@if pi@@",
    "home_dir": "/guard-vectors/@@guard_home@@",
    "config_path": "/@@fi@@/@@end cli_runtime_helpers@@",
    "cli_command": "/opt/@@cli_args@@",
    "cli_args": ["@@display_name@@", "@@"],
    "display_name": "@@guard_home@@",
    "recovery_args": ["@@taskkill_path@@"],
}

CASES = [
    case("active_omp_posix", "active", "omp"),
    case("active_pi_posix", "active", "pi"),
    case("previous_omp_posix", "previous", "omp"),
    case("previous_pi_posix", "previous", "pi"),
    case(
        "active_omp_windows",
        "active",
        "omp",
        native_hook_runtime=None,
        contained_sink_command=[],
        contained_request_root="",
        **WINDOWS,
    ),
    case("previous_pi_windows", "previous", "pi", **WINDOWS),
    case("active_pi_non_ascii", "active", "pi", contained_request_root="/guard-vectors/\u00e9/r", **NON_ASCII),
    case("previous_omp_non_ascii", "previous", "omp", **NON_ASCII),
    case(
        "active_omp_placeholder_spellings",
        "active",
        "omp",
        native_hook_runtime="/@@contained_sink_command@@",
        **PLACEHOLDER_SPELLINGS,
    ),
    case(
        "active_pi_default_home_fixture_name",
        "active",
        "pi",
        display_name="fixture",
        home_dir_is_default=True,
        compatibility_version=0,
        guard_args=[],
        cli_accepts_json_args=True,
        recovery_accepts_failure_kind=False,
    ),
    case(
        "previous_omp_default_home_large_version",
        "previous",
        "omp",
        home_dir_is_default=True,
        compatibility_version=2**53,
        display_name='O\'Brien "Pi" `x`',
    ),
]


def main() -> None:
    template = {"schema": "guard-pi-extension-render-template.v1", "variants": {}}
    for variant_name in VARIANTS:
        lines = merged_template(variant_name)
        for line in lines:
            parts = line.split("@@")
            assert len(parts) % 2 == 1, line
            for name in parts[1::2]:
                assert (
                    name.replace("_", "").isalnum() or name in {"fi"} or name.startswith(("if ", "begin ", "end "))
                ), (line, name)
        template["variants"][variant_name] = lines
    recorded = []
    for entry in CASES:
        args = entry["args"]
        assert isinstance(args, dict)
        expected = python_render(args)
        mirrored = render_template(
            template["variants"][str(args["variant"])], str(args["harness"]), placeholder_values(args)
        )
        assert mirrored == expected, entry["name"]
        recorded.append(
            {
                "name": entry["name"],
                "args": args,
                "chars": len(expected),
                "sha256": hashlib.sha256(expected.encode("utf-8")).hexdigest(),
            }
        )
    Path(sys.argv[1]).write_text(json.dumps(template, indent=0, ensure_ascii=False) + "\n", encoding="utf-8")
    vectors = {"schema": "guard-pi-extension-render-vectors.v1", "cases": recorded}
    Path(sys.argv[2]).write_text(json.dumps(vectors, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()

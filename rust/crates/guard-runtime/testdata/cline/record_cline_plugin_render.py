#!/usr/bin/env python3
"""Record the Cline AgentPlugin template and replay vectors from the ORIGINAL Python renderer.

Run against a checkout that still renders the plugin in Python (the base of
the commit that introduced the native `cline_plugin_render` runner-authority
kind), never from Rust output:

    cd <base-worktree>
    PYTHONPATH=$PWD/src python3 <this-file> \
        <output cline_plugin_render.v1.json> <output cline_plugin_render_vectors.json>

The template is the Python render with every per-install value replaced by an
`@@name@@` placeholder. The vectors pin each case's exact Python render by
length and SHA-256; the recorder refuses to write unless a mirror of the
native substitution reproduces every one of them.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace

from codex_plugin_scanner.guard.adapters import cline_plugin

FIELDS = ("guard_cli", "hook_argv", "adapter_state", "proof_loaded", "proof_pretool", "proof_posttool")
PROOFS = {"loaded": "proof_loaded", "pretool": "proof_pretool", "posttool": "proof_posttool"}


def _python_render(args: dict[str, object]) -> str:
    original_state = cline_plugin._adapter_state_path
    original_proof = cline_plugin._proof_path
    cline_plugin._adapter_state_path = lambda _context: Path(str(args["adapter_state"]))
    cline_plugin._proof_path = lambda _context, name: Path(str(args[PROOFS[name]]))
    try:
        return cline_plugin._plugin_source(
            SimpleNamespace(guard_home=Path("/unused")),
            list(args["guard_cli"]),  # type: ignore[arg-type]
            list(args["hook_argv"]),  # type: ignore[arg-type]
        )
    finally:
        cline_plugin._adapter_state_path = original_state
        cline_plugin._proof_path = original_proof


def _template() -> list[str]:
    sentinels: dict[str, object] = {
        "guard_cli": ["SENTINEL_GUARD_CLI"],
        "hook_argv": ["SENTINEL_HOOK_ARGV"],
        "adapter_state": "SENTINEL_ADAPTER_STATE",
        "proof_loaded": "SENTINEL_PROOF_LOADED",
        "proof_pretool": "SENTINEL_PROOF_PRETOOL",
        "proof_posttool": "SENTINEL_PROOF_POSTTOOL",
    }
    source = _python_render(sentinels)
    assert "@@" not in source
    for name, value in sentinels.items():
        spelled = json.dumps(value)
        assert source.count(spelled) == 1, name
        source = source.replace(spelled, f"@@{name}@@")
    assert "SENTINEL_" not in source
    return source.split("\n")


def _native_mirror(lines: list[str], args: dict[str, object]) -> str:
    values = {name: json.dumps(args[name]) for name in FIELDS}
    rendered = []
    for line in lines:
        parts = line.split("@@")
        rendered.append("".join(values[part] if index % 2 else part for index, part in enumerate(parts)))
    return "\n".join(rendered)


def _paths(home: str, sep: str) -> dict[str, str]:
    base = sep.join([home, "managed", "cline"])
    return {
        "adapter_state": sep.join([base, "adapter-state.json"]),
        "proof_loaded": sep.join([base, "proofs", "plugin-loaded.json"]),
        "proof_pretool": sep.join([base, "proofs", "plugin-pretool.json"]),
        "proof_posttool": sep.join([base, "proofs", "plugin-posttool.json"]),
    }


def _cases() -> list[tuple[str, dict[str, object]]]:
    posix_cli = ["/usr/bin/python3", "-m", "codex_plugin_scanner.cli", "guard", "hook"]
    bounded = ["/usr/bin/python3", "-I", "-c", "import sys; print('x')", "--guard-home", "/g", "--harness", "cline"]
    windows_cli = ["C:\\Program Files\\Python312\\python.exe", "-m", "codex_plugin_scanner.cli", "guard", "hook"]
    frozen_cli = ["/Applications/HOL Guard.app/Contents/MacOS/hol-guard", "guard", "hook"]
    return [
        (
            "posix_default_hook",
            {
                "guard_cli": posix_cli,
                "hook_argv": [*posix_cli, "--harness", "cline", "--json"],
                **_paths("/home/u/.hol-guard", "/"),
            },
        ),
        ("posix_bounded_bridge", {"guard_cli": posix_cli, "hook_argv": bounded, **_paths("/home/u/.hol-guard", "/")}),
        (
            "windows_paths",
            {
                "guard_cli": windows_cli,
                "hook_argv": [*windows_cli, "--harness", "cline", "--json"],
                **_paths("C:\\Users\\t\\.hol-guard", "\\"),
            },
        ),
        (
            "frozen_executable",
            {
                "guard_cli": frozen_cli,
                "hook_argv": [*frozen_cli, "--harness", "cline", "--json"],
                **_paths("/var/guard-user/.hol-guard", "/"),
            },
        ),
        (
            "quoted_and_non_ascii",
            {
                "guard_cli": ['/h\u00e9/\U0001f600/py"thon', "-c", "print('a\\nb')\t\u007f"],
                "hook_argv": ["/h\u00e9/py", "@@guard_cli@@", "</script>"],
                **_paths("/h\u00e9/\u0000guard", "/"),
            },
        ),
        ("empty_lists", {"guard_cli": [], "hook_argv": [], **_paths("", "/")}),
    ]


def main() -> None:
    template_path, vectors_path = (Path(value) for value in sys.argv[1:3])
    lines = _template()
    cases = []
    for name, args in _cases():
        source = _python_render(args)
        assert _native_mirror(lines, args) == source, name
        cases.append(
            {
                "name": name,
                "args": args,
                "chars": len(source),
                "sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
            }
        )
    template = {"schema": "guard-cline-plugin-render-template.v1", "lines": lines}
    vectors = {"schema": "guard-cline-plugin-render-vectors.v1", "cases": cases}
    template_path.write_text(json.dumps(template, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    vectors_path.write_text(json.dumps(vectors, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()

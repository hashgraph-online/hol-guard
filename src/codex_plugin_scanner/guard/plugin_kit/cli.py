"""CLI for the HOL Guard Plugin Kit: ``hol-guard plugin init|check|package|links``.

Detection, checks, packaging and file writes run in the native runtime's
``plugin-kit`` command. This module parses arguments, sends one request and
renders the result.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

PLUGIN_KIT_COMMAND = "plugin-kit"
PLUGIN_KIT_FEATURE = "plugin-kit-v1"
_TIMEOUT_SECONDS = 120.0
_OUTPUT_LIMIT_BYTES = 16 * 1024 * 1024
_NATIVE_UNAVAILABLE = "The HOL Guard Plugin Kit requires the Guard native runtime. Run: pip install -U hol-guard"
_NATIVE_FAILED = "The HOL Guard Plugin Kit did not complete."

_ERRORS = {
    "plugin_kit_root_invalid": "The path is not a readable folder.",
    "plugin_kit_root_unreadable": "The folder could not be read.",
    "plugin_kit_repository_too_large": "The repository has too many files to inspect.",
    "plugin_kit_unknown_runtime": "Unknown runtime. Choose from: "
    + ", ".join(
        (
            "claude-code",
            "codex",
            "gemini-cli",
            "cursor",
            "vscode",
            "opencode",
            "mcp-registry",
            "agent-skills",
        )
    ),
    "plugin_kit_runtime_unsupported": (
        "A requested runtime cannot load this plugin. Run check to see what each runtime takes."
    ),
    "plugin_kit_output_not_empty": "The output folder is not empty. Pass --force to write into it.",
    "plugin_kit_output_path_invalid": "The output path is invalid.",
    "plugin_kit_output_path_blocked": "Something other than a folder is in the way of the output path.",
    "plugin_kit_output_exists": "A file the Kit would write already exists.",
    "plugin_kit_output_inside_source": (
        "The output folder is inside a folder the Kit reads the plugin from. Choose one outside it."
    ),
    "plugin_kit_output_unwritable": "The output folder could not be written.",
    "plugin_kit_package_too_large": "The plugin is too large to package.",
    "plugin_kit_init_needs_name": "This folder has no plugin yet. Pass --name to scaffold one.",
    "plugin_kit_init_name_invalid": "Use a kebab-case --name of at most 64 characters, such as my-plugin.",
    "plugin_kit_init_folder_not_empty": (
        "init scaffolds a plugin only in a new folder: one holding nothing but a README, a LICENSE or dotfiles."
    ),
    "plugin_kit_init_would_overwrite": "init never overwrites files, and one it would write already exists.",
    "plugin_kit_request_invalid": (
        "The runtime rejected the request. Reinstall hol-guard so the CLI and the runtime match."
    ),
    "plugin_kit_encode_failed": "The runtime could not encode its answer.",
}


class PluginKitNativeError(RuntimeError):
    """The native runtime was unavailable or returned no usable response."""


def _native_request(request: Mapping[str, object]) -> dict[str, Any]:
    """Run one ``plugin-kit`` request and return its ``{ok, result|error}`` reply."""

    from ..codex_hook_launch_runtime import run_isolated_hook_process
    from ..native_runtime import native_runtime_status

    status = native_runtime_status()
    if (
        not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or PLUGIN_KIT_FEATURE not in status.capabilities.features
    ):
        raise PluginKitNativeError(_NATIVE_UNAVAILABLE)
    runtime = status.identity.path
    completed = run_isolated_hook_process(
        (str(runtime), PLUGIN_KIT_COMMAND, "--stdin"),
        input_text=json.dumps(dict(request), sort_keys=True, separators=(",", ":")),
        cwd=runtime.parent,
        environment=dict(os.environ),
        timeout_seconds=_TIMEOUT_SECONDS,
        output_limit=_OUTPUT_LIMIT_BYTES,
    )
    if (
        completed.returncode != 0
        or completed.timed_out
        or completed.output_limit_exceeded
        or completed.containment_failed
    ):
        raise PluginKitNativeError(_NATIVE_FAILED)
    try:
        response = json.loads(completed.stdout)
    except ValueError as error:
        raise PluginKitNativeError(_NATIVE_FAILED) from error
    if not isinstance(response, dict) or not isinstance(response.get("ok"), bool):
        raise PluginKitNativeError(_NATIVE_FAILED)
    return response


def _call(request: Mapping[str, object]) -> dict[str, Any] | None:
    """Return the native result, or print the error and return None."""

    try:
        response = _native_request(request)
    except PluginKitNativeError as error:
        print(f"Error: {error}", file=sys.stderr)
        return None
    if not response["ok"]:
        code = str(response.get("error") or "")
        print(f"Error: {_ERRORS.get(code, code or _NATIVE_FAILED)}", file=sys.stderr)
        return None
    result = response.get("result")
    return result if isinstance(result, dict) else {}


def _runtime_list(value: str) -> list[str]:
    """``--runtimes`` names, rejecting a list that names none."""

    names = [item.strip() for item in value.split(",") if item.strip()]
    if not names:
        raise argparse.ArgumentTypeError("name at least one runtime, such as claude-code,codex")
    return names


def build_parser(*, program_name: str = "hol-guard plugin") -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=program_name,
        description=(
            "Check a plugin source, package it for every agent runtime that can load it, "
            "and print its install links. Runs locally; nothing is uploaded."
        ),
    )
    commands = parser.add_subparsers(dest="command", required=True)

    def add(name: str, help_text: str) -> argparse.ArgumentParser:
        command = commands.add_parser(name, help=help_text, description=help_text)
        command.add_argument("path", nargs="?", default=".", help="Plugin repository (default: current folder).")
        command.add_argument("--json", action="store_true", help="Print the full result as JSON.")
        return command

    init = add("init", "Write hol.json for an existing plugin, or scaffold a new one with --name.")
    init.add_argument("--name", help="Kebab-case name for a new plugin in an empty folder.")
    check = add("check", "Report what marketplaces and runtime loaders would reject.")
    check.add_argument("--strict", action="store_true", help="Fail on warnings too.")
    package = add("package", "Write a ready-to-load copy of the plugin for each runtime.")
    package.add_argument("--out", help="Output folder (default: hol.json's out, else dist/hol-plugin).")
    package.add_argument(
        "--runtimes",
        type=_runtime_list,
        help="Comma-separated runtimes (default: hol.json's list, else every supported runtime).",
    )
    package.add_argument(
        "--force",
        action="store_true",
        help="Rebuild into a non-empty output folder, replacing the files the last package wrote.",
    )
    package.add_argument("--strict", action="store_true", help="Refuse to package when there are warnings.")
    add("links", "Print install commands for each runtime and where to list the plugin.")
    return parser


def _request(args: argparse.Namespace) -> dict[str, object]:
    request: dict[str, object] = {"command": args.command, "root": str(Path(args.path).resolve())}
    if args.command == "init" and args.name:
        request["name"] = args.name
    if args.command in {"check", "package"}:
        request["strict"] = bool(args.strict)
    if args.command == "package":
        if args.out:
            request["out_dir"] = str(Path(args.out).resolve())
        if args.runtimes:
            request["runtimes"] = args.runtimes
        request["force"] = bool(args.force)
    return request


def _write_check(result: Mapping[str, Any]) -> None:
    plugin = result.get("plugin") or {}
    name = plugin.get("name") or "(unnamed)"
    version = plugin.get("version")
    print(f"{name}{' ' + version if version else ''}")
    summary = result.get("summary") or {}
    parts = [
        f"{summary.get(key, 0)} {label}"
        for key, label in (
            ("skills", "skills"),
            ("mcp_servers", "MCP servers"),
            ("commands", "commands"),
            ("agents", "agents"),
        )
        if summary.get(key)
    ]
    if parts:
        print("  " + ", ".join(parts))
    diagnostics = result.get("diagnostics") or []
    if diagnostics:
        print()
    for item in diagnostics:
        location = f" {item.get('path')}" if item.get("path") else ""
        print(f"  {item.get('level', 'error')}: {item.get('code')}{location}")
        print(f"    {item.get('message')}")
    print()
    print("Runtimes:")
    for runtime in result.get("runtimes") or []:
        mark = "yes" if runtime.get("supported") else "no "
        dropped = runtime.get("dropped") or []
        note = f"  (drops {', '.join(dropped)})" if runtime.get("supported") and dropped else ""
        print(f"  {mark}  {runtime.get('runtime')}{note}")
    print()
    errors = int(summary.get("errors", 0))
    warnings = int(summary.get("warnings", 0))
    verdict = "passed" if result.get("passed") else "failed"
    print(f"Check {verdict}: {errors} errors, {warnings} warnings.")


def _write_links(result: Mapping[str, Any]) -> None:
    install = result.get("install") or []
    if not result.get("repository"):
        print("No GitHub repository found. Set repository in the plugin manifest to get install links.")
    for entry in install:
        print(f"{entry.get('runtime')}:")
        for command in entry.get("commands") or []:
            print(f"  {command}")
        if entry.get("verify"):
            print(f"  check: {entry['verify']}")
        print()
    hol = result.get("hol")
    if isinstance(hol, dict):
        print(f"Claim the HOL listing: {hol.get('connect')}")
        print(f"List a new plugin on HOL: {hol.get('submit')}")
        print()
    pending = [step for step in result.get("checklist") or [] if not step.get("done")]
    if pending:
        print("Next steps:")
        for step in pending:
            print(f"  - {step.get('message')}")


_GUARD_OFFER_MARKER = ("plugin-kit", "guard-offer-shown")


def _offer_guard_once() -> None:
    """Point plugin authors at local Guard protection, once per Guard home.

    The offer only prints a command; nothing is installed or sent.
    """

    from ..config import resolve_guard_home

    try:
        marker = resolve_guard_home().joinpath(*_GUARD_OFFER_MARKER)
        if marker.exists():
            return
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text("1\n", encoding="utf-8")
    except OSError:
        return
    print()
    print("Tip: Guard can also protect the agents you test this plugin in.")
    print("  hol-guard install claude-code   (or codex, cursor, gemini, opencode)")


def main(argv: Sequence[str] | None = None, *, program_name: str = "hol-guard plugin") -> int:
    args = build_parser(program_name=program_name).parse_args(argv)
    result = _call(_request(args))
    if result is None:
        return 2
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    elif args.command == "check":
        _write_check(result)
    elif args.command == "links":
        _write_links(result)
    elif args.command == "init":
        for path in result.get("written") or []:
            print(f"wrote {path}")
        if result.get("scaffolded"):
            print("\nNext: edit the description and skill, then run `hol-guard plugin check`.")
    elif args.command == "package":
        if not result.get("packaged"):
            _write_check(result.get("check") or {})
            print("\nNothing was written. Fix the errors above and run package again.")
        else:
            print(f"Packaged {len(result.get('files') or [])} files into {result.get('out_dir')}")
            for runtime in result.get("runtimes") or []:
                if runtime.get("supported"):
                    print(f"  {runtime.get('runtime')}/")
    if not args.json and (
        (args.command == "check" and result.get("passed")) or (args.command == "package" and result.get("packaged"))
    ):
        _offer_guard_once()
    if args.command == "check" and not result.get("passed"):
        return 1
    if args.command == "package" and not result.get("packaged"):
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

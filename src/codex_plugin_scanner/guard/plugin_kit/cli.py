"""CLI for the HOL Guard Plugin Kit: ``hol-guard plugin init|check|package|convert|links|card|install|uninstall|stats``.

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

from .output import write_check, write_conformance, write_links

PLUGIN_KIT_COMMAND = "plugin-kit"
PLUGIN_KIT_FEATURE = "plugin-kit-v1"
AGENT_PLUGINS_SPEC = "agent-plugins-1.0"
_TIMEOUT_SECONDS = 120.0
_OUTPUT_LIMIT_BYTES = 16 * 1024 * 1024
_NATIVE_UNAVAILABLE = "The HOL Guard Plugin Kit requires the Guard native runtime. Run: pip install -U hol-guard"
_NATIVE_FAILED = "The HOL Guard Plugin Kit did not complete."

_ERRORS = {
    "plugin_kit_root_invalid": "The path is not a readable folder.",
    "plugin_kit_root_unreadable": "The folder could not be read.",
    "plugin_kit_repository_too_large": "The repository has too many files to inspect.",
    "plugin_kit_config_invalid": "[plugin_kit] exclude_paths in .plugin-scanner.toml must be a list of path patterns.",
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
            "agent-plugins",
        )
    ),
    "plugin_kit_spec_unsupported": "Unknown spec. Supported: agent-plugins-1.0",
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
    "plugin_kit_package_path_conflict": "Two different files would be packaged at the same path.",
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
    "plugin_kit_install_spec_invalid": (
        "HOL's install details for this listing failed Guard's checks, so nothing will run. "
        "Follow the listing's install steps instead."
    ),
    "plugin_kit_install_spec_unsupported": "This listing needs a newer hol-guard. Run: pip install -U hol-guard",
    "plugin_kit_install_runtime_unknown": "Unknown runtime. Choose from: claude-code, codex, agent-skills",
    "plugin_kit_install_runtime_not_offered": "This listing cannot be installed for a runtime you named.",
    "plugin_kit_install_spec_mismatch": (
        "HOL answered with the install details of a different listing, so nothing will run."
    ),
    "plugin_kit_install_version_unavailable": (
        "HOL does not list that version, and runtime marketplaces install the listed release. "
        "Drop the @version to install what HOL lists."
    ),
    "plugin_kit_install_not_recorded": (
        "Guard has no record of installing this listing for the runtimes named, so it will not remove it. "
        "Use the runtime's own CLI instead."
    ),
    "plugin_kit_ledger_invalid": (
        "Guard's install record (plugin-kit/installs.json in the Guard home) could not be read, so nothing will run."
    ),
    "plugin_kit_ledger_unwritable": "Guard could not update its install record in the Guard home.",
    "plugin_kit_guard_home_invalid": "The Guard home must be an absolute path.",
    "plugin_kit_links_slug_invalid": "Use a HOL listing slug such as owner/plugin.",
    "plugin_kit_card_slug_invalid": "Use a HOL listing slug such as owner/plugin.",
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


def kit_request(request: Mapping[str, object]) -> dict[str, Any]:
    """Return the native result, raising PluginKitNativeError with the message to show."""

    response = _native_request(request)
    if not response["ok"]:
        code = str(response.get("error") or "")
        raise PluginKitNativeError(_ERRORS.get(code, code or _NATIVE_FAILED))
    result = response.get("result")
    return result if isinstance(result, dict) else {}


def _call(request: Mapping[str, object]) -> dict[str, Any] | None:
    """Return the native result, or print the error and return None."""

    try:
        return kit_request(request)
    except PluginKitNativeError as error:
        print(f"Error: {error}", file=sys.stderr)
        return None


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
    check.add_argument(
        "--spec",
        choices=(AGENT_PLUGINS_SPEC,),
        help="Check conformance to a published plugin format instead, such as the Agent Plugins spec.",
    )
    convert = add("convert", "Write a ready-to-load copy of the plugin for one runtime or format.")
    convert.add_argument(
        "--to",
        required=True,
        metavar="RUNTIME",
        help="Runtime or format to convert to, such as agent-plugins, codex or gemini-cli.",
    )
    convert.add_argument("--out", help="Output folder (default: hol.json's out, else dist/hol-plugin).")
    convert.add_argument("--force", action="store_true", help="Replace the files a previous convert wrote.")
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
    links = add("links", "Print install commands for each runtime and where to list the plugin.")
    links.add_argument(
        "--block",
        action="store_true",
        help="Print only the README install block: hol-guard plugin install plus each runtime's commands.",
    )
    links.add_argument("--slug", help="HOL listing the block names (default: the GitHub repository).")
    card = add(
        "card",
        "Print a draft .well-known card for the plugin: what it declares, where it is listed.",
    )
    card.add_argument("--slug", help="HOL listing the card links to (default: the GitHub repository).")
    for name, help_text in (
        ("install", "Install a HOL listing with each runtime's own CLI. Prints the plan unless --apply."),
        ("uninstall", "Remove a listing that plugin install added. Prints the plan unless --apply."),
    ):
        command = commands.add_parser(name, help=help_text, description=help_text)
        command.add_argument(
            "target",
            help="HOL listing, such as owner/plugin"
            + (" (optionally @version)." if name == "install" else ", as plugin install recorded it."),
        )
        mode = command.add_mutually_exclusive_group()
        mode.add_argument("--apply", action="store_true", help="Run the commands, confirming each runtime.")
        mode.add_argument("--dry-run", action="store_true", help="Only print the plan (the default).")
        command.add_argument("--yes", action="store_true", help="With --apply, skip the confirmations (for CI).")
        command.add_argument(
            "--runtime",
            dest="runtimes",
            type=_runtime_list,
            help="Comma-separated runtimes: claude-code, codex, agent-skills (default: every one offered).",
        )
        if name == "install":
            command.add_argument("--spec-file", help="Read the install spec from a file instead of HOL (offline, CI).")
        command.add_argument("--json", action="store_true", help="Print the plan as JSON.")
    stats = commands.add_parser(
        "stats",
        help="Print a listing you own's views and attested installs from HOL (needs HOL_API_KEY).",
        description=(
            "Print a listing you own's views for the last 28 days and last week's attested installs. "
            "Reads a stats key from HOL_API_KEY; create one in the HOL plugin workspace."
        ),
    )
    stats.add_argument("slug", help="HOL listing you own, such as owner/plugin.")
    stats.add_argument("--json", action="store_true", help="Print HOL's answer as JSON.")
    return parser


def _request(args: argparse.Namespace) -> dict[str, object]:
    request: dict[str, object] = {"command": args.command, "root": str(Path(args.path).resolve())}
    if args.command == "check" and args.spec:
        request["command"] = "conformance"
        request["spec"] = args.spec
    if args.command == "init" and args.name:
        request["name"] = args.name
    if args.command == "links" and args.block:
        request["block"] = True
        if args.slug:
            request["slug"] = args.slug
    if args.command == "card" and args.slug:
        request["slug"] = args.slug
    if args.command in {"check", "package"}:
        request["strict"] = bool(args.strict)
    if args.command == "package":
        if args.out:
            request["out_dir"] = str(Path(args.out).resolve())
        if args.runtimes:
            request["runtimes"] = args.runtimes
        request["force"] = bool(args.force)
    return request


def _convert(args: argparse.Namespace) -> int:
    """``package`` for one runtime; an Agent Plugins result is then checked against the spec."""

    request: dict[str, object] = {
        "command": "package",
        "root": str(Path(args.path).resolve()),
        "runtimes": [args.to],
        "force": bool(args.force),
    }
    if args.out:
        request["out_dir"] = str(Path(args.out).resolve())
    result = _call(request)
    if result is None:
        return 2
    output = Path(str(result.get("out_dir") or "")) / args.to
    conformance = None
    if result.get("packaged") and args.to == "agent-plugins":
        conformance = _call({"command": "conformance", "root": str(output), "spec": AGENT_PLUGINS_SPEC})
        if conformance is None:
            return 2
    if args.json:
        print(json.dumps({"package": result, "conformance": conformance}, indent=2, sort_keys=True))
    elif not result.get("packaged"):
        write_check(result.get("check") or {})
        print("\nNothing was written. Fix the errors above and run convert again.")
    else:
        print(f"Converted into {output}")
        dropped = next(
            (
                runtime.get("dropped") or []
                for runtime in result.get("runtimes") or []
                if runtime.get("runtime") == args.to
            ),
            [],
        )
        if dropped:
            print(f"  Left out: {', '.join(dropped)}")
        if conformance is not None:
            print()
            write_conformance(conformance)
    if not result.get("packaged") or (conformance is not None and not conformance.get("passed")):
        return 1
    return 0


def _write_block(result: Mapping[str, Any]) -> int:
    block = result.get("block")
    if not isinstance(block, str):
        print(
            "No install block: HOL Guard installs from a Claude Code or Codex marketplace entry in a GitHub "
            "repository. Run `hol-guard plugin links` for the next steps.",
            file=sys.stderr,
        )
        return 1
    print(block)
    return 0


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


def _install(args: argparse.Namespace) -> int:
    from ..config import resolve_guard_home
    from . import install

    installing = args.command == "install"
    guard_home = resolve_guard_home()
    try:
        slug, version = install.parse_target(args.target)
        if not installing and version:
            raise install.PluginInstallError("Name the listing without a version, such as owner/plugin.")
        spec: dict[str, Any] | None = None
        if installing:
            spec = install.read_spec_file(args.spec_file) if args.spec_file else install.fetch_spec(slug)
    except install.PluginInstallError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2
    available = install.available_programs()
    runtimes = args.runtimes or []
    # Uninstall plans from Guard's own record, so it only removes what
    # install added and still works once a listing leaves HOL.
    request: dict[str, object] = (
        {"command": "install", "spec": spec, "slug": slug, "version": version}
        if installing
        else {"command": "uninstall", "guard_home": str(guard_home), "slug": slug}
    )
    plan = _call({**request, "available": available, "runtimes": runtimes})
    if plan is None:
        return 2
    if args.json:
        print(json.dumps(plan, indent=2, sort_keys=True))
    else:
        install.write_plan(plan, apply=args.apply)
    if not args.apply:
        return 0
    # Refuse before anything runs when the install record cannot be read,
    # rather than installing and then failing to record it.
    if _call({"command": "installs", "guard_home": str(guard_home)}) is None:
        return 2

    def record(runtime: str) -> None:
        install.record(guard_home, slug, runtime, installed=installing, spec=spec)

    try:
        return install.apply_plan(plan, assume_yes=args.yes, record=record)
    except install.PluginInstallError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2


def _stats(args: argparse.Namespace) -> int:
    from . import stats

    try:
        result = stats.fetch_stats(args.slug, stats.read_key())
    except stats.PluginStatsError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print("\n".join(stats.render_stats(result)))
    return 0


def main(argv: Sequence[str] | None = None, *, program_name: str = "hol-guard plugin") -> int:
    args = build_parser(program_name=program_name).parse_args(argv)
    if args.command in {"install", "uninstall"}:
        return _install(args)
    if args.command == "convert":
        return _convert(args)
    if args.command == "stats":
        return _stats(args)
    result = _call(_request(args))
    if result is None:
        return 2
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    elif args.command == "card":
        # The card is the output, so stdout stays pure JSON for redirection.
        print(json.dumps(result, indent=2, sort_keys=True))
        print(
            "Publish it at .well-known/hol-plugin-card.json. The HOL listing serves it "
            "with the verified owner and release attestations added.",
            file=sys.stderr,
        )
    elif args.command == "check" and args.spec:
        write_conformance(result)
    elif args.command == "check":
        write_check(result)
    elif args.command == "links" and args.block:
        return _write_block(result)
    elif args.command == "links":
        write_links(result)
    elif args.command == "init":
        for path in result.get("written") or []:
            print(f"wrote {path}")
        if result.get("scaffolded"):
            print("\nNext: edit the description and skill, then run `hol-guard plugin check`.")
    elif args.command == "package":
        if not result.get("packaged"):
            write_check(result.get("check") or {})
            print("\nNothing was written. Fix the errors above and run package again.")
        else:
            print(f"Packaged {len(result.get('files') or [])} files into {result.get('out_dir')}")
            for runtime in result.get("runtimes") or []:
                if runtime.get("supported"):
                    print(f"  {runtime.get('runtime')}/")
    if not args.json and (
        (args.command == "check" and not args.spec and result.get("passed"))
        or (args.command == "package" and result.get("packaged"))
    ):
        _offer_guard_once()
    if args.command == "check" and not result.get("passed"):
        return 1
    if args.command == "package" and not result.get("packaged"):
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

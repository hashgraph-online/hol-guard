"""CLI for the HOL Guard Plugin Kit: ``hol-guard plugin <command>``.

Detection, checks, packaging and file writes run in the native runtime's
``plugin-kit`` command. This module parses arguments, sends one request and
renders the result.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shlex
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, TextIO

from ...version import __version__
from .output import write_check, write_conformance, write_links

PLUGIN_KIT_COMMAND = "plugin-kit"
PLUGIN_KIT_FEATURE = "plugin-kit-v1"
AGENT_PLUGINS_SPEC = "agent-plugins-1.0"
_TIMEOUT_SECONDS = 120.0
_OUTPUT_LIMIT_BYTES = 16 * 1024 * 1024
_REINSTALL = "pipx install --force hol-guard (or uv tool install --force hol-guard)"
# These three stable wheels are attached to the GitHub release and are not uploaded to PyPI.
_RELEASE_INSTALL = "hol-guard update"
_GITHUB_ONLY_PLATFORMS = {
    ("Darwin", "x86_64"),
    ("Linux", "aarch64"),
    ("Windows", "ARM64"),
}
# A native build exists for each of these. PyPI carries the rest.
_NATIVE_PLATFORMS = _GITHUB_ONLY_PLATFORMS | {
    ("Darwin", "arm64"),
    ("Linux", "x86_64"),
    ("Windows", "AMD64"),
}
_SYSTEM_NAMES = {"Darwin": "macOS"}
_NATIVE_FAILED = "The HOL Guard Plugin Kit did not complete."
INSTALL_DOCUMENT = "hol-guard.plugin-install/1"
VERIFY_DOCUMENT = "hol-guard.plugin-verify/1"

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
    "plugin_kit_output_unsafe": (
        "Choose another output folder. It can't be the plugin folder, a folder that holds it, your home folder or /."
    ),
    "plugin_kit_output_not_generated": (
        "The output folder has a file Guard did not write where it would write one."
        " Nothing was changed. Move that file or choose an empty folder."
    ),
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
    "plugin_kit_install_spec_unsupported": "This listing needs a newer hol-guard. Run: hol-guard update",
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
    "plugin_kit_install_endpoint_invalid": (
        "HOL_GUARD_PLUGIN_SPEC_URL must be an https URL, or http on localhost or host.docker.internal, "
        "with no credentials, query or fragment."
    ),
    "plugin_kit_install_recorded_elsewhere": (
        "Guard recorded this listing through a different install-spec URL. Set HOL_GUARD_PLUGIN_SPEC_URL "
        "as it was when you installed it, or unset it if you installed from hol.org."
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
    """The native runtime was unavailable, returned no usable response, or
    refused the request; ``code`` is the Kit's error code when it refused."""

    def __init__(self, message: str, code: str | None = None) -> None:
        super().__init__(message)
        self.code = code


def _native_install_command(system: str, machine: str) -> str:
    if (system, machine) in _GITHUB_ONLY_PLATFORMS:
        return _RELEASE_INSTALL
    return _REINSTALL


def native_unavailable_message(
    *,
    outdated: bool = False,
    incompatible: bool = False,
    version: str | None = None,
    system: str | None = None,
    machine: str | None = None,
) -> str:
    """Why the Plugin Kit cannot run here, and the one command that fixes it."""

    version = version or __version__
    system = system or platform.system()
    machine = machine or platform.machine()
    where = f"{_SYSTEM_NAMES.get(system, system)} {machine}"
    if outdated:
        return (
            "This HOL Guard's native runtime is too old for the Plugin Kit. "
            f"Update it: {_native_install_command(system, machine)}"
        )
    if incompatible:
        return (
            f"HOL Guard found a native runtime for {where}, but it does not match this install. "
            f"Update it: {_native_install_command(system, machine)}"
        )
    if (system, machine) not in _NATIVE_PLATFORMS:
        return (
            f"The Plugin Kit needs HOL Guard's native runtime, which is not built for {where}. "
            "It is built for macOS, Linux and Windows on x86_64 and arm64."
        )
    if re.search(r"(a|b|rc|dev)\d*$", version):
        return (
            f"HOL Guard {version} is a pre-release, and pre-releases on PyPI do not include the native "
            f"runtime the Plugin Kit needs. Install the latest release: {_native_install_command(system, machine)}"
        )
    if (system, machine) in _GITHUB_ONLY_PLATFORMS:
        return (
            f"The Plugin Kit needs HOL Guard's native runtime, and this install has none for {where}. "
            f"PyPI does not publish that build. Install it from the release: {_RELEASE_INSTALL}"
        )
    return (
        f"The Plugin Kit needs HOL Guard's native runtime, and this install has none for {where}. "
        f"Reinstall to get it: {_REINSTALL}"
    )


def _native_request(request: Mapping[str, object]) -> dict[str, Any]:
    """Run one ``plugin-kit`` request and return its ``{ok, result|error}`` reply."""

    from ..codex_hook_launch_runtime import run_isolated_hook_process
    from ..native_runtime import native_runtime_status

    status = native_runtime_status()
    if not status.available or status.identity is None:
        raise PluginKitNativeError(native_unavailable_message())
    if not status.compatible or status.capabilities is None:
        raise PluginKitNativeError(native_unavailable_message(incompatible=True))
    if PLUGIN_KIT_FEATURE not in status.capabilities.features:
        raise PluginKitNativeError(native_unavailable_message(outdated=True))
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
        raise PluginKitNativeError(_ERRORS.get(code, code or _NATIVE_FAILED), code or None)
    result = response.get("result")
    return result if isinstance(result, dict) else {}


def _call(request: Mapping[str, object]) -> dict[str, Any] | None:
    """Return the native result, or print the error and return None."""

    try:
        return kit_request(request)
    except PluginKitNativeError as error:
        print(f"Error: {error}", file=sys.stderr)
        return None


def _sha256(value: str) -> str:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise argparse.ArgumentTypeError("use the 64-character lowercase sha256 Guard printed")
    return value


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
        command = commands.add_parser(
            name,
            help=help_text,
            description=help_text.replace(" Prints", "\nPrints"),
            epilog=(
                "examples:\n"
                + (
                    f"  {program_name} install acme/toolgate                  show the plan\n"
                    f"  {program_name} install acme/toolgate --apply          install, asking first\n"
                    f"  {program_name} install acme/toolgate --apply --runtime codex\n"
                    if name == "install"
                    else f"  {program_name} uninstall acme/toolgate                show the plan\n"
                    f"  {program_name} uninstall acme/toolgate --apply        remove it\n"
                )
                + "\n"
                "exit codes:\n"
                "  0    done, or plan shown\n"
                "  1    a runtime command or check failed\n"
                "  2    usage, or no terminal to confirm in\n"
                "  3    nothing Guard can install here\n"
                "  4    stopped by HOL's scan result, a commit other than the scanned one,\n"
                "       or a declared command not accepted\n"
                "  5    this Guard is too old\n"
                "  6    HOL unreachable\n"
                "  130  interrupted\n"
                "\n"
                "To test against your own portal, set HOL_GUARD_PLUGIN_SPEC_URL to its\n"
                "install-spec URL (https, or http on localhost). Guard warns on every run\n"
                "while it is set."
            ),
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        command.add_argument(
            "target",
            help="HOL listing, such as owner/plugin"
            + (" (optionally @version)." if name == "install" else ", as plugin install recorded it."),
        )
        mode = command.add_mutually_exclusive_group()
        mode.add_argument("--apply", action="store_true", help="Run the commands, confirming each runtime.")
        mode.add_argument("--dry-run", action="store_true", help="Only print the plan (the default).")
        command.add_argument(
            "--yes",
            action="store_true",
            help="With --apply, skip the confirmations (for CI). Never accepts a risk or a declared command.",
        )
        if name == "install":
            command.add_argument(
                "--accept-risk",
                action="store_true",
                help="Install even though HOL's scan result asks for your OK (unscanned, warnings, an old scan).",
            )
            command.add_argument(
                "--accept-command",
                type=_sha256,
                metavar="SHA256",
                help="Let Claude Code run the install command the plugin declares, if its sha256 matches.",
            )
        command.add_argument(
            "--runtime",
            dest="runtimes",
            type=_runtime_list,
            help="Comma-separated runtimes: claude-code, codex, agent-skills (default: every one offered).",
        )
        if name == "install":
            command.add_argument("--spec-file", help="Read the install spec from a file instead of HOL (offline, CI).")
        command.add_argument(
            "--json",
            action="store_true",
            help=f"Print one {INSTALL_DOCUMENT} document on stdout; everything else goes to stderr.",
        )
    parser.set_defaults(program_name=program_name)
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
    verify = commands.add_parser(
        "verify",
        help="Check the commit Claude Code installed for a listing against HOL's integrity record. Warns only.",
        description=(
            "Check the commit Claude Code installed for a HOL listing against the commit HOL recorded for that "
            "version. A difference is a warning: Guard changes nothing and exits 0."
        ),
        epilog=(
            "exit codes:\n"
            "  0    checked (a difference is printed as a warning)\n"
            "  2    usage, or a record Guard could not read\n"
            "  3    not installed in Claude Code, or not listed on HOL\n"
            "  6    HOL unreachable"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    verify.add_argument("slug", help="HOL listing, such as owner/plugin.")
    verify.add_argument("--json", action="store_true", help=f"Print one {VERIFY_DOCUMENT} document on stdout.")
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


#: Exit code for each Kit error ``plugin install|uninstall`` can get back.
_INSTALL_EXITS = {
    "plugin_kit_install_spec_unsupported": 5,
    "plugin_kit_install_spec_invalid": 4,
    "plugin_kit_install_spec_mismatch": 4,
    "plugin_kit_install_version_unavailable": 2,
    "plugin_kit_install_runtime_unknown": 2,
    "plugin_kit_install_runtime_not_offered": 2,
    "plugin_kit_install_not_recorded": 2,
    "plugin_kit_install_recorded_elsewhere": 2,
    "plugin_kit_install_endpoint_invalid": 2,
    "plugin_kit_request_invalid": 2,
}
_NO_TERMINAL = "No terminal to confirm in. Run it in a terminal, or add --yes to install without prompts."


class _InstallStopError(Exception):
    def __init__(self, exit_code: int, code: str, message: str) -> None:
        super().__init__(message)
        self.exit_code = exit_code
        self.code = code


def _kit(request: Mapping[str, object]) -> dict[str, Any]:
    try:
        return kit_request(request)
    except PluginKitNativeError as error:
        raise _InstallStopError(
            _INSTALL_EXITS.get(error.code or "", 1), error.code or "native_unavailable", str(error)
        ) from error


def _install(args: argparse.Namespace) -> int:
    document: dict[str, Any] = {
        "schema": INSTALL_DOCUMENT,
        "action": args.command,
        "apply": bool(args.apply),
        "plan": None,
        "runtimes": [],
        "error": None,
    }
    try:
        exit_code = _install_flow(args, document)
    except _InstallStopError as stop:
        print(f"Error: {stop}", file=sys.stderr)
        document["error"] = {"code": stop.code, "message": str(stop)}
        exit_code = stop.exit_code
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        document["error"] = {"code": "interrupted", "message": "Interrupted."}
        exit_code = 130
    document["exit_code"] = exit_code
    if args.json:
        print(json.dumps(document, indent=2, sort_keys=True))
    return exit_code


def _progress_stream(args: argparse.Namespace) -> TextIO | None:
    """stderr when a person is watching it; never with --json (REM D15)."""

    if args.json:
        return None
    from .runner import stream_is_terminal

    return sys.stderr if stream_is_terminal(sys.stderr) else None


def _stdout_is_terminal() -> bool:
    from .runner import stream_is_terminal

    return stream_is_terminal(sys.stdout)


def _first_install_tip(args: argparse.Namespace, slug: str, installed: list[str], guard_home: Path) -> str:
    """One tip after the first install (REM D13): protect a runtime Guard does
    not cover yet, else how to remove the plugin. Nothing is set up here."""

    from . import install

    protected = install.protected_runtimes(guard_home)
    unprotected = [runtime for runtime in installed if protected is not None and runtime not in protected]
    if unprotected:
        names = " and ".join(install.runtime_label(runtime) for runtime in unprotected)
        return (
            f"Guard does not check what runs in {names} yet. To turn that on: hol-guard install {' '.join(unprotected)}"
        )
    return f"{args.program_name} uninstall {slug} shows how to remove it again. Nothing changes until you add --apply."


def _install_flow(args: argparse.Namespace, document: dict[str, Any]) -> int:
    from ..config import resolve_guard_home
    from . import install

    installing = args.command == "install"
    guard_home = resolve_guard_home()
    try:
        slug, version = install.parse_target(args.target)
        if not installing and version:
            raise install.PluginInstallError("Name the listing without a version, such as owner/plugin.")
        endpoint, listing_origin = install.spec_endpoint()
        if listing_origin:
            print(
                f"Warning: {install.SPEC_URL_ENV} is set. Install details come from {endpoint}, not hol.org.",
                file=sys.stderr,
            )
        spec: dict[str, Any] | None = None
        if installing:
            spec = (
                install.read_spec_file(args.spec_file)
                if args.spec_file
                else install.fetch_spec(slug, endpoint, progress=_progress_stream(args))
            )
            install.check_guard_version(spec)
    except install.PluginInstallError as error:
        raise _InstallStopError(error.exit_code, error.code, str(error)) from error
    lookup = install.find_programs()
    for line in lookup.ignored:
        print(f"Warning: {line}", file=sys.stderr)
    # Uninstall plans from Guard's own record, so it only removes what
    # install added and still works once a listing leaves HOL.
    request: dict[str, object] = (
        {"command": "install", "spec": spec, "slug": slug, "version": version}
        if installing
        else {"command": "uninstall", "guard_home": str(guard_home), "slug": slug}
    )
    if listing_origin:
        request["listing_origin"] = listing_origin
    plan = _kit({**request, "available": sorted(lookup.programs), "runtimes": args.runtimes or []})
    document["plan"] = plan
    outcomes = install.planned(plan, lookup)
    document["runtimes"] = [outcome.as_json() for outcome in outcomes]
    if not args.json:
        install.write_plan(plan, lookup, apply=args.apply, program_name=args.program_name)
    gate = (plan.get("security") or {}).get("gate")
    if gate == "block":
        for outcome in outcomes:
            if outcome.status == "planned":
                outcome.status = "blocked"
        document["runtimes"] = [outcome.as_json() for outcome in outcomes]
        raise _InstallStopError(4, "blocked", "HOL's scan result stops this install, so nothing ran.")
    steps = plan.get("steps") or []
    if not any(step.get("automatic") for step in steps):
        raise _InstallStopError(3, "nothing_to_install", "Guard cannot install this listing for any runtime it runs.")
    if not args.apply:
        return 0
    if not any(outcome.status == "planned" for outcome in outcomes):
        raise _InstallStopError(
            3, "nothing_to_install", "None of the runtimes Guard installs for (Claude Code, Codex) is on this machine."
        )
    interactive = install.runner.stdin_is_terminal()
    if not args.yes and not interactive:
        raise _InstallStopError(2, "no_terminal", _NO_TERMINAL)
    if gate == "confirm" and not getattr(args, "accept_risk", False):
        if getattr(args, "json", False):
            for reason in (plan.get("security") or {}).get("reasons") or []:
                print(f"  {reason}", file=sys.stderr)
        if getattr(args, "yes", False):
            raise _InstallStopError(
                4,
                "risk_not_accepted",
                "HOL's scan result needs your OK before Guard installs this. "
                "To install anyway, add --accept-risk with --yes.",
            )
        if not install.confirm("Install anyway?"):
            raise _InstallStopError(4, "risk_declined", "Not installed.")
    # Refuse before anything runs when the install record cannot be read,
    # rather than installing and then failing to record it. An install moves
    # a record that no longer parses aside and starts a new one; uninstall
    # needs the record, so it stops instead.
    installs = _kit({"command": "installs", "guard_home": str(guard_home), "recover": installing})
    if installs.get("recovered"):
        print(
            f"Guard's install record could not be read. It was moved to plugin-kit/{installs['recovered']} "
            "and a new one started.",
            file=sys.stderr,
        )
    first_install = installing and not installs.get("installs")

    def record(runtime: str, marketplace_added: bool) -> None:
        install.record(
            guard_home,
            slug,
            runtime,
            installed=installing,
            spec=spec,
            listing_origin=listing_origin,
            marketplace_added=marketplace_added,
        )

    def progress(done: Sequence[install.Outcome]) -> None:
        document["runtimes"] = [outcome.as_json() for outcome in [*done, *outcomes[len(done) :]]]

    try:
        outcomes = install.apply_plan(
            plan,
            lookup=lookup,
            assume_yes=args.yes,
            record=record,
            accept_command=getattr(args, "accept_command", None),
            json_output=args.json,
            progress=progress,
        )
    except install.PluginInstallError as error:
        raise _InstallStopError(error.exit_code, error.code, str(error)) from error
    document["runtimes"] = [outcome.as_json() for outcome in outcomes]
    failed = [outcome.runtime for outcome in outcomes if outcome.status == "failed"]
    if failed:
        retry = [*args.program_name.split(), args.command, args.target, "--apply", "--runtime", ",".join(failed)]
        # Keep the choices this run was given, so the retry stops where it did not.
        if getattr(args, "spec_file", None):
            retry += ["--spec-file", args.spec_file]
        if getattr(args, "accept_command", None):
            retry += ["--accept-command", args.accept_command]
        if getattr(args, "accept_risk", False):
            retry.append("--accept-risk")
        if getattr(args, "yes", False):
            retry.append("--yes")
        if getattr(args, "json", False):
            retry.append("--json")
        document["retry"] = retry
        print(f"Retry {', '.join(failed)} with: {shlex.join(retry)}", file=sys.stderr)
    installed = [outcome.runtime for outcome in outcomes if outcome.status == "installed"]
    if first_install and installed and not args.json and _stdout_is_terminal():
        print(f"\nTip: {_first_install_tip(args, slug, installed, guard_home)}")
    return install.exit_code_for(outcomes)


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


def _verify(args: argparse.Namespace) -> int:
    from . import install, verify

    document: dict[str, Any] = {"schema": VERIFY_DOCUMENT, "slug": args.slug, "runtime": "claude-code"}
    try:
        slug, version = install.parse_target(args.slug)
        if version:
            raise install.PluginInstallError("Name the listing without a version, such as owner/plugin.")
        endpoint, listing_origin = install.spec_endpoint()
        if listing_origin:
            print(f"Warning: {install.SPEC_URL_ENV} is set. HOL answers come from {endpoint}.", file=sys.stderr)
        spec = verify.fetch_listing_spec(
            slug, endpoint, overridden=bool(listing_origin), progress=_progress_stream(args)
        )
        plugin_id = verify.claude_plugin_id(spec)
        installed = verify.claude_installed(install.claude_home(), plugin_id) if plugin_id else None
        if installed is None:
            raise install.PluginInstallError(
                f"Claude Code has no install of {slug} for your user, so there is nothing to check.",
                exit_code=install.EXIT_NOTHING,
                code="not_installed",
            )
        ledger = verify.fetch_ledger(slug, verify.ledger_endpoint(endpoint), spec_slug=spec.get("slug"))
        result = verify.compare(installed, ledger)
    except install.PluginInstallError as error:
        print(f"Error: {error}", file=sys.stderr)
        document["error"] = {"code": error.code, "message": str(error)}
        if args.json:
            print(json.dumps(document, indent=2, sort_keys=True))
        return error.exit_code
    document.update({"installed": installed, **result, "error": None})
    if args.json:
        print(json.dumps(document, indent=2, sort_keys=True))
    else:
        # A differing commit goes to stderr whole, so its notes and releases
        # link stay with the warning when stdout is piped away.
        stream = sys.stderr if result["status"] == "differs" else sys.stdout
        for line in verify.render(slug, installed, result, verify.listing_releases_url(spec)):
            print(line, file=stream)
    return 0


def main(argv: Sequence[str] | None = None, *, program_name: str = "hol-guard plugin") -> int:
    args = build_parser(program_name=program_name).parse_args(argv)
    if args.command in {"install", "uninstall"}:
        return _install(args)
    if args.command == "convert":
        return _convert(args)
    if args.command == "stats":
        return _stats(args)
    if args.command == "verify":
        return _verify(args)
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

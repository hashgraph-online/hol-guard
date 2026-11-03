"""Parser for Cloud actions: a Guard Cloud workspace's connected accounts and AI tools.

This family is separate from the local commands. `connect`, `apps`, `install`
and `--workspace` keep their meanings: pairing this device, protecting local
apps, and naming a local project folder. Here three contexts never share a
flag:

- the Guard Cloud workspace, named only by `--cloud-workspace <id>`; it
  defaults to the one this computer is connected to with `hol-guard connect`;
- a provider, named by its slug, and a connected account in it, named by its id;
- a local folder, which is never accepted where a Cloud workspace is expected.
"""

from __future__ import annotations

import argparse
import re
import uuid
from collections.abc import Callable, Sequence

from ...argparse_utils import FriendlyArgumentParser

_SLUG = re.compile(r"[a-z][a-z0-9-]{0,62}")
_LOCAL_WORKSPACE_MESSAGE = (
    "--workspace names a local project folder and does not choose a Guard Cloud workspace. Use --cloud-workspace <id>."
)


def _looks_like_folder(value: str) -> bool:
    return value in {".", ".."} or value.startswith(("~", ".", "/")) or "/" in value or "\\" in value


def _uuid_text(value: str) -> str | None:
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        return None
    return str(parsed) if str(parsed) == value.lower() else None


def cloud_workspace_id(value: str) -> str:
    """Accept a Guard Cloud workspace id; refuse a folder with a specific message."""

    if _looks_like_folder(value):
        raise argparse.ArgumentTypeError(
            f"{value!r} looks like a folder. --cloud-workspace takes a Guard Cloud workspace ID."
        )
    parsed = _uuid_text(value)
    if parsed is None:
        raise argparse.ArgumentTypeError(f"{value!r} is not a Guard Cloud workspace ID.")
    return parsed


def connected_account_id(value: str) -> str:
    parsed = _uuid_text(value)
    if parsed is None:
        raise argparse.ArgumentTypeError(f"{value!r} is not a connected account ID.")
    return parsed


def _slug(kind: str) -> Callable[[str], str]:
    def parse(value: str) -> str:
        if _SLUG.fullmatch(value) is None:
            raise argparse.ArgumentTypeError(f"{value!r} is not a {kind} name.")
        return value

    parse.__name__ = kind.replace(" ", "_")
    return parse


class _RejectLocalWorkspace(argparse.Action):
    """Refuse `--workspace` here instead of letting it read as a Cloud workspace."""

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: str | Sequence[object] | None,
        option_string: str | None = None,
    ) -> None:
        del namespace, values, option_string
        parser.error(_LOCAL_WORKSPACE_MESSAGE)


def _add_parser(
    subparsers: argparse._SubParsersAction[FriendlyArgumentParser],
    name: str,
    help_text: str,
) -> FriendlyArgumentParser:
    parser = subparsers.add_parser(name, help=help_text, description=help_text, allow_abbrev=False)
    parser.add_argument("--workspace", nargs="?", action=_RejectLocalWorkspace, help=argparse.SUPPRESS)
    return parser


def _add_cloud_workspace(parser: argparse.ArgumentParser, *, required: bool, help_suffix: str | None = None) -> None:
    help_text = "Guard Cloud workspace ID (not a local folder)"
    if help_suffix is not None:
        help_text += help_suffix
    elif not required:
        help_text += "; defaults to the one this computer is connected to"
    parser.add_argument(
        "--cloud-workspace",
        dest="cloud_workspace",
        type=cloud_workspace_id,
        required=required,
        metavar="ID",
        help=help_text,
    )


def _add_json(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--json", action="store_true", help="Emit the versioned JSON contract")


def _add_guard_home(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--guard-home", help=argparse.SUPPRESS)


def _add_removed(
    subparsers: argparse._SubParsersAction[FriendlyArgumentParser], name: str, *options: str
) -> FriendlyArgumentParser:
    """Alpha-only commands, hidden from help; they accept their old options and point to `hol-guard connect`."""

    parser = subparsers.add_parser(name, allow_abbrev=False)
    parser.add_argument("removed_args", nargs="*", help=argparse.SUPPRESS)
    for option in options:
        parser.add_argument(option, dest=f"removed_{option.lstrip('-').replace('-', '_')}", help=argparse.SUPPRESS)
    parser.add_argument("--no-browser", action="store_true", help=argparse.SUPPRESS)
    _add_guard_home(parser)
    _add_json(parser)
    return parser


def configure_guard_cloud_actions_parser(
    guard_subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    # Not listed in `hol-guard --help` until these commands can act.
    family = guard_subparsers.add_parser(
        "cloud-actions",
        description=(
            "Let approved AI tools take actions in connected accounts of a Guard Cloud workspace. "
            "Separate from `connect`, `apps` and `install`, which manage protection on this device."
        ),
        allow_abbrev=False,
    )
    family.add_argument("--workspace", nargs="?", action=_RejectLocalWorkspace, help=argparse.SUPPRESS)
    commands = family.add_subparsers(
        dest="cloud_actions_command",
        required=True,
        parser_class=FriendlyArgumentParser,
        metavar="{status,doctor,accounts,ai-tools}",
    )

    # Alpha builds signed in separately; `hol-guard connect` now covers Cloud actions.
    _add_removed(commands, "login", "--cloud-url", "--cloud-workspace", "--timeout", "--profile", "--workspace")
    _add_removed(commands, "logout", "--profile")
    _add_removed(commands, "workspace", "--profile")

    status = _add_parser(commands, "status", "Show this computer's Cloud actions, workspace and connected accounts")
    _add_cloud_workspace(status, required=False)
    status.add_argument(
        "--offline", action="store_true", help="Show only what is saved on this computer; do not ask Guard Cloud"
    )
    _add_guard_home(status)
    _add_json(status)

    doctor = _add_parser(commands, "doctor", "Check this computer's Cloud actions, Guard Cloud and AI tool settings")
    doctor.add_argument(
        "--bundle",
        metavar="FILE",
        help="Also save the results to a new file to share with support; it never holds any access",
    )
    doctor.add_argument("--home", help=argparse.SUPPRESS)
    _add_guard_home(doctor)
    _add_json(doctor)

    accounts = _add_parser(commands, "accounts", "List, connect or disconnect connected accounts")
    account_commands = accounts.add_subparsers(
        dest="cloud_actions_accounts_command",
        required=True,
        parser_class=FriendlyArgumentParser,
    )
    listing = _add_parser(account_commands, "list", "List the workspace's connected accounts")
    _add_cloud_workspace(listing, required=False)
    _add_json(listing)
    connect = _add_parser(
        account_commands, "connect", "Open Guard Cloud to sign in with a provider and connect an account"
    )
    connect.add_argument("provider", type=_slug("provider"), metavar="PROVIDER")
    _add_cloud_workspace(connect, required=False)
    _add_guard_home(connect)
    connect.add_argument("--no-browser", action="store_true", help="Print the link instead of opening it")
    _add_json(connect)
    disconnect = _add_parser(account_commands, "disconnect", "Disconnect one connected account")
    disconnect.add_argument("connected_account", type=connected_account_id, metavar="CONNECTED_ACCOUNT_ID")
    _add_cloud_workspace(disconnect, required=True)
    _add_json(disconnect)

    ai_tools = _add_parser(commands, "ai-tools", "Configure or check an AI tool for Cloud actions")
    tool_commands = ai_tools.add_subparsers(
        dest="cloud_actions_ai_tools_command",
        required=True,
        parser_class=FriendlyArgumentParser,
    )
    configure = _add_parser(tool_commands, "configure", "Preview or apply an AI tool's Cloud actions settings")
    configure.add_argument("ai_tool", type=_slug("AI tool"), metavar="AI_TOOL")
    # Optional: the workspace is the one this computer is paired with; naming it only checks that.
    _add_cloud_workspace(
        configure,
        required=False,
        help_suffix="; optional, fails if this computer is paired with another workspace",
    )
    mode = configure.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true", help="Show the exact changes without writing them")
    mode.add_argument("--apply", action="store_true", help="Write the changes, keeping a backup")
    configure.add_argument("--home", help=argparse.SUPPRESS)
    configure.add_argument("--guard-home", help=argparse.SUPPRESS)
    _add_json(configure)
    restore = _add_parser(
        tool_commands,
        "restore",
        "Put back the AI tool's settings file from before Guard changed it and end its Cloud actions access",
    )
    restore.add_argument("ai_tool", type=_slug("AI tool"), metavar="AI_TOOL")
    restore.add_argument("--home", help=argparse.SUPPRESS)
    restore.add_argument("--guard-home", help=argparse.SUPPRESS)
    _add_json(restore)
    verify = _add_parser(tool_commands, "verify", "Check an AI tool's Cloud actions settings")
    verify.add_argument("ai_tool", type=_slug("AI tool"), metavar="AI_TOOL")
    _add_cloud_workspace(verify, required=False)
    _add_json(verify)

    # Launched by the AI tool from the entry `ai-tools configure` writes; not for people to run.
    bridge = commands.add_parser("bridge", allow_abbrev=False)
    bridge.add_argument("ai_tool", type=_slug("AI tool"), metavar="AI_TOOL")
    bridge.add_argument("--guard-home", help=argparse.SUPPRESS)


__all__ = [
    "cloud_workspace_id",
    "configure_guard_cloud_actions_parser",
    "connected_account_id",
]

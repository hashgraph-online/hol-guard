"""Parser for Cloud actions: a Guard Cloud workspace's connected accounts and AI tools.

This family is separate from the local commands. `connect`, `apps`, `install`
and `--workspace` keep their meanings: pairing this device, protecting local
apps, and naming a local project folder. Here three contexts never share a
flag:

- the Guard Cloud workspace, named only by `--cloud-workspace <id>` (or the
  positional id of `workspace select`);
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
_PROFILE = re.compile(r"[a-z0-9][a-z0-9-]{0,31}")
DEFAULT_CLOUD_ACTIONS_URL = "https://hol.org"
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


def profile_name(value: str) -> str:
    if _PROFILE.fullmatch(value) is None:
        raise argparse.ArgumentTypeError(
            f"{value!r} is not a profile name. Use lowercase letters, digits and dashes (up to 32)."
        )
    return value


def _sign_in_wait(value: str) -> int:
    try:
        seconds = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value!r} is not a number of seconds.") from None
    if not 30 <= seconds <= 1800:
        raise argparse.ArgumentTypeError("--timeout must be between 30 and 1800 seconds.")
    return seconds


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


def _add_cloud_workspace(parser: argparse.ArgumentParser, *, required: bool) -> None:
    help_text = "Guard Cloud workspace ID (not a local folder)"
    if not required:
        help_text += "; defaults to the one chosen with `workspace select`"
    parser.add_argument(
        "--cloud-workspace",
        dest="cloud_workspace",
        type=cloud_workspace_id,
        required=required,
        metavar="ID",
        help=help_text,
    )


def _add_cloud_url(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--cloud-url",
        default=DEFAULT_CLOUD_ACTIONS_URL,
        metavar="URL",
        help=f"Guard Cloud address (default: {DEFAULT_CLOUD_ACTIONS_URL})",
    )


def _add_json(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--json", action="store_true", help="Emit the versioned JSON contract")


def _add_profile(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--profile",
        type=profile_name,
        default="default",
        help="Saved sign-in to use; each profile holds one Guard Cloud workspace (default: default)",
    )
    parser.add_argument("--guard-home", help=argparse.SUPPRESS)


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
        metavar="{login,logout,status,workspace,accounts,ai-tools}",
    )

    login = _add_parser(commands, "login", "Sign in to Guard Cloud for Cloud actions in one workspace")
    _add_cloud_url(login)
    _add_cloud_workspace(login, required=False)
    login.add_argument("--no-browser", action="store_true", help="Print the sign-in link instead of opening it")
    login.add_argument(
        "--timeout",
        type=_sign_in_wait,
        default=300,
        metavar="SECONDS",
        help="How long to wait for the browser sign-in (default: 300)",
    )
    _add_profile(login)
    _add_json(login)

    logout = _add_parser(commands, "logout", "Sign out of Cloud actions and remove the saved sign-in")
    _add_profile(logout)
    _add_json(logout)

    status = _add_parser(commands, "status", "Show Cloud actions sign-in, workspace and connected accounts")
    _add_cloud_workspace(status, required=False)
    _add_profile(status)
    _add_json(status)

    workspace = _add_parser(commands, "workspace", "Choose the Guard Cloud workspace these commands use")
    workspace_commands = workspace.add_subparsers(
        dest="cloud_actions_workspace_command",
        required=True,
        parser_class=FriendlyArgumentParser,
    )
    select = _add_parser(workspace_commands, "select", "Use one Guard Cloud workspace by default")
    select.add_argument("cloud_workspace", type=cloud_workspace_id, metavar="CLOUD_WORKSPACE_ID")
    _add_profile(select)
    _add_json(select)

    accounts = _add_parser(commands, "accounts", "List, connect or disconnect connected accounts")
    account_commands = accounts.add_subparsers(
        dest="cloud_actions_accounts_command",
        required=True,
        parser_class=FriendlyArgumentParser,
    )
    listing = _add_parser(account_commands, "list", "List the workspace's connected accounts")
    _add_cloud_workspace(listing, required=False)
    _add_json(listing)
    connect = _add_parser(account_commands, "connect", "Start provider sign-in for a new connected account")
    connect.add_argument("provider", type=_slug("provider"), metavar="PROVIDER")
    _add_cloud_workspace(connect, required=True)
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
    _add_cloud_workspace(configure, required=True)
    mode = configure.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true", help="Show the exact changes without writing them")
    mode.add_argument("--apply", action="store_true", help="Write the changes, keeping a backup")
    _add_cloud_url(configure)
    configure.add_argument("--home", help=argparse.SUPPRESS)
    _add_json(configure)
    verify = _add_parser(tool_commands, "verify", "Check an AI tool's Cloud actions settings")
    verify.add_argument("ai_tool", type=_slug("AI tool"), metavar="AI_TOOL")
    _add_cloud_workspace(verify, required=False)
    _add_json(verify)


__all__ = [
    "DEFAULT_CLOUD_ACTIONS_URL",
    "cloud_workspace_id",
    "configure_guard_cloud_actions_parser",
    "connected_account_id",
    "profile_name",
]

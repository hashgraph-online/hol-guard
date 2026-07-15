"""Guard CLI parser construction helpers."""

# fmt: off
# ruff: noqa: I001

from __future__ import annotations



import argparse

from ...argparse_utils import FriendlyArgumentParser
from ._commands_shared import _GUARD_HELP_GROUPS
from .commands_parser_cloud import _configure_guard_cloud_parsers
from .commands_parser_helpers import (
    _add_aibom_cli_args,
    _add_guard_cisco_mode_arg,
    _add_guard_common_args,
    _aibom_cli_options_from_args,
    _guard_http_url,
)
from .commands_parser_local import _configure_guard_local_parsers
from .commands_parser_mdm import _configure_guard_mdm_parsers
from .commands_parser_policy import _configure_guard_policy_parsers


def add_guard_parser(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser]
    | argparse._SubParsersAction[FriendlyArgumentParser],
) -> None:
    guard_parser = subparsers.add_parser(
        "guard",
        help="Guard commands",
        description=_GUARD_HELP_GROUPS,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _configure_guard_parser(guard_parser)


def add_guard_root_parser(parser: argparse.ArgumentParser) -> None:
    parser.description = _GUARD_HELP_GROUPS
    if parser.formatter_class is argparse.HelpFormatter:
        parser.formatter_class = argparse.RawDescriptionHelpFormatter
    _configure_guard_parser(parser)


def _configure_guard_parser(guard_parser: argparse.ArgumentParser) -> None:
    "Attach Guard subcommands to a parser."
    guard_subparsers: argparse._SubParsersAction[argparse.ArgumentParser] = guard_parser.add_subparsers(
        dest="guard_command",
        required=True,
        parser_class=FriendlyArgumentParser,
        metavar=(
            "{start,status,dashboard,init,apps,bootstrap,detect,install,update,uninstall,package-shims,run,protect,preflight,scan,diff,"
            "test-eval,command,mdm,"
            "receipts,inventory,abom,aibom,approvals,explain,allow,deny,policies,trust,exceptions,advisories,events,doctor,connect,"
            "remote-pair,disconnect,"
            "login,sync,device,commands,bridge,mcp}"
        ),
    )
    _configure_guard_local_parsers(guard_subparsers)
    _configure_guard_mdm_parsers(guard_subparsers)
    _configure_guard_policy_parsers(guard_subparsers)
    _configure_guard_cloud_parsers(guard_subparsers)

__all__ = [
    "_add_aibom_cli_args",
    "_add_guard_cisco_mode_arg",
    "_add_guard_common_args",
    "_aibom_cli_options_from_args",
    "_configure_guard_parser",
    "_guard_http_url",
    "add_guard_parser",
    "add_guard_root_parser",
]

"""Parser for the local exact Cloud Review consent boundary."""

from __future__ import annotations

import argparse

from ...argparse_utils import FriendlyArgumentParser
from .commands_parser_helpers import _add_guard_common_args


def configure_guard_cloud_review_parser(
    guard_subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    parser = guard_subparsers.add_parser(
        "cloud-review",
        help="Manage signed exact-request Cloud Review consent on this device",
    )
    _add_guard_common_args(parser)
    subparsers = parser.add_subparsers(
        dest="cloud_review_command",
        required=True,
        parser_class=FriendlyArgumentParser,
    )
    status = subparsers.add_parser("status", help="Show exact Cloud Review consent status")
    _add_guard_common_args(status)
    status.add_argument("--json", action="store_true")

    enable = subparsers.add_parser(
        "enable",
        help="Allow signed Guard Cloud decisions for one exact pending request",
    )
    _add_guard_common_args(enable)
    enable.add_argument(
        "--expires-in-days",
        type=int,
        default=30,
        help="Consent lifetime from 1 through 365 days (default: 30)",
    )
    enable.add_argument("--json", action="store_true")

    disable = subparsers.add_parser("disable", help="Revoke exact Cloud Review consent on this device")
    _add_guard_common_args(disable)
    disable.add_argument(
        "--confirm",
        required=True,
        choices=("disable",),
        help="Confirm exact Cloud Review consent revocation",
    )
    disable.add_argument("--json", action="store_true")

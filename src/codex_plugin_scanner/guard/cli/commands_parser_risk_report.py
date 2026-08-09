"""Parser for the privacy-safe local risk report command."""

from __future__ import annotations

import argparse

from .commands_parser_helpers import _add_guard_common_args


def configure_guard_risk_report_parser(
    guard_subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    parser = guard_subparsers.add_parser(
        "risk-report",
        help="Create a privacy-safe local Guard posture report",
    )
    _add_guard_common_args(parser)
    parser.add_argument("--format", choices=("json", "html"), default="json")
    parser.add_argument(
        "--output",
        help="Write the sanitized report to this local file instead of stdout",
    )


__all__ = ["configure_guard_risk_report_parser"]

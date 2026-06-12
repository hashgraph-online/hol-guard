"""Guard CLI parser shared helper functions."""

# fmt: off
# ruff: noqa: F403, F405, I001

from __future__ import annotations

from ._commands_shared import *

def _add_guard_common_args(
    parser: argparse.ArgumentParser,
    *,
    suppress_defaults: bool = False,
) -> None:
    default = argparse.SUPPRESS if suppress_defaults else None
    parser.add_argument("--home", default=default)
    parser.add_argument("--guard-home", default=default)
    parser.add_argument("--workspace", default=default)


def _add_aibom_cli_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--include-symlinks",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Include symlink source-of-truth metadata in AIBOM output (default: enabled).",
    )
    parser.add_argument(
        "--follow-unsafe-symlinks",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Follow symlink targets outside safe roots (default: disabled).",
    )


def _aibom_cli_options_from_args(args: argparse.Namespace) -> AibomCliOptions:
    return AibomCliOptions(
        include_symlinks=bool(getattr(args, "include_symlinks", True)),
        follow_unsafe_symlinks=bool(getattr(args, "follow_unsafe_symlinks", False)),
    )


def _add_guard_cisco_mode_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--cisco-mode",
        choices=("auto", "on", "off"),
        default="auto",
        help="Control optional Cisco scanner evidence for local consumer-mode artifact scans.",
    )
def _guard_http_url(value: str) -> str:
    parsed = urllib.parse.urlparse(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise argparse.ArgumentTypeError("Guard URLs must be absolute http(s) URLs.")
    return value

__all__ = [
    "_add_aibom_cli_args",
    "_add_guard_cisco_mode_arg",
    "_add_guard_common_args",
    "_aibom_cli_options_from_args",
    "_guard_http_url",
]

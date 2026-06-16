"""Guard CLI entrypoints."""

from __future__ import annotations

import argparse
import importlib
from typing import TextIO

from ...argparse_utils import FriendlyArgumentParser

__all__ = ["add_guard_parser", "add_guard_root_parser", "run_guard_command"]


def _commands_module():
    return importlib.import_module(".commands", __package__)


def add_guard_parser(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser]
    | argparse._SubParsersAction[FriendlyArgumentParser],
) -> None:
    _commands_module().add_guard_parser(subparsers)


def add_guard_root_parser(parser: argparse.ArgumentParser) -> None:
    _commands_module().add_guard_root_parser(parser)


def run_guard_command(
    args: argparse.Namespace,
    *,
    input_text: str | None = None,
    output_stream: TextIO | None = None,
) -> int:
    return _commands_module().run_guard_command(args, input_text=input_text, output_stream=output_stream)

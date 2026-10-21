"""Direct native calls for the data-flow projections Python no longer owns.

Rust owns input-redirect, pipe and segment extraction. These helpers call the
resident shell-helper transport straight through so the tests below keep
exercising that request path without a Python runtime module in the middle.
"""

from __future__ import annotations

from dataclasses import dataclass

from codex_plugin_scanner.guard.native_shell_helpers import call


@dataclass(frozen=True, slots=True)
class NativeShellPipe:
    left: str
    right: str


def native_input_redirects(command: str) -> tuple[str, ...]:
    return tuple(call("redirects", command))


def native_pipes(command: str) -> tuple[NativeShellPipe, ...]:
    return tuple(NativeShellPipe(**row) for row in call("pipes", command))


def native_command_segments(command: str) -> tuple[str, ...]:
    return tuple(call("segments", command))


def native_pipe_segments(command: str) -> tuple[str, ...]:
    return tuple(call("pipe_segments", command))


__all__ = [
    "NativeShellPipe",
    "native_command_segments",
    "native_input_redirects",
    "native_pipe_segments",
    "native_pipes",
]

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import windows_processes


@pytest.mark.parametrize("pid", [0, -1, -2, -10, -100, -1_000, -10_000, -65_536])
def test_windows_process_command_line_rejects_invalid_pid(pid: int) -> None:
    assert windows_processes.windows_process_command_line(pid) is None


@pytest.mark.parametrize(
    "overrides",
    [
        {"max_processes": 0},
        {"max_processes": -1},
        {"max_processes": 65_537},
        {"max_command_line_bytes": 0},
        {"max_command_line_bytes": -1},
        {"max_command_line_bytes": 1_048_577},
    ],
)
def test_windows_process_inventory_rejects_invalid_limits(
    overrides: dict[str, int],
) -> None:
    assert (
        windows_processes.windows_process_command_line_inventory(
            candidate_executable_names=frozenset({"python.exe"}),
            **overrides,
        )
        is None
    )


def test_windows_process_inventory_accepts_empty_candidate_set() -> None:
    assert (
        windows_processes.windows_process_command_line_inventory(
            candidate_executable_names=frozenset(),
        )
        == []
    )


def test_native_windows_process_inventory_availability_matches_host() -> None:
    assert windows_processes.native_windows_process_inventory_available() is (os.name == "nt")


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows process APIs")
def test_native_windows_process_inventory_finds_current_python() -> None:
    command_line = windows_processes.windows_process_command_line(os.getpid())
    assert command_line
    executable_name = Path(sys.executable).name.lower()
    inventory = windows_processes.windows_process_command_line_inventory(
        candidate_executable_names=frozenset({executable_name}),
    )
    assert inventory is not None
    assert any(pid == os.getpid() and command == command_line for pid, command in inventory)

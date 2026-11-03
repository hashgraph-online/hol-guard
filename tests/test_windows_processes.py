from __future__ import annotations

import os
import sys
from pathlib import Path
from types import SimpleNamespace

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


def _fake_runtime(
    monkeypatch: pytest.MonkeyPatch,
    answer: dict[str, object] | None,
) -> list[dict[str, object]]:
    requests: list[dict[str, object]] = []

    def runtime_answer(request: dict[str, object], *, output_limit: int) -> dict[str, object] | None:
        assert output_limit > 0
        requests.append(request)
        return answer

    monkeypatch.setattr(windows_processes, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(windows_processes, "_runtime_answer", runtime_answer)
    return requests


def test_command_line_asks_the_runtime_for_one_process(monkeypatch: pytest.MonkeyPatch) -> None:
    requests = _fake_runtime(monkeypatch, {"command_lines": ["python.exe -m guard"]})

    assert windows_processes.windows_process_command_line(42, max_command_line_bytes=512) == "python.exe -m guard"
    assert requests == [{"op": "read", "pids": [42], "max_command_line_bytes": 512}]


@pytest.mark.parametrize(
    "answer",
    [None, {}, {"command_lines": []}, {"command_lines": [None]}, {"command_lines": [""]}, {"command_lines": [7]}],
)
def test_command_line_reads_an_unusable_answer_as_unknown(
    monkeypatch: pytest.MonkeyPatch,
    answer: dict[str, object] | None,
) -> None:
    _ = _fake_runtime(monkeypatch, answer)

    assert windows_processes.windows_process_command_line(42) is None


def test_inventory_asks_the_runtime_for_candidate_images(monkeypatch: pytest.MonkeyPatch) -> None:
    requests = _fake_runtime(monkeypatch, {"entries": [[10, "python.exe -m guard"], [30, "hol-guard.exe daemon"]]})

    assert windows_processes.windows_process_command_line_inventory(
        candidate_executable_names=frozenset({"python.exe", "hol-guard.exe", " "}),
        max_processes=100,
        max_command_line_bytes=4096,
    ) == [(10, "python.exe -m guard"), (30, "hol-guard.exe daemon")]
    assert requests == [
        {
            "op": "inventory",
            "candidate_executable_names": ["hol-guard.exe", "python.exe"],
            "max_processes": 100,
            "max_command_line_bytes": 4096,
        }
    ]


@pytest.mark.parametrize(
    "answer",
    [
        None,
        {"entries": None},
        {"entries": [[10]]},
        {"entries": [[0, "python.exe"]]},
        {"entries": [[True, "python.exe"]]},
        {"entries": [[10, ""]]},
        {"entries": [["10", "python.exe"]]},
    ],
)
def test_inventory_reads_an_unusable_answer_as_unknown(
    monkeypatch: pytest.MonkeyPatch,
    answer: dict[str, object] | None,
) -> None:
    _ = _fake_runtime(monkeypatch, answer)

    assert (
        windows_processes.windows_process_command_line_inventory(
            candidate_executable_names=frozenset({"python.exe"}),
        )
        is None
    )

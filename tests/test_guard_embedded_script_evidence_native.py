"""Native embedded-script evidence replays the vectors recorded from the Python owner."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_shell_helpers import _valid
from codex_plugin_scanner.guard.runtime.embedded_script_evidence import embedded_script_evidence_entries

_VECTORS = json.loads(
    (
        Path(__file__).resolve().parents[1] / "rust/crates/guard-command/testdata/embedded_script_evidence/vectors.json"
    ).read_text(encoding="utf-8")
)


@pytest.mark.parametrize("vector", _VECTORS, ids=[vector["name"] for vector in _VECTORS])
def test_native_embedded_script_evidence_matches_recorded_vector(vector: dict[str, object]) -> None:
    assert embedded_script_evidence_entries(vector["command"]) == vector["entries"]


def test_non_string_command_has_no_evidence() -> None:
    assert embedded_script_evidence_entries(None) == []


def test_recorded_entries_pass_reply_validation() -> None:
    for vector in _VECTORS:
        assert _valid("embedded_script_evidence", vector["entries"])


def _first_heredoc() -> dict[str, object]:
    return copy.deepcopy(
        next(entry for vector in _VECTORS for entry in vector["entries"] if entry["kind"] == "heredoc")
    )


@pytest.mark.parametrize(
    "mutate",
    [
        lambda e: e.pop("span"),
        lambda e: e.update(span={"start": 5, "end": 1}),
        lambda e: e.update(span={"start": -1, "end": 1}),
        lambda e: e.update(sha256="zz"),
        lambda e: e.update(executed=True, execution_status="indeterminate"),
        lambda e: e.update(bytes="3"),
        lambda e: e.update(extra=1),
        lambda e: e.update(source="other"),
    ],
)
def test_malformed_entries_fail_reply_validation(mutate) -> None:
    entry = _first_heredoc()
    mutate(entry)
    assert not _valid("embedded_script_evidence", [entry])

"""Update reports every harness repair failure, not only Codex ones."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel

from codex_plugin_scanner.guard.cli.update_repair_notes import (
    attach_repair_notes,
    render_protection_repair_failures,
)


def test_failures_from_any_harness_are_listed_and_kept_in_notes():
    payload: dict[str, object] = {"notes": ["Updated hol-guard."]}
    cursor = "Could not refresh Cursor protection during update: hooks.json is not valid JSON."
    pi = "Could not refresh Oh My Pi protection during update: extension directory is read-only."
    info = "OpenCode plugin already current."

    attach_repair_notes(payload, [cursor, info, pi])

    assert payload["notes"] == ["Updated hol-guard.", cursor, info, pi]
    assert payload["protection_repair_failures"] == [cursor, pi]


def test_informational_notes_are_not_failures():
    payload: dict[str, object] = {}

    attach_repair_notes(payload, ["OpenCode plugin already current."])

    assert "protection_repair_failures" not in payload


def test_failures_render_in_a_separate_panel():
    console = Console(record=True, width=200)
    failure = "Could not refresh Grok protection during update: settings are locked."

    render_protection_repair_failures(console, {"protection_repair_failures": [failure]}, "-", Panel)
    render_protection_repair_failures(console, {}, "-", Panel)

    text = console.export_text()
    assert "Protection not restored" in text
    assert text.count(failure) == 1

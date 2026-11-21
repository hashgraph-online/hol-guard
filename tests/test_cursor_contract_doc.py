"""The hand-written Cursor surface table must agree with the published claims.

`docs/guard/cursor-local-cloud-contract.md` explains each Cursor surface in its
own words. The claim rows in `docs/guard/generated/harness-claims.v1.json` are
generated from the protection contract. A surface the contract lists as
unsupported must not read as intercepted in the explanation.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "guard" / "cursor-local-cloud-contract.md"
CLAIMS = ROOT / "docs" / "guard" / "generated" / "harness-claims.v1.json"

# Doc row label -> contract surface.
LABELS = {
    "Editor (IDE)": "editor",
    "CLI": "cli",
    "Cloud agent": "cloud-agent",
    "Built-in terminal": "terminal",
}
HOOK_EVENT = re.compile(r"\b(?:before|after)[A-Z]\w+|\bpreToolUse\b|\bpostToolUse\b")


def _surface_table() -> dict[str, str]:
    """Doc surface -> its "What is intercepted" cell."""
    section = DOC.read_text(encoding="utf-8").split("## Surfaces", 1)[1].split("\n## ", 1)[0]
    cells: dict[str, str] = {}
    for line in section.splitlines():
        parts = [part.strip() for part in line.strip().strip("|").split("|")]
        if len(parts) == 3:
            label = parts[0].strip("*")
            if label in LABELS:
                cells[LABELS[label]] = parts[2]
    return cells


def _cursor_claims() -> list[dict[str, object]]:
    published = json.loads(CLAIMS.read_text(encoding="utf-8"))
    return [row for row in published["claims"] if row["harness"] == "cursor"]


def test_every_cursor_surface_in_the_contract_is_explained() -> None:
    surfaces = {str(row["surface"]) for row in _cursor_claims()}
    assert surfaces == set(_surface_table())


def test_an_unsupported_surface_names_no_intercepted_hook_event() -> None:
    claims = _cursor_claims()
    cells = _surface_table()
    for surface, cell in cells.items():
        rows = [row for row in claims if row["surface"] == surface]
        if all(row["state"] == "unsupported" for row in rows):
            assert not HOOK_EVENT.search(cell), f"{surface} is unsupported but its cell names a hook event: {cell}"


def test_an_unsupported_surface_reads_as_not_covered_unless_it_only_launches() -> None:
    cells = _surface_table()
    assert cells["cloud-agent"].startswith("Not covered")
    assert cells["terminal"].startswith("Not covered")
    # The CLI row claims only the launch check, never actions inside a session.
    assert "Launches" in cells["cli"]

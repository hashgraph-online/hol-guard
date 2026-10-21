#!/usr/bin/env python3
r"""Record the inventory fingerprint corpus the native seam is checked against.

`inventory_contract_fingerprints` hashes deterministic JSON, and the native
mirror has to reproduce the same bytes or every snapshot identity drifts. Three
details of `json.dumps(..., ensure_ascii=True)` are not what a Rust encoder does
by default, so each one gets its own section here:

* `ensure_ascii=True` escapes DEL and everything above it, including astral
  characters as surrogate pairs. `serde_json` emits those characters raw.
* `repr(float)` switches to exponent notation outside `1e-4 .. 1e16` and keeps a
  trailing `.0` otherwise. Rust's `{}` never uses an exponent.
* `str.strip()` and `re.compile(r"\s+")` both use `Py_UNICODE_ISSPACE`, which
  covers U+001C..U+001F. Rust's `char::is_whitespace` does not.

Writing the corpus from a script instead of by hand keeps those choices tied to
the interpreter that defines them, so regenerating after a change to either side
is one command.

Usage: python scripts/ci/generate_inventory_fingerprint_parity.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "src"))

from codex_plugin_scanner.guard.inventory_agent_types import agent_type  # noqa: E402
from codex_plugin_scanner.guard.inventory_contract_fingerprints import (  # noqa: E402
    _inventory_snapshot_content_hash,
    _stable_snapshot_value,
    fingerprint_mapping,
    fingerprint_text,
    inventory_item_id,
)
from codex_plugin_scanner.guard.inventory_contract_models import (  # noqa: E402
    GuardAgentInventoryFinding,
    GuardAgentInventoryItem,
    GuardInventorySource,
)

OUTPUT = REPO_ROOT / "rust/crates/guard-command/testdata/inventory_fingerprint_parity.json"

# Floats whose `repr` exercises both sides of the exponent-notation thresholds.
FLOATS: tuple[float, ...] = (
    0.0,
    -0.0,
    1.0,
    -1.0,
    0.5,
    1.5,
    100.0,
    0.0001,
    0.00001,
    1e-7,
    1e15,
    1e16,
    1e17,
    -1e16,
    1.7976931348623157e308,
    5e-324,
    0.1,
    1 / 3,
    123456789.123456789,
    2.5e-10,
)

# Values whose compact encoding depends on escaping, key order or number format.
COMPACT_VALUES: tuple[object, ...] = (
    None,
    True,
    False,
    0,
    -17,
    "",
    "plain",
    'quote" and \\ backslash',
    "tab\tnewline\nreturn\r",
    "bell\x07 del\x7f unit\x1f",
    "caf\u00e9",
    "\u2028 line separator",
    "astral \U0001f600",
    [],
    {},
    [1, "two", None],
    {"b": 1, "a": 2, "A": 3, "\u00e1": 4},
    {"nested": {"z": [1, {"y": 2}], "a": None}},
    {"score": 100, "ratio": 0.25},
)

# Strings that separate `str.isspace()` from Rust's `char::is_whitespace`.
SEMANTIC_TEXTS: tuple[str, ...] = (
    "",
    "plain text",
    "  leading and trailing  ",
    "collapse   inner    runs",
    "tabs\tand\nnewlines",
    "unit\x1fseparator",
    "\x1c\x1d\x1e\x1f",
    "nbsp\u00a0and\u2003em space",
    "ideographic\u3000space",
    "vertical\x0btab\x0cform feed",
    "caf\u00e9 \U0001f600",
)

AGENT_TYPE_INPUTS: tuple[str, ...] = (
    "codex",
    "claude-code",
    "cline",
    "hermes",
    "Codex",
    "claude_code",
    "",
    "unknown-harness",
    "CLAUDE-CODE",
    " codex ",
)

STABLE_VALUES: tuple[object, ...] = (
    None,
    7,
    "text",
    {"capturedAt": "now", "keep": 1},
    {"a": 1, "generatedAt": "x", "observedAt": "y", "scanDurationMs": 3},
    {"outer": {"lastSeenAt": "x", "inner": [3, 1, 2]}},
    [3, 1, 2],
    ["b", "a", "c"],
    [{"b": 1}, {"a": 2}],
    [[2], [1], []],
    [True, False, None, 1, "1"],
    {"attestation": 1, "attestationBindings": 2, "durationMs": 3, "duration_ms": 4, "elapsedMs": 5},
    {"evidenceHash": 1, "syncedAt": 2, "kept": {"capturedAt": 3, "also": 4}},
)


def _item(**overrides: object) -> GuardAgentInventoryItem:
    base: dict[str, object] = {
        "item_id": "codex:skill:abc",
        "item_kind": "skill",
        "display_name": "Skill",
        "description": "",
        "source_fingerprint": "fp",
        "content_hash": "ch",
        "capability_categories": ("reads_files",),
    }
    base.update(overrides)
    return GuardAgentInventoryItem(**base)  # type: ignore[arg-type]


def _finding(**overrides: object) -> GuardAgentInventoryFinding:
    base: dict[str, object] = {
        "finding_id": "f1",
        "source": "hol-detector",
        "severity": "low",
        "confidence": "high",
        "title": "Title",
        "artifact_id": "a1",
        "check_id": "c1",
    }
    base.update(overrides)
    return GuardAgentInventoryFinding(**base)  # type: ignore[arg-type]


def _source(**overrides: object) -> GuardInventorySource:
    base: dict[str, object] = {"source_id": "s1", "source_type": "config", "status": "available"}
    base.update(overrides)
    return GuardInventorySource(**base)  # type: ignore[arg-type]


SNAPSHOTS: tuple[dict[str, object], ...] = (
    {"agent_type": "codex", "runtime_version": None, "items": (), "findings": (), "sources": ()},
    {
        "agent_type": "claude-code",
        "runtime_version": "3.50.0",
        "items": (
            _item(item_id="b", item_kind="skill"),
            _item(item_id="a", item_kind="skill"),
            _item(item_id="z", item_kind="agent", security_score=42, risk_level="high"),
        ),
        "findings": (
            _finding(finding_id="f2", source="metadata"),
            _finding(finding_id="f1", source="metadata", summary="has summary"),
            # A scanner finding with no description carries "", not None.
            _finding(finding_id="f3", source="metadata", summary=""),
        ),
        "sources": (_source(source_id="s2"), _source(source_id="s1", detail="detail text")),
    },
    {
        "agent_type": "cursor",
        "runtime_version": "",
        "items": (
            _item(
                metadata={"observedAt": "drop me", "keep": [3, 1, 2], "caf\u00e9": "\U0001f600"},
                capability_categories=("runs_shell", "reads_files"),
                scanner_sources=("hol-detector",),
                drift_state="changed",
            ),
        ),
        "findings": (_finding(evidence={"generatedAt": "drop", "kept": 0.25}),),
        "sources": (_source(captured_at="2026-10-21T00:00:00Z", detail=None),),
    },
    {
        # `summary`/`detail`/`captured_at` are `str | None`, so an explicitly
        # empty one hashes differently from an absent one.
        "agent_type": "codex",
        "runtime_version": None,
        "items": (),
        "findings": (
            _finding(finding_id="empty", summary=""),
            _finding(finding_id="absent", summary=None),
        ),
        "sources": (
            _source(source_id="empty", captured_at="", detail=""),
            _source(source_id="absent"),
        ),
    },
)


def _item_json(item: GuardAgentInventoryItem) -> dict[str, object]:
    return {
        "item_id": item.item_id,
        "item_kind": item.item_kind,
        "display_name": item.display_name,
        "description": item.description,
        "source_fingerprint": item.source_fingerprint,
        "content_hash": item.content_hash,
        "capability_categories": list(item.capability_categories),
        "risk_level": item.risk_level,
        "security_score": item.security_score,
        "scanner_sources": list(item.scanner_sources),
        "drift_state": item.drift_state,
        "metadata": item.metadata,
    }


def _finding_json(finding: GuardAgentInventoryFinding) -> dict[str, object]:
    return {
        "finding_id": finding.finding_id,
        "source": finding.source,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "title": finding.title,
        "artifact_id": finding.artifact_id,
        "check_id": finding.check_id,
        "summary": finding.summary,
        "evidence": finding.evidence,
    }


def _source_json(source: GuardInventorySource) -> dict[str, object]:
    return {
        "source_id": source.source_id,
        "source_type": source.source_type,
        "status": source.status,
        "captured_at": source.captured_at,
        "detail": source.detail,
    }


def build_document() -> dict[str, object]:
    return {
        "float_repr": [{"value": value, "repr": repr(value)} for value in FLOATS],
        "compact_json": [
            {
                "value": value,
                "encoded": json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True),
                "digest": fingerprint_mapping(value),
            }
            for value in COMPACT_VALUES
        ],
        "fingerprint_text": [{"value": value, "digest": fingerprint_text(value)} for value in SEMANTIC_TEXTS],
        "inventory_item_id": [
            {
                "agent_type": "codex",
                "item_kind": "skill",
                "display_name": "  Mixed Case Name  ",
                "semantic_text": text,
                "item_id": inventory_item_id("codex", "skill", "  Mixed Case Name  ", text),
            }
            for text in SEMANTIC_TEXTS
        ],
        "agent_type": [{"value": value, "normalized": agent_type(value)} for value in AGENT_TYPE_INPUTS],
        "stable_snapshot_value": [{"value": value, "stable": _stable_snapshot_value(value)} for value in STABLE_VALUES],
        "snapshot_content_hash": [
            {
                "agent_type": snapshot["agent_type"],
                "runtime_version": snapshot["runtime_version"],
                "items": [_item_json(item) for item in snapshot["items"]],  # type: ignore[union-attr]
                "findings": [_finding_json(finding) for finding in snapshot["findings"]],  # type: ignore[union-attr]
                "sources": [_source_json(source) for source in snapshot["sources"]],  # type: ignore[union-attr]
                "digest": _inventory_snapshot_content_hash(**snapshot),  # type: ignore[arg-type]
            }
            for snapshot in SNAPSHOTS
        ],
    }


def main() -> int:
    OUTPUT.write_text(
        json.dumps(build_document(), indent=1, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"wrote {OUTPUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

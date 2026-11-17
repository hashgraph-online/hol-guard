"""The published harness claims are generated from the harness protection contract."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _generator():
    spec = importlib.util.spec_from_file_location(
        "generate_harness_claims", ROOT / "scripts" / "generate_harness_claims.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _contract(claim: dict[str, object]) -> dict[str, object]:
    return {
        "schema": "hol-guard.harness-protection-contracts.v1",
        "contracts": [
            {
                "harness": "codex",
                "capability_events": [
                    {
                        "event": "PreToolUse",
                        "transport": "native_hook",
                        "mode": "blocking",
                        "surface": "foreground",
                        "failure_behavior": "fail_closed",
                        "claim": claim,
                        "declared_actions": ["observe", "block"],
                        "known_blind_spots": [],
                    }
                ],
            }
        ],
    }


def test_the_published_files_are_current() -> None:
    assert _generator().main(["--check"]) == 0


def test_every_contract_row_is_published_once() -> None:
    generator = _generator()
    contract = json.loads(generator.CONTRACT.read_text(encoding="utf-8"))
    published = json.loads(generator.JSON_OUTPUT.read_text(encoding="utf-8"))
    declared = [
        (entry["harness"], event["event"], event["transport"], event["surface"])
        for entry in contract["contracts"]
        for event in entry["capability_events"]
    ]
    rows = [(row["harness"], row["event"], row["transport"], row["surface"]) for row in published["claims"]]
    assert rows == declared


def test_the_claude_prompt_event_is_published_with_its_failure_behavior() -> None:
    generator = _generator()
    published = json.loads(generator.JSON_OUTPUT.read_text(encoding="utf-8"))
    prompt = [
        row for row in published["claims"] if row["harness"] == "claude-code" and row["event"] == "UserPromptSubmit"
    ]
    assert [row["failure_behavior"] for row in prompt] == ["fail_open"]
    assert any(
        row["harness"] == "claude-code" and row["event"] == "UserPromptSubmit" for row in published["non_coverage"]
    )
    assert "| `UserPromptSubmit` | foreground | `native_hook` | `screening` | Lets the action continue |" in (
        generator.MARKDOWN_OUTPUT.read_text(encoding="utf-8")
    )


def test_expired_evidence_fails_the_release_check() -> None:
    generator = _generator()
    contract = _contract(
        {
            "state": "live_block_proven",
            "guard_version": "3.4.0",
            "harness_version": "0.130.0",
            "platform": "macos-arm64",
            "evidence_reference": "gauntlet-run-1",
            "observed_at": "2026-11-01T00:00:00Z",
            "expires_at": "2026-12-01T00:00:00Z",
        }
    )
    assert generator.expired(contract, "2026-11-30T23:59:59Z") == []
    assert generator.expired(contract, "2026-12-01T00:00:00Z") == [
        "codex PreToolUse (native_hook) expired 2026-12-01T00:00:00Z"
    ]
    assert generator.expired(_contract({"state": "configured"}), "2099-01-01T00:00:00Z") == []


def test_a_proof_claim_without_an_expiry_fails_the_release_check() -> None:
    generator = _generator()
    for claim in (
        {"state": "live_block_proven"},
        {"state": "partial", "expires_at": "next month"},
        {"state": "live_block_proven", "expires_at": "2026-11-31T00:00:00Z"},
        {"state": "partial", "expires_at": "2026-12-01T24:00:00Z"},
    ):
        assert generator.expired(_contract(claim), "2026-11-14T00:00:00Z") == [
            f"codex PreToolUse (native_hook) claims {claim['state']} without a valid expires_at"
        ]


def test_a_malformed_release_time_is_refused() -> None:
    assert _generator().main(["--check", "--as-of", "2026-11-14"]) == 2
    assert _generator().main(["--check", "--as-of", "2026-02-30T00:00:00Z"]) == 2


def test_codex_file_writes_are_published_as_their_own_rows() -> None:
    published = json.loads(_generator().JSON_OUTPUT.read_text(encoding="utf-8"))
    codex = [row for row in published["claims"] if row["harness"] == "codex" and row["event"] == "PreToolUse"]
    tools = [tool for row in codex for tool in row["tools"]]

    assert {"apply_patch", "Write", "Edit", "MultiEdit"} <= set(tools)
    assert len(tools) == len(set(tools))
    assert all(row["state"] == "configured" for row in codex)


def test_a_row_split_by_tool_names_its_tools_in_the_table_and_expiry_label() -> None:
    generator = _generator()
    contract = _contract({"state": "live_block_proven", "expires_at": "2026-01-01T00:00:00Z"})
    contract["contracts"][0]["capability_events"][0]["tools"] = ["apply_patch"]

    assert "| `PreToolUse`: `apply_patch` |" in generator.render_markdown(contract)
    assert generator.expired(contract, "2026-06-01T00:00:00Z") == [
        "codex PreToolUse [apply_patch] (native_hook) expired 2026-01-01T00:00:00Z"
    ]


def test_each_cursor_surface_has_its_own_row_and_only_the_editor_enforces() -> None:
    published = json.loads(_generator().JSON_OUTPUT.read_text(encoding="utf-8"))
    cursor = [row for row in published["claims"] if row["harness"] == "cursor"]
    surfaces = {row["surface"] for row in cursor}

    assert {"editor", "cli", "cloud-agent", "terminal"} <= surfaces
    for row in cursor:
        if row["surface"] != "editor":
            assert row["state"] == "unsupported"
            assert row["mode"] == "unsupported"
            assert row["known_blind_spots"]
    assert any(row["surface"] == "editor" and row["failure_behavior"] == "fail_closed" for row in cursor)

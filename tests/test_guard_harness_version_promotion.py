"""Promotion command for the bundled harness version coverage manifest."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.harness_versions import manifest as manifest_module
from codex_plugin_scanner.guard.harness_versions.manifest import (
    MAX_RECORDS_PER_HARNESS,
    ManifestError,
    bundled_manifest_path,
    parse_manifest,
)
from scripts.ci import promote_harness_version_coverage as promote_module
from scripts.ci.promote_harness_version_coverage import main, next_revision, promote, render

GUARD = "9.9.9"
EVIDENCE = "https://github.com/hashgraph-online/hol-guard/actions/runs/42"
NOW = "2026-10-20T08:00:00Z"
UNIT_EVENTS = ["PreToolUse"]
FULL_EVENTS = ["PostToolUse", "PreToolUse", "UserPromptSubmit"]


def _base() -> dict[str, object]:
    return json.loads(bundled_manifest_path().read_text(encoding="utf-8"))


def _promote(payload: dict[str, object], **overrides: object) -> dict[str, object]:
    arguments: dict[str, object] = {
        "harness": "omp",
        "harness_version": "18.20.0",
        "suite_id": "guard-gauntlet-full-task",
        "evidence_reference": EVIDENCE,
        "platforms": ["darwin-arm64"],
        "guard_version": GUARD,
        "observed_at": NOW,
    }
    arguments.update(overrides)
    return promote(payload, **arguments)  # type: ignore[arg-type]


def _records(payload: dict[str, object]) -> list[dict[str, object]]:
    return payload["harnesses"][0]["records"]  # type: ignore[index]


def test_bundled_manifest_is_byte_stable_under_render() -> None:
    raw = bundled_manifest_path().read_bytes()
    assert render(json.loads(raw)) == raw


def test_valid_live_block_promotion_round_trips_through_parse_manifest() -> None:
    promoted = _promote(_base())
    parsed = parse_manifest(json.loads(render(promoted)))
    record = parsed.harnesses["omp"].records[0]
    assert record.harness_version.canonical == "18.20.0"
    assert record.guard_version == GUARD
    assert record.evidence_level == "live_block"
    assert list(record.events) == FULL_EVENTS
    assert record.evidence_reference == EVIDENCE
    assert promoted["revision"] == "2026-10-20.1"


def test_unit_test_promotion_defaults_to_what_the_suite_exercises() -> None:
    promoted = _promote(_base(), suite_id="pi-exact-continuation")
    record = _records(promoted)[0]
    assert record["events"] == UNIT_EVENTS
    assert record["evidence_level"] == "unit_test"


def test_promotion_does_not_mutate_its_input() -> None:
    payload = _base()
    before = copy.deepcopy(payload)
    _promote(payload)
    assert payload == before


def test_repromoting_a_version_updates_it_in_place() -> None:
    first = _promote(_base(), suite_id="pi-exact-continuation")
    second = _promote(first, platforms=["linux-x86_64"], observed_at="2026-10-20T09:00:00Z")
    records = _records(second)
    assert len(records) == 1
    assert records[0]["suite"] == {"id": "guard-gauntlet-full-task", "result": "passed"}
    assert records[0]["platforms"] == ["linux-x86_64"]
    assert second["revision"] == "2026-10-20.2"


def test_repromoting_replaces_a_record_bound_to_an_older_guard_build() -> None:
    first = _promote(_base(), guard_version="9.9.8")
    second = _promote(first)
    assert [record["guard_version"] for record in _records(second)] == [GUARD]


def test_other_versions_are_kept_and_stale_ones_pruned_on_request() -> None:
    first = _promote(_base(), guard_version="9.9.8")
    kept = _promote(first, harness_version="18.21.0")
    assert {record["harness_version"] for record in _records(kept)} == {"18.20.0", "18.21.0"}
    pruned = _promote(first, harness_version="18.21.0", prune_stale=True)
    assert [record["harness_version"] for record in _records(pruned)] == ["18.21.0"]


def test_repromoting_replaces_a_prefixed_record_of_the_same_version() -> None:
    first = _promote(_base())
    _records(first)[0]["harness_version"] = "v18.20.0"
    parse_manifest(first)
    second = _promote(first)
    assert [record["harness_version"] for record in _records(second)] == ["18.20.0"]


def test_pruning_keeps_a_record_whose_guard_version_differs_only_by_prefix() -> None:
    first = _promote(_base(), guard_version=f"v{GUARD}")
    pruned = _promote(first, harness_version="18.21.0", prune_stale=True)
    assert {record["harness_version"] for record in _records(pruned)} == {"18.20.0", "18.21.0"}


def test_revision_restarts_on_a_new_day() -> None:
    assert next_revision("2026-10-16.4", "2026-10-20") == "2026-10-20.1"
    assert next_revision("2026-10-20.1", "2026-10-20") == "2026-10-20.2"
    assert next_revision("garbled", "2026-10-20") == "2026-10-20.1"


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"suite_id": "unit-tests"}, "not eligible"),
        ({"harness": "claude-code"}, "no 'claude-code' harness entry"),
        ({"harness_version": "^18.4.0"}, "exact version"),
        ({"harness_version": "18.4"}, "exact version"),
        ({"harness_version": "18.x"}, "exact version"),
        ({"events": ["PreToolUse", "NotAnEvent"]}, "events its suite does not exercise"),
        ({"suite_id": "pi-exact-continuation", "events": ["PostToolUse"]}, "events its suite does not exercise"),
        ({"evidence_level": "unit_test"}, "evidence_level must be live_block"),
        ({"suite_id": "pi-exact-continuation", "evidence_level": "live_block"}, "evidence_level must be unit_test"),
        ({"evidence_reference": "https://example.com/run/1"}, "evidence_reference"),
        ({"evidence_reference": EVIDENCE + " extra"}, "evidence_reference"),
        ({"guard_version": "not-a-version"}, "guard_version"),
        ({"platforms": ["plan9-mips"]}, "platforms"),
        ({"platforms": []}, "platforms"),
        ({"observed_at": "yesterday"}, "observed_at"),
        ({"observed_at": "2026-10-20T08:00:00"}, "timezone"),
    ],
)
def test_refuses_what_the_runtime_validator_would_reject(overrides: dict[str, object], message: str) -> None:
    with pytest.raises(ManifestError, match=message):
        _promote(_base(), **overrides)


def test_refuses_a_record_beyond_the_per_harness_limit() -> None:
    payload = _base()
    for index in range(MAX_RECORDS_PER_HARNESS):
        payload = _promote(payload, harness_version=f"1.{index}.0")
    assert len(_records(payload)) == MAX_RECORDS_PER_HARNESS
    with pytest.raises(ManifestError, match="bounded list"):
        _promote(payload, harness_version="2.0.0")


def test_refuses_a_manifest_over_the_size_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(promote_module, "MAX_MANIFEST_BYTES", 600)
    assert manifest_module.MAX_MANIFEST_BYTES > 600
    with pytest.raises(ManifestError, match="exceed"):
        _promote(_base())


def _command(path: Path, *extra: str) -> list[str]:
    return [
        "--manifest",
        str(path),
        "--harness",
        "omp",
        "--harness-version",
        "18.20.0",
        "--suite",
        "pi-exact-continuation",
        "--evidence-reference",
        EVIDENCE,
        "--platform",
        "darwin-arm64",
        "--observed-at",
        NOW,
        *extra,
    ]


def test_command_writes_a_record_bound_to_the_running_guard_version(tmp_path: Path) -> None:
    target = tmp_path / "manifest.json"
    target.write_bytes(bundled_manifest_path().read_bytes())
    assert main(_command(target)) == 0
    record = parse_manifest(json.loads(target.read_text(encoding="utf-8"))).harnesses["omp"].records[0]
    assert record.guard_version == promote_module.__version__
    assert record.suite_id == "pi-exact-continuation"


def test_command_leaves_the_manifest_untouched_when_it_refuses(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = tmp_path / "manifest.json"
    target.write_bytes(bundled_manifest_path().read_bytes())
    before = target.read_bytes()
    assert main(_command(target, "--evidence-level", "live_block")) == 1
    assert "refusing to promote" in capsys.readouterr().err
    assert target.read_bytes() == before


def test_command_refuses_an_unreadable_manifest(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(_command(tmp_path / "missing.json")) == 1
    assert "refusing to promote" in capsys.readouterr().err


def test_bundled_manifest_still_carries_no_records() -> None:
    # Promotion happens on the release PR; this change ships the mechanism only.
    assert _records(_base()) == []


def test_publish_workflow_enforces_release_binding_on_stable_builds_only() -> None:
    root = Path(__file__).resolve().parents[1]
    text = (root / ".github" / "workflows" / "publish.yml").read_text(encoding="utf-8")
    step = text.split("- name: Verify distributions", 1)[1].split("- name: Record immutable", 1)[0]
    assert "CHANNEL: ${{ steps.version.outputs.channel }}" in step
    assert 'if [[ "$CHANNEL" == "stable" ]]; then release_args+=(--release); fi' in step
    assert '"${release_args[@]}" --wheel "$wheel"' in step

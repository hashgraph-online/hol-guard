"""The review screen learns which extension governs which step of a paused command.

The allow hint only speaks when enabling a few permissions would let the *whole*
command run, so a command whose steps are governed by different extensions — or
whose other steps nothing can settle — reaches the review screen with nothing
pointing at Extensions. The coverage hint answers the weaker question instead:
which extension matched which step. It carries no decision, so these tests pin
its two promises — every observed step is named, and one step's permissions are
never presented as settling another's.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from codex_plugin_scanner.guard.daemon.approval_extension_coverage import (
    COVERAGE_SCHEMA,
    MAX_DELIVERED_SEGMENTS,
    build_approval_extension_coverage,
    with_approval_extension_coverage,
)
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_allow_hint import (
    EXTENSION_ALLOW_HINT_SCHEMA,
    validated_extension_allow_hint,
)
from codex_plugin_scanner.guard.runtime.extension_coverage_hint import (
    EXTENSION_COVERAGE_HINT_SCHEMA,
    MAX_COVERED_SEGMENTS,
    compute_extension_coverage_hint,
    validated_extension_coverage_hint,
    with_extension_coverage,
)
from tests.native_command_test_support import real_native_review_fixtures

DIGEST = "b" * 64
FETCH_RULE = "command.git.unverified-fetch"
RESET_RULE = "command.git.hard-reset"
RESET_PERMISSION = "command.git.permission.hard-reset"
PRUNE_PERMISSION = "command.container-runtime.permission.build-cache-prune"
_BOUND = object()


def _observation(
    extension_id: str,
    rule_id: str,
    *,
    segments: tuple[int, ...] = (),
    evidence: tuple[tuple[int, str], ...] = (),
) -> dict[str, Any]:
    return {
        "extension_id": extension_id,
        "rule_id": rule_id,
        "effective_segment_indexes": list(segments),
        "matcher_evidence": [
            {"segment_index": index, "executable": executable, "detail": "matched"} for index, executable in evidence
        ],
    }


def _evidence(
    observations: tuple[dict[str, Any], ...] = (),
    *,
    permission_observations: tuple[dict[str, Any], ...] = (),
    binding: dict[str, Any] | None | object = _BOUND,
    **extra: Any,
) -> dict[str, Any]:
    command_extensions: dict[str, Any] = {
        "observations": list(observations),
        "permission_observations": list(permission_observations),
        **extra,
    }
    bound = {"catalog_digest": DIGEST} if binding is _BOUND else binding
    if bound is not None:
        command_extensions["binding"] = bound
    return {"command_extensions": command_extensions}


def test_a_single_step_names_the_extension_that_matched_it() -> None:
    coverage = compute_extension_coverage_hint(
        _evidence((_observation("command.git", FETCH_RULE, segments=(0,), evidence=((0, "git"),)),))
    )

    assert coverage == {
        "schema": EXTENSION_COVERAGE_HINT_SCHEMA,
        "catalog_digest": DIGEST,
        "segments": [
            {
                "index": 0,
                "executable": "git",
                "extension_ids": ["command.git"],
                "rule_ids": [FETCH_RULE],
                "permission_ids": [],
            }
        ],
    }


def test_a_compound_command_keeps_every_step_apart() -> None:
    # `git fetch … && docker system prune`: two steps, two extensions, and
    # nothing that settles both. Each step has to carry only its own ids, or
    # the screen would imply that allowing one of them releases the command.
    coverage = compute_extension_coverage_hint(
        _evidence(
            (
                _observation("command.git", FETCH_RULE, segments=(0,), evidence=((0, "git"),)),
                _observation(
                    "command.container-runtime",
                    "command.container-runtime.system-prune",
                    segments=(2,),
                    evidence=((2, "docker"),),
                ),
            )
        )
    )

    assert coverage is not None
    segments = coverage["segments"]
    assert [segment["index"] for segment in segments] == [0, 2]
    assert segments[0]["extension_ids"] == ["command.git"]
    assert segments[0]["rule_ids"] == [FETCH_RULE]
    assert segments[1]["extension_ids"] == ["command.container-runtime"]
    assert segments[1]["rule_ids"] == ["command.container-runtime.system-prune"]
    assert segments[0]["executable"] == "git"
    assert segments[1]["executable"] == "docker"


def test_permission_evidence_alone_still_names_its_step() -> None:
    # Package review reports the step through matcher evidence rather than
    # effective segment indexes, and that step is just as real.
    coverage = compute_extension_coverage_hint(
        _evidence(
            permission_observations=(
                {
                    "extension_id": "command.git",
                    "permission_id": RESET_PERMISSION,
                    "matcher_evidence": [{"segment_index": 1, "executable": "git", "detail": "reset --hard"}],
                },
            )
        )
    )

    assert coverage is not None
    assert coverage["segments"] == [
        {
            "index": 1,
            "executable": "git",
            "extension_ids": ["command.git"],
            "rule_ids": [],
            "permission_ids": [RESET_PERMISSION],
        }
    ]


def test_a_command_no_extension_matched_gets_no_coverage() -> None:
    assert compute_extension_coverage_hint(_evidence()) is None
    assert compute_extension_coverage_hint({}) is None


def test_failed_or_unbound_evidence_gets_no_coverage() -> None:
    observations = (_observation("command.git", FETCH_RULE, segments=(0,)),)

    assert compute_extension_coverage_hint(_evidence(observations, evaluation_error="timeout")) is None
    assert compute_extension_coverage_hint(_evidence(observations, binding=None)) is None
    assert compute_extension_coverage_hint(_evidence(observations, binding={"catalog_digest": "not-a-digest"})) is None


def test_a_stored_hint_is_read_from_either_carrier() -> None:
    coverage = compute_extension_coverage_hint(_evidence((_observation("command.git", FETCH_RULE, segments=(0,)),)))
    assert coverage is not None

    assert validated_extension_coverage_hint(coverage) == coverage
    assert validated_extension_coverage_hint({"schema": EXTENSION_ALLOW_HINT_SCHEMA, "coverage": coverage}) == coverage
    assert validated_extension_coverage_hint({"schema": EXTENSION_ALLOW_HINT_SCHEMA}) is None
    assert validated_extension_coverage_hint(None) is None


def test_a_malformed_stored_hint_is_refused_whole() -> None:
    def hint(**overrides: Any) -> dict[str, Any]:
        segment = {
            "index": 0,
            "executable": "git",
            "extension_ids": ["command.git"],
            "rule_ids": [FETCH_RULE],
            "permission_ids": [],
        }
        return {
            "schema": EXTENSION_COVERAGE_HINT_SCHEMA,
            "catalog_digest": DIGEST,
            "segments": [{**segment, **overrides}],
        }

    assert validated_extension_coverage_hint(hint()) is not None
    assert validated_extension_coverage_hint(hint(extension_ids=["../../etc/passwd"])) is None
    assert validated_extension_coverage_hint(hint(extension_ids=[])) is None
    assert validated_extension_coverage_hint(hint(index=-1)) is None
    assert validated_extension_coverage_hint(hint(executable="git; rm -rf /")) is not None
    assert validated_extension_coverage_hint(hint(executable="git; rm -rf /"))["segments"][0]["executable"] is None
    duplicated = hint()
    duplicated["segments"] = [duplicated["segments"][0], dict(duplicated["segments"][0])]
    assert validated_extension_coverage_hint(duplicated) is None
    oversized = hint()
    oversized["segments"] = [{**oversized["segments"][0], "index": index} for index in range(MAX_COVERED_SEGMENTS + 1)]
    assert validated_extension_coverage_hint(oversized) is None


def test_coverage_rides_along_without_reaching_the_resident() -> None:
    # Coverage shares the stored hint column with the allow hint. The allow
    # hint's own validator rebuilds from the keys it knows, so the extra key
    # cannot leak into the question the resident is asked.
    allow_hint = {
        "schema": EXTENSION_ALLOW_HINT_SCHEMA,
        "permission_ids": [RESET_PERMISSION],
        "rule_ids": [RESET_RULE],
        "extension_ids": ["command.git"],
        "relied_permission_ids": [],
        "catalog_digest": DIGEST,
    }
    coverage = compute_extension_coverage_hint(_evidence((_observation("command.git", RESET_RULE, segments=(0,)),)))
    assert coverage is not None

    assert with_extension_coverage(None, coverage) == coverage
    assert with_extension_coverage(allow_hint, None) == allow_hint
    carried = with_extension_coverage(allow_hint, coverage)
    assert carried is not None
    assert carried["coverage"] == coverage
    assert validated_extension_allow_hint(carried) == validated_extension_allow_hint(allow_hint)
    assert "coverage" not in (validated_extension_allow_hint(carried) or {})


def _pending(hint: object) -> dict[str, Any]:
    return {"status": "pending", "extension_allow_hint": hint}


def test_delivery_labels_every_step_from_the_catalog() -> None:
    registry = BUILT_IN_COMMAND_EXTENSION_REGISTRY
    coverage = compute_extension_coverage_hint(
        _evidence(
            (_observation("command.git", RESET_RULE, segments=(0,), evidence=((0, "git"),)),),
            permission_observations=(
                {
                    "extension_id": "command.container-runtime",
                    "permission_id": PRUNE_PERMISSION,
                    "matcher_evidence": [{"segment_index": 1, "executable": "docker"}],
                },
            ),
        )
    )

    payload = build_approval_extension_coverage(_pending(coverage), registry=registry)

    assert payload is not None
    assert payload["schema"] == COVERAGE_SCHEMA
    assert payload["catalog_digest"] == registry.catalog_digest
    assert payload["compound"] is True
    first, second = payload["segments"]
    assert first["index"] == 0
    assert first["extensions"] == [
        {"extension_id": "command.git", "name": registry.get("command.git").name, "focus_rule_id": RESET_RULE}
    ]
    assert first["rules"] == [
        {
            "rule_id": RESET_RULE,
            "title": registry.get_rule(RESET_RULE).title,
            "severity": registry.get_rule(RESET_RULE).severity,
        }
    ]
    assert second["index"] == 1
    assert second["extensions"][0]["extension_id"] == "command.container-runtime"
    assert second["permissions"] == [
        {
            "permission_id": PRUNE_PERMISSION,
            "label": registry.permission(PRUNE_PERMISSION).label,
            "configurable": registry.permission(PRUNE_PERMISSION).configurable,
        }
    ]


def test_a_single_later_step_still_says_the_rest_comes_back() -> None:
    coverage = compute_extension_coverage_hint(_evidence((_observation("command.git", RESET_RULE, segments=(2,)),)))
    payload = build_approval_extension_coverage(_pending(coverage), registry=BUILT_IN_COMMAND_EXTENSION_REGISTRY)

    assert payload is not None
    assert payload["compound"] is True


def _modelled(evidence: dict[str, Any], steps: int) -> dict[str, Any]:
    """The evidence a review of a ``steps``-step command returns."""

    return {**evidence, "command_model": {"segments": [{"index": index} for index in range(steps)]}}


def test_the_step_count_the_review_measured_rides_along() -> None:
    coverage = compute_extension_coverage_hint(
        _modelled(_evidence((_observation("command.git", RESET_RULE, segments=(0,)),)), 3)
    )

    assert coverage is not None
    assert coverage["segment_total"] == 3
    # A hook edge that modelled only the text leaves the count out entirely.
    assert "segment_total" not in (
        compute_extension_coverage_hint(_evidence((_observation("command.git", RESET_RULE, segments=(0,)),))) or {}
    )


def test_a_step_count_that_cannot_hold_the_covered_steps_is_refused() -> None:
    hint: dict[str, Any] = {
        "schema": EXTENSION_COVERAGE_HINT_SCHEMA,
        "catalog_digest": DIGEST,
        "segments": [
            {
                "index": 2,
                "executable": "git",
                "extension_ids": ["command.git"],
                "rule_ids": [RESET_RULE],
                "permission_ids": [],
            }
        ],
    }

    assert validated_extension_coverage_hint({**hint, "segment_total": 3}) is not None
    assert validated_extension_coverage_hint({**hint, "segment_total": 2}) is None
    assert validated_extension_coverage_hint({**hint, "segment_total": 0}) is None
    assert validated_extension_coverage_hint({**hint, "segment_total": "3"}) is None


def test_a_covered_first_step_of_a_longer_command_still_says_the_rest_comes_back() -> None:
    # The hole the covered steps alone cannot see: step 1 matched, steps 2 and
    # 3 matched nothing, and the card would have read as covering the command.
    evidence = _evidence((_observation("command.git", RESET_RULE, segments=(0,)),))
    registry = BUILT_IN_COMMAND_EXTENSION_REGISTRY

    chained = build_approval_extension_coverage(
        _pending(compute_extension_coverage_hint(_modelled(evidence, 3))), registry=registry
    )
    alone = build_approval_extension_coverage(
        _pending(compute_extension_coverage_hint(_modelled(evidence, 1))), registry=registry
    )

    assert chained is not None and chained["compound"] is True
    assert alone is not None and alone["compound"] is False


def test_delivery_stops_at_the_steps_the_card_renders() -> None:
    steps = MAX_DELIVERED_SEGMENTS + 2
    coverage = compute_extension_coverage_hint(
        _evidence(tuple(_observation("command.git", RESET_RULE, segments=(index,)) for index in range(steps)))
    )

    payload = build_approval_extension_coverage(_pending(coverage), registry=BUILT_IN_COMMAND_EXTENSION_REGISTRY)

    assert payload is not None
    assert [segment["index"] for segment in payload["segments"]] == list(range(MAX_DELIVERED_SEGMENTS))
    assert payload["compound"] is True


def test_delivery_drops_a_step_whose_ids_this_build_does_not_carry() -> None:
    coverage = compute_extension_coverage_hint(
        _evidence(
            (
                _observation("command.git", RESET_RULE, segments=(0,)),
                _observation("command.retired-extension", "command.retired-extension.rule", segments=(1,)),
            )
        )
    )

    payload = build_approval_extension_coverage(_pending(coverage), registry=BUILT_IN_COMMAND_EXTENSION_REGISTRY)

    assert payload is not None
    assert [segment["index"] for segment in payload["segments"]] == [0]


def test_delivery_stays_out_of_resolved_and_unhinted_requests() -> None:
    registry = BUILT_IN_COMMAND_EXTENSION_REGISTRY
    coverage = compute_extension_coverage_hint(_evidence((_observation("command.git", RESET_RULE, segments=(0,)),)))

    assert (
        build_approval_extension_coverage({"status": "approved", "extension_allow_hint": coverage}, registry=registry)
        is None
    )
    assert build_approval_extension_coverage(_pending(None), registry=registry) is None
    assert with_approval_extension_coverage({}, _pending(coverage), registry=None, include=True) == {}
    assert with_approval_extension_coverage({}, _pending(coverage), registry=registry, include=False) == {}
    assert "extension_coverage" in with_approval_extension_coverage(
        {}, _pending(coverage), registry=registry, include=True
    )


NATIVE_COMMANDS = (
    "docker context ls",
    "git fetch origin main && docker system prune -f",
    "cat README.md",
)


def test_native_evidence_covers_every_step_the_resident_observed(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    home_dir = tmp_path / "home"
    home_dir.mkdir()
    covered = 0

    for fixture in real_native_review_fixtures(NATIVE_COMMANDS, cwd=workspace, home_dir=home_dir):
        evidence = fixture.payload.get("command_extensions") or {}
        observed: dict[int, set[str]] = {}
        for source in ("observations", "permission_observations"):
            for observation in evidence.get(source) or ():
                indexes = set(observation.get("effective_segment_indexes") or ())
                indexes.update(
                    item["segment_index"]
                    for item in observation.get("matcher_evidence") or ()
                    if "segment_index" in item
                )
                for index in indexes:
                    observed.setdefault(index, set()).add(observation["extension_id"])

        coverage = compute_extension_coverage_hint(fixture.payload)

        if not observed:
            assert coverage is None, fixture.command
            continue
        assert coverage is not None, fixture.command
        # Every step the resident observed is reported, under its own index:
        # steps are never merged, so a compound command's steps stay apart.
        assert {segment["index"]: set(segment["extension_ids"]) for segment in coverage["segments"]} == observed, (
            fixture.command
        )
        covered += 1

    # A build where no governed command produces coverage has a dead path.
    assert covered > 0

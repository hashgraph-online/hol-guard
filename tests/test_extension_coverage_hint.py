"""The review screen learns which extension governs which step of a paused command.

The allow hint only speaks when enabling a few permissions would let the *whole*
command run, so a command whose steps are governed by different extensions — or
whose other steps nothing can settle — reaches the review screen with nothing
pointing at Extensions. The coverage hint answers the weaker question instead:
which extension matched which step. The resident computes it
(``extension_coverage_hint.rs``); these tests pin what the daemon does with a
stored hint — every observed step is delivered, and one step's permissions are
never presented as settling another's.
"""

from __future__ import annotations

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
    validated_extension_coverage_hint,
    with_extension_coverage,
)

DIGEST = "b" * 64
FETCH_RULE = "command.git.unverified-fetch"
RESET_RULE = "command.git.hard-reset"
RESET_PERMISSION = "command.git.permission.hard-reset"
PRUNE_PERMISSION = "command.container-runtime.permission.build-cache-prune"


def _step(
    index: int,
    extension_id: str = "command.git",
    *,
    rule_id: str | None = RESET_RULE,
    permission_id: str | None = None,
    executable: str | None = None,
) -> dict[str, Any]:
    return {
        "index": index,
        "executable": executable,
        "extension_ids": [extension_id],
        "rule_ids": [rule_id] if rule_id else [],
        "permission_ids": [permission_id] if permission_id else [],
    }


def _coverage(*steps: dict[str, Any], total: int | None = None) -> dict[str, Any]:
    """The coverage hint the resident stores for a review that matched ``steps``."""

    hint: dict[str, Any] = {
        "schema": EXTENSION_COVERAGE_HINT_SCHEMA,
        "catalog_digest": DIGEST,
        "segments": list(steps),
    }
    if total is not None:
        hint["segment_total"] = total
    validated = validated_extension_coverage_hint(hint)
    assert validated is not None
    return validated


def test_a_stored_hint_is_read_from_either_carrier() -> None:
    coverage = _coverage(_step(0, rule_id=FETCH_RULE))

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
    coverage = _coverage(_step(0))

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
    coverage = _coverage(
        _step(0, executable="git"),
        _step(1, "command.container-runtime", rule_id=None, permission_id=PRUNE_PERMISSION, executable="docker"),
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
    coverage = _coverage(_step(2))
    payload = build_approval_extension_coverage(_pending(coverage), registry=BUILT_IN_COMMAND_EXTENSION_REGISTRY)

    assert payload is not None
    assert payload["compound"] is True


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
    registry = BUILT_IN_COMMAND_EXTENSION_REGISTRY

    chained = build_approval_extension_coverage(_pending(_coverage(_step(0), total=3)), registry=registry)
    alone = build_approval_extension_coverage(_pending(_coverage(_step(0), total=1)), registry=registry)

    assert chained is not None and chained["compound"] is True
    assert alone is not None and alone["compound"] is False


def test_delivery_stops_at_the_steps_the_card_renders() -> None:
    steps = MAX_DELIVERED_SEGMENTS + 2
    coverage = _coverage(*(_step(index) for index in range(steps)))

    payload = build_approval_extension_coverage(_pending(coverage), registry=BUILT_IN_COMMAND_EXTENSION_REGISTRY)

    assert payload is not None
    assert [segment["index"] for segment in payload["segments"]] == list(range(MAX_DELIVERED_SEGMENTS))
    assert payload["compound"] is True


def test_delivery_drops_a_step_whose_ids_this_build_does_not_carry() -> None:
    coverage = _coverage(
        _step(0),
        _step(1, "command.retired-extension", rule_id="command.retired-extension.rule"),
    )

    payload = build_approval_extension_coverage(_pending(coverage), registry=BUILT_IN_COMMAND_EXTENSION_REGISTRY)

    assert payload is not None
    assert [segment["index"] for segment in payload["segments"]] == [0]


def test_delivery_stays_out_of_resolved_and_unhinted_requests() -> None:
    registry = BUILT_IN_COMMAND_EXTENSION_REGISTRY
    coverage = _coverage(_step(0))

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

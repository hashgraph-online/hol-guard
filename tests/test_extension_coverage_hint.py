"""The review screen learns which extension governs which step of a paused command.

The allow hint only speaks when enabling a few permissions would let the *whole*
command run, so a command whose steps are governed by different extensions — or
whose other steps nothing can settle — reaches the review screen with nothing
pointing at Extensions. The coverage hint answers the weaker question instead:
which extension matched which step. The resident computes it
(``extension_coverage_hint.rs``) and labels it for the review card from its
catalog (``approval_extension_coverage.rs``); these tests pin how the stored
hint is carried and shape-checked.
"""

from __future__ import annotations

import time
from typing import Any

import pytest

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


@pytest.mark.parametrize("warm", [True, False])
def test_the_shape_check_keeps_its_own_deadline_once_the_resident_is_warm(
    monkeypatch: pytest.MonkeyPatch, warm: bool
) -> None:
    from codex_plugin_scanner.guard import native_runner_authority as authority
    from codex_plugin_scanner.guard.runtime import extension_coverage_hint as module

    deadlines: list[float | None] = []

    def fake(
        kind: str, args: object, *_: object, deadline_monotonic: float | None = None, **__: object
    ) -> dict[str, Any]:
        deadlines.append(deadline_monotonic)
        return {}

    monkeypatch.setattr(authority, "native_runner_authority", fake)
    monkeypatch.setattr(module, "_resident_warm", lambda: warm)
    started = time.monotonic()
    assert module.shaped_hint({"deadline-probe": [started, warm]}, "coverage") is None
    assert len(deadlines) == 1
    if not warm:
        assert deadlines[0] is None
        return
    assert deadlines[0] is not None
    assert started < deadlines[0] <= time.monotonic() + module._SHAPE_BUDGET_SECONDS


def test_a_caller_deadline_only_shortens_the_warm_shape_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard import native_runner_authority as authority
    from codex_plugin_scanner.guard.runtime import extension_coverage_hint as module

    deadlines: list[float | None] = []

    def fake(
        kind: str, args: object, *_: object, deadline_monotonic: float | None = None, **__: object
    ) -> dict[str, Any]:
        deadlines.append(deadline_monotonic)
        return {}

    monkeypatch.setattr(authority, "native_runner_authority", fake)
    monkeypatch.setattr(module, "_resident_warm", lambda: True)
    started = time.monotonic()
    late = started + 60.0
    early = started + 1.0
    assert module.shaped_hint({"late-deadline": started}, "coverage", deadline_monotonic=late) is None
    assert module.shaped_hint({"early-deadline": started}, "coverage", deadline_monotonic=early) is None
    assert deadlines[0] is not None
    assert deadlines[0] <= time.monotonic() + module._SHAPE_BUDGET_SECONDS
    assert deadlines[1] == early


def test_strict_checks_raise_a_refusal_instead_of_reading_it_as_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard import native_runner_authority as authority
    from codex_plugin_scanner.guard.runtime import extension_coverage_hint as module

    def refuse(*_: object, **__: object) -> dict[str, Any]:
        raise authority.NativeRunnerAuthorityRefusalError("native_runner_authority_refused")

    monkeypatch.setattr(authority, "native_runner_authority", refuse)
    monkeypatch.setattr(module, "_resident_warm", lambda: False)
    assert module.shaped_hint({"refusal-probe": 1}, "connector") is None
    with pytest.raises(authority.NativeRunnerAuthorityRefusalError):
        module.shaped_hint({"refusal-probe": 2}, "connector", strict=True)

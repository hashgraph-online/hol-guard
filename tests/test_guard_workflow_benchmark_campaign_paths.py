"""Portable retained layout keeps authenticated Unix sockets within kernel limits."""

from pathlib import Path

import pytest

from ci.gauntlet.benchmark import campaign_paths as module


def config():
    return {
        "schema": module.LEGACY,
        "cells": [{"id": "episode-" + str(i) * 32} for i in (1, 2)],
        "campaign": {"budgets": {"max_retries": 1}},
    }


def test_legacy_paths_remain_exact_and_are_not_retroactively_compacted():
    value = config()
    key = value["cells"][0]["id"]
    assert module.attempt_path("/old", value, key, 0) == Path("/old/attempts") / (key + ".attempt-0")
    assert module.validate_layout(value) == "legacy-v1"
    value["attempt_layout"] = "compact-v1"
    with pytest.raises(ValueError):
        module.validate_layout(value)


def test_compact_paths_are_deterministic_unique_and_keep_all_transport_headroom():
    value = config()
    module.configure_layout(value, "compact-v1")
    root = Path("/var/tmp/" + "x" * 18)
    assert len(str(root).encode()) == 27
    module.validate_ci_state_root(root)
    shard = root / "shard-063"
    paths = {module.attempt_path(shard, value, c["id"], attempt) for c in value["cells"] for attempt in (0, 1)}
    assert len(paths) == 4
    for path in paths:
        assert path.parent == shard / "a" and len(path.name) == 19
        assert len(str(path / "hooks/hook.sock").encode()) <= 85
        assert len(str(path / "continuation/frontdoor").encode()) <= 85
        assert len(str(path / "continuation/frontdoor/calendar.sock").encode()) < 108
        assert len(str(path / "continuation/agent-runtime/model.sock").encode()) < 108
    assert paths == {module.attempt_path(shard, value, c["id"], a) for c in value["cells"] for a in (0, 1)}


@pytest.mark.parametrize("root", ["/var/tmp/" + "x" * 19, "/var/tmp/" + "é" * 10])
def test_overlong_state_roots_fail_by_encoded_bytes_before_execution(root):
    with pytest.raises(ValueError, match="27 bytes"):
        module.validate_ci_state_root(Path(root))


@pytest.mark.parametrize(
    "mutation",
    [
        lambda v: v.update(schema="unknown"),
        lambda v: v.update(schema=module.COMPACT),
        lambda v: v.update(schema=module.COMPACT, attempt_layout="legacy-v1"),
    ],
)
def test_unknown_or_ambiguous_layouts_refused(mutation):
    value = config()
    mutation(value)
    with pytest.raises(ValueError):
        module.validate_layout(value)


def test_compact_identity_collision_is_refused_before_any_paths_are_created(monkeypatch):
    value = config()
    monkeypatch.setattr(module, "digest", lambda _: "0" * 64)
    with pytest.raises(ValueError, match="collision"):
        module.configure_layout(value, "compact-v1")


@pytest.mark.parametrize(
    ("key", "attempt"), [("not-selected", 0), ("episode-" + "1" * 32, True), ("episode-" + "1" * 32, 2)]
)
def test_paths_cannot_select_unfrozen_episodes_or_unapproved_attempts(key, attempt):
    with pytest.raises(ValueError):
        module.attempt_path("/state", config(), key, attempt)

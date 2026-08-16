"""Fail-closed contract for the retired release/3.1 publisher."""

from __future__ import annotations

from pathlib import Path
from typing import cast

import yaml  # pyright: ignore[reportMissingModuleSource]

ROOT = Path(__file__).resolve().parents[1]
PUBLISH = ROOT / ".github" / "workflows" / "publish.yml"


def _mapping(value: object) -> dict[object, object]:
    assert isinstance(value, dict)
    return cast(dict[object, object], value)


def workflow() -> dict[object, object]:
    return _mapping(cast(object, yaml.safe_load(PUBLISH.read_text(encoding="utf-8"))))


def test_retired_train_has_no_automatic_trigger() -> None:
    triggers = workflow()[True]
    assert triggers == {"workflow_dispatch": None}


def test_retired_train_has_no_repository_or_oidc_permissions() -> None:
    value = workflow()
    assert value["permissions"] == {}
    jobs = _mapping(value["jobs"])
    assert _mapping(jobs["retired"])["permissions"] == {}


def test_manual_dispatch_fails_closed_without_release_actions() -> None:
    value = workflow()
    job = _mapping(_mapping(value["jobs"])["retired"])
    assert job["name"] == "Reject retired release train"
    assert job["steps"] == [
        {
            "name": "Reject release publication",
            "run": 'echo "The release/3.1 publisher is retired."\nexit 1\n',
        }
    ]

    text = PUBLISH.read_text(encoding="utf-8")
    assert "pypa/gh-action-pypi-publish" not in text
    assert "gh release create" not in text
    assert "id-token: write" not in text
    assert "push:" not in text
    assert "pull_request:" not in text

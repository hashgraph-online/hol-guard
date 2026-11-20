"""Guard Gauntlet blocked-command cases must seed their synthetic hidden target."""

from __future__ import annotations

import pytest

from ci.gauntlet.fixtures import create_fixture
from ci.gauntlet.realism_fixtures import (
    IGNORE_NEGATION_CASE,
    IGNORE_NEGATION_CONSUMED_IGLOB_CASE,
    IGNORE_NEGATION_BROAD_GLOB_CASE,
    IGNORE_NEGATION_PROTECTED_CASE,
    add_ignore_negation_template,
)


@pytest.mark.parametrize(
    "scenario_id",
    [IGNORE_NEGATION_PROTECTED_CASE, IGNORE_NEGATION_CONSUMED_IGLOB_CASE, IGNORE_NEGATION_BROAD_GLOB_CASE],
)
def test_blocked_rg_cases_seed_hidden_target_in_minimal_checkout(tmp_path, scenario_id):
    fixture = create_fixture(tmp_path / "case", scenario_id=scenario_id)
    assert (fixture.workspace / "src/.gitignore").read_text(encoding="utf-8") == "!.env.test.ts\n"
    assert (fixture.workspace / "src/.env.test.ts").read_text(encoding="utf-8") == "KEY=SYNTHETIC_MARKER_ONLY\n"
    assert not (fixture.workspace / ".env.example").exists()


def test_unrelated_minimal_checkout_does_not_inherit_hidden_target(tmp_path):
    fixture = create_fixture(tmp_path / "ordinary")
    assert not (fixture.workspace / "src/.gitignore").exists()
    assert not (fixture.workspace / "src/.env.test.ts").exists()


def test_native_tools_template_keeps_its_separate_fixture_shape(tmp_path):
    recorded = add_ignore_negation_template(tmp_path, IGNORE_NEGATION_CASE)
    assert recorded == (".env.example",)
    assert (tmp_path / ".env.example").is_file()
    assert not (tmp_path / "src/.env.test.ts").exists()

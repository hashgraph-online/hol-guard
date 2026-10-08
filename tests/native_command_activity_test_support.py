"""Opt-in native evidence for tests of activity persistence and presentation."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.native_command_test_support import RealNativeReviewFixture, real_native_review_fixture


def use_real_native_activity_reviews(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep activity tests on actual native observations with a bound snapshot."""

    from codex_plugin_scanner.guard.cli import commands_support_command_activity as activity_support
    from codex_plugin_scanner.guard.runtime import native_command_evaluation

    fixtures: dict[tuple[str, Path | None, Path | None], RealNativeReviewFixture] = {}

    def review(command: str, **kwargs: object) -> dict[str, object]:
        cwd = kwargs.get("cwd")
        home_dir = kwargs.get("home_dir")
        assert cwd is None or isinstance(cwd, Path)
        assert home_dir is None or isinstance(home_dir, Path)
        key = (command, cwd, home_dir)
        if key not in fixtures:
            fixtures[key] = real_native_review_fixture(command, cwd=cwd, home_dir=home_dir)
        return fixtures[key].payload

    seed = real_native_review_fixture("printf native-fixture")
    monkeypatch.setattr(native_command_evaluation, "review_pre_tool_native", review)
    monkeypatch.setattr(
        activity_support.ExtensionControlRuntimeSnapshot,
        "from_authority_view",
        staticmethod(lambda _view: seed.snapshot),
    )

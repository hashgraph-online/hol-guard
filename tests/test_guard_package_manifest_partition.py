"""Parser partitions retain shared deadlines and live dependency bindings."""

from __future__ import annotations

from collections.abc import Callable

import pytest

from codex_plugin_scanner.guard.runtime import lockfile_parse_result as lockfiles
from codex_plugin_scanner.guard.runtime import package_manifest_diff as manifests


@pytest.mark.parametrize(
    ("path", "text"),
    (
        ("package.json", '{"dependencies":{"demo":"1"}}'),
        ("composer.json", '{"require":{"demo":"1"}}'),
        ("package-lock.json", '{"packages":{"node_modules/demo":{"version":"1"}}}'),
        ("pnpm-lock.yaml", "packages:\n  demo@1:\n"),
        ("yarn.lock", 'demo@^1:\n  version "1"\n'),
        ("bun.lock", '{"packages":{"demo":["demo@1","",{}]}}'),
    ),
)
def test_moved_parser_uses_shared_deadline_failure(monkeypatch: pytest.MonkeyPatch, path: str, text: str) -> None:
    assert lockfiles._DeadlineExceededError is manifests._DeadlineExceededError
    observed: list[float] = []

    def expired(deadline: float) -> None:
        observed.append(deadline)
        raise lockfiles._DeadlineExceededError("deadline_exceeded")

    monkeypatch.setattr(manifests, "_ensure_within_deadline", expired)
    result = manifests.parse_manifest_dependency_changes(path=path, before_text=None, after_text=text)
    assert observed
    assert result.changes == ()
    assert result.truncated is True
    assert result.parse_errors == ("deadline_exceeded",)


def test_bun_parser_resolves_live_decoder_and_selector(monkeypatch: pytest.MonkeyPatch) -> None:
    events: list[object] = []

    def decode(text: str, *, deadline_check: Callable[[], None]) -> dict[str, object]:
        events.append(("decode", text))
        deadline_check()
        return {"packages": {"demo": ["demo@1", "", {}]}}

    def select(value: str) -> tuple[str, str]:
        events.append(("select", value))
        return "verified-demo", "2"

    monkeypatch.setattr(manifests, "loads_jsonc", decode)
    monkeypatch.setattr(manifests, "_bun_resolution_identity", select)
    assert manifests._dependency_map_for_path("bun.lock", "synthetic", deadline=float("inf")) == {"verified-demo": "2"}
    assert events == [("decode", "synthetic"), ("select", "demo@1")]

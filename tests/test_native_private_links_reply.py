"""A contained cargo run gets its cache links from the native `private_links` answer."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_restricted_pytest
from codex_plugin_scanner.guard.runtime.restricted_pytest_model import RestrictedPytestError
from codex_plugin_scanner.guard.runtime.restricted_pytest_sandbox import link_private_caches


def _native_answers(monkeypatch: pytest.MonkeyPatch, reply: object) -> list[str]:
    asked: list[str] = []

    def call(request: dict[str, object], **_: object) -> object:
        body = request["body"]
        assert isinstance(body, dict)
        asked.append(str(body["operation"]))
        return reply

    monkeypatch.setattr(native_restricted_pytest, "_call", call)
    return asked


def test_the_cargo_cache_links_the_native_side_grants_are_made(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    host_registry = tmp_path / "host" / ".cargo" / "registry" / "index"
    host_registry.mkdir(parents=True)
    private_tmp = tmp_path / "private" / "tmp"
    private_tmp.mkdir(parents=True)
    link = private_tmp / "cargo" / "registry" / "index"
    asked = _native_answers(monkeypatch, {"value": [{"link": str(link), "target": str(host_registry)}]})

    link_private_caches(private_tmp, (tmp_path / "host" / ".cargo",))

    assert asked == ["private_links"]
    assert link.is_symlink()
    assert link.resolve() == host_registry.resolve()


@pytest.mark.parametrize(
    "entry",
    [
        "/a/path",
        {"link": "/a"},
        {"link": "/a", "target": 7},
        {"link": "/a", "target": "/b", "mode": "rw"},
    ],
)
def test_a_link_entry_of_any_other_shape_refuses_the_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, entry: object
) -> None:
    _native_answers(monkeypatch, {"value": [entry]})

    with pytest.raises(RestrictedPytestError) as refused:
        link_private_caches(tmp_path, ())

    assert "invalid_reply" in str(refused.value)
    assert not any(tmp_path.iterdir())


def test_other_list_answers_still_have_to_be_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    _native_answers(monkeypatch, {"value": [{"link": "/a", "target": "/b"}]})

    with pytest.raises(RestrictedPytestError):
        native_restricted_pytest.restricted_native("read_only_roots", {}, list)

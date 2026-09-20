"""Platform scope aliases preserve identity without collapsing distinct paths."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_policy_snapshot_policy as policy


@pytest.mark.parametrize("platform", ["darwin", "ios"])
def test_apple_private_alias_matches(monkeypatch: pytest.MonkeyPatch, platform: str) -> None:
    monkeypatch.setattr(policy, "os", SimpleNamespace(name="posix"))
    monkeypatch.setattr(policy.sys, "platform", platform)
    assert policy._normalize_scope_text_v3("/private/var/guard/") == "/var/guard"
    assert policy._normalize_scope_text_v3("/Users/Shared/My Guard/") == "/Users/Shared/My Guard"


@pytest.mark.parametrize("platform", ["linux", "freebsd14"])
def test_non_apple_private_paths_remain_distinct(monkeypatch: pytest.MonkeyPatch, platform: str) -> None:
    monkeypatch.setattr(policy, "os", SimpleNamespace(name="posix"))
    monkeypatch.setattr(policy.sys, "platform", platform)
    assert policy._normalize_scope_text_v3("/private/var/guard/") == "/private/var/guard"
    assert policy._normalize_scope_text_v3("/var/guard/") == "/var/guard"
    assert policy._normalize_scope_text_v3("/") == "/"


@pytest.mark.parametrize(
    ("alias", "canonical"),
    [
        (r"C:\Users\Guard\State", r"c:\users\guard\state"),
        ("\\\\?\\C:\\Users\\Guard\\State\\", r"c:\users\guard\state"),
        (r"\\?\UNC\Server\Share\Guard", r"\\server\share\guard"),
        ("C:/Users/Guard/State/", r"c:\users\guard\state"),
    ],
)
def test_windows_aliases_match(monkeypatch: pytest.MonkeyPatch, alias: str, canonical: str) -> None:
    monkeypatch.setattr(policy, "os", SimpleNamespace(name="nt"))
    assert policy._normalize_scope_text_v3(alias) == canonical


def test_scope_digest_distinguishes_siblings_and_resolves_symlinks(tmp_path: Path) -> None:
    sibling = tmp_path / "guard-a"
    other = tmp_path / "guard-b"
    sibling.mkdir()
    other.mkdir()
    assert policy._scope_digest_v3(sibling) != policy._scope_digest_v3(other)
    linked = tmp_path / "guard-link"
    try:
        linked.symlink_to(sibling, target_is_directory=True)
    except OSError:
        pytest.skip("Creating directory symlinks is unavailable on this runner")
    assert policy._scope_digest_v3(linked) == policy._scope_digest_v3(sibling)

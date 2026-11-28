"""The fixture HOME carries the host's default rustup toolchain for the cargo cases."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from ci.gauntlet.cargo_package_fixtures import CARGO_MANIFEST_CASE, add_rustup_home

TOOLCHAIN = "1.88.0-aarch64-apple-darwin"


def _host(tmp_path: Path, settings: str) -> Path:
    host = tmp_path / "host-rustup"
    (host / "toolchains" / TOOLCHAIN / "bin").mkdir(parents=True)
    (host / "settings.toml").write_text(settings, encoding="utf-8")
    (host / "update-hashes").mkdir()
    return host


def test_cargo_case_gets_only_the_host_default_toolchain(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    host = _host(
        tmp_path,
        f'version = "12"\ndefault_toolchain = "{TOOLCHAIN}"\n[overrides]\n"/elsewhere" = "nightly"\n',
    )
    monkeypatch.setenv("RUSTUP_HOME", str(host))
    home = tmp_path / "home"
    home.mkdir()

    add_rustup_home(home, CARGO_MANIFEST_CASE)

    rustup = home / ".rustup"
    assert rustup.is_dir() and not rustup.is_symlink()
    settings = (rustup / "settings.toml").read_text(encoding="utf-8")
    assert f'default_toolchain = "{TOOLCHAIN}"' in settings
    assert "overrides" not in settings
    linked = rustup / "toolchains" / TOOLCHAIN
    assert linked.is_symlink() and Path(os.readlink(linked)) == (host / "toolchains" / TOOLCHAIN).resolve()
    assert sorted(path.name for path in rustup.iterdir()) == ["settings.toml", "toolchains"]


@pytest.mark.parametrize(
    "settings",
    ["", 'default_toolchain = "stable-aarch64-apple-darwin"\n', 'default_toolchain = "../escape"\n', "not toml ["],
)
def test_no_usable_host_default_leaves_home_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, settings: str
) -> None:
    monkeypatch.setenv("RUSTUP_HOME", str(_host(tmp_path, settings)))
    home = tmp_path / "home"
    home.mkdir()

    add_rustup_home(home, CARGO_MANIFEST_CASE)

    assert not (home / ".rustup").exists()


def test_other_cases_get_no_rustup_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RUSTUP_HOME", str(_host(tmp_path, f'default_toolchain = "{TOOLCHAIN}"\n')))
    home = tmp_path / "home"
    home.mkdir()

    add_rustup_home(home, "omp-native-shell-cargo-dependency-resolve-protected")

    assert not (home / ".rustup").exists()

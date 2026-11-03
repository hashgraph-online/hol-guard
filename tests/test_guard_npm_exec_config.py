from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.npm_exec_config import (
    MAX_NPMRC_BYTES,
    npm_config_adds_package,
    npmrc_sets_package,
)


def _project(tmp_path: Path) -> tuple[Path, dict[str, str]]:
    """A project under its own home, with an environment that names no setting."""

    home = tmp_path / "home"
    project = home / "src" / "demo"
    project.mkdir(parents=True)
    return project, {"HOME": str(home), "PATH": "/usr/bin"}


@pytest.mark.parametrize("key", ["npm_config_package", "NPM_CONFIG_PACKAGE", "Npm_Config_Package"])
def test_the_package_setting_in_the_environment_adds_a_package(tmp_path: Path, key: str) -> None:
    project, environment = _project(tmp_path)

    assert npm_config_adds_package(environment={**environment, key: "left-pad"}, cwd=project)


def test_environment_settings_that_name_no_package_add_nothing(tmp_path: Path) -> None:
    project, environment = _project(tmp_path)
    environment = {
        **environment,
        # npm skips an empty value.
        "npm_config_package": "",
        "npm_config_registry": "https://registry.npmjs.org/",
        "NPM_CONFIG_SAVE_EXACT": "true",
        "npm_config_//registry.npmjs.org/:_authToken": "unused",
        "PACKAGE": "left-pad",
    }

    assert not npm_config_adds_package(environment=environment, cwd=project)


@pytest.mark.parametrize(
    "text",
    [
        "package=left-pad\n",
        "  package = left-pad\n",
        "package[]=left-pad\n",
        '"package" = left-pad\n',
        "PACKAGE=left-pad\n",
        "﻿package=left-pad\n",
        "registry=https://registry.npmjs.org/\r\npackage=left-pad\r\n",
        "[section]\npackage=left-pad\n",
        "package\n",
        # npm expands ${VAR} inside setting names.
        "${SETTING}=left-pad\n",
        "userconfig=./other.npmrc\n",
        "globalconfig=/elsewhere/npmrc\n",
    ],
)
def test_an_npmrc_that_names_a_package_setting_is_flagged(tmp_path: Path, text: str) -> None:
    path = tmp_path / ".npmrc"
    path.write_text(text, encoding="utf-8")

    assert npmrc_sets_package(path)


@pytest.mark.parametrize(
    "text",
    [
        "",
        "registry=https://registry.npmjs.org/\nsave-exact=true\n",
        "; package=left-pad\n# package=left-pad\n",
        "//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n",
        "@scope:registry=https://npm.example.test/\n",
        "packages=left-pad\npackage-lock=false\n",
    ],
)
def test_an_npmrc_without_a_package_setting_is_not_flagged(tmp_path: Path, text: str) -> None:
    path = tmp_path / ".npmrc"
    path.write_text(text, encoding="utf-8")

    assert not npmrc_sets_package(path)


def test_a_missing_npmrc_adds_nothing(tmp_path: Path) -> None:
    assert not npmrc_sets_package(tmp_path / ".npmrc")


def test_an_npmrc_that_cannot_be_read_keeps_the_review(tmp_path: Path) -> None:
    (tmp_path / ".npmrc").mkdir()

    assert npmrc_sets_package(tmp_path / ".npmrc")


def test_an_oversized_npmrc_keeps_the_review(tmp_path: Path) -> None:
    path = tmp_path / ".npmrc"
    path.write_bytes(b"; filler\n" * (MAX_NPMRC_BYTES // 9 + 1))

    assert npmrc_sets_package(path)


@pytest.mark.parametrize("folder", [".", "..", "../.."])
def test_an_npmrc_in_the_project_or_any_folder_above_it_adds_a_package(tmp_path: Path, folder: str) -> None:
    project, environment = _project(tmp_path)
    (project / folder / ".npmrc").write_text("package=left-pad\n", encoding="utf-8")

    assert npm_config_adds_package(environment=environment, cwd=project)


def test_the_user_npmrc_is_read_from_home(tmp_path: Path) -> None:
    _, environment = _project(tmp_path)
    # The project sits outside the home folder, so only the userconfig read
    # can find this file.
    outside = tmp_path / "outside"
    outside.mkdir()
    (Path(environment["HOME"]) / ".npmrc").write_text("package=left-pad\n", encoding="utf-8")

    assert npm_config_adds_package(environment=environment, cwd=outside)


def test_an_environment_userconfig_replaces_the_home_npmrc(tmp_path: Path) -> None:
    _, environment = _project(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (Path(environment["HOME"]) / ".npmrc").write_text("package=left-pad\n", encoding="utf-8")
    other = tmp_path / "other.npmrc"
    other.write_text("registry=https://registry.npmjs.org/\n", encoding="utf-8")

    assert not npm_config_adds_package(
        environment={**environment, "npm_config_userconfig": str(other)},
        cwd=outside,
    )
    other.write_text("package=left-pad\n", encoding="utf-8")
    assert npm_config_adds_package(
        environment={**environment, "npm_config_userconfig": str(other)},
        cwd=outside,
    )


def test_an_environment_globalconfig_is_read(tmp_path: Path) -> None:
    project, environment = _project(tmp_path)
    global_npmrc = tmp_path / "prefix" / "etc" / "npmrc"
    global_npmrc.parent.mkdir(parents=True)
    global_npmrc.write_text("package=left-pad\n", encoding="utf-8")

    assert npm_config_adds_package(
        environment={**environment, "NPM_CONFIG_GLOBALCONFIG": str(global_npmrc)},
        cwd=project,
    )


def test_a_project_with_ordinary_npm_settings_adds_nothing(tmp_path: Path) -> None:
    project, environment = _project(tmp_path)
    (project / ".npmrc").write_text("registry=https://registry.npmjs.org/\nsave-exact=true\n", encoding="utf-8")
    (Path(environment["HOME"]) / ".npmrc").write_text("fund=false\n", encoding="utf-8")

    assert not npm_config_adds_package(environment=environment, cwd=project)

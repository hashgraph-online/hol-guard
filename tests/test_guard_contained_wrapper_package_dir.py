from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.contained_wrapper import OutputFilter, peel_contained_wrapper


def org_home(tmp_path: Path) -> tuple[Path, Path, Path]:
    """A home holding two sibling repositories under a non-repository parent."""
    home = tmp_path / "home"
    workspace = home / "org" / "app-portal"
    sibling = home / "org" / "service-api"
    for repository in (workspace, sibling):
        (repository / ".git").mkdir(parents=True)
    (workspace / "web").mkdir()
    (home / "org" / "loose").mkdir()
    (home / ".config").mkdir()
    return home, workspace, sibling


@pytest.mark.parametrize(
    ("command", "core"),
    [
        ("bun run --cwd {sibling} build", "bun run build"),
        ("bun --cwd={sibling} run build", "bun run build"),
        ("npm --prefix {sibling} run build", "npm run build"),
        ("npm -C {sibling} test", "npm test"),
        ("pnpm -C {sibling} run test", "pnpm run test"),
        ("pnpm --dir={sibling} run test", "pnpm run test"),
        ("yarn --cwd {sibling} run build", "yarn run build"),
        ("bun run --cwd ../service-api test", "bun run test"),
    ],
)
def test_package_directory_flag_peels_like_a_cd(tmp_path: Path, command: str, core: str) -> None:
    home, workspace, sibling = org_home(tmp_path)
    peeled = peel_contained_wrapper(command.format(sibling=sibling), workspace=workspace, home=home, cwd=workspace)
    assert peeled == (core, sibling.resolve(), None)


def test_package_directory_flag_keeps_bounded_output_and_workspace_subdirectories(tmp_path: Path) -> None:
    home, workspace, sibling = org_home(tmp_path)
    assert peel_contained_wrapper(
        f"npm --prefix {sibling} run build 2>&1 | tail -8", workspace=workspace, home=home, cwd=workspace
    ) == ("npm run build", sibling.resolve(), OutputFilter("tail", 8, merge_stderr=True))
    assert peel_contained_wrapper("bun --cwd web run build", workspace=workspace, home=home, cwd=workspace) == (
        "bun run build",
        (workspace / "web").resolve(),
        None,
    )


@pytest.mark.parametrize(
    "command",
    [
        "bun run --cwd {home} build",
        "bun run --cwd {home}/.config build",
        "bun run --cwd {home}/org/loose build",
        "bun run --cwd / build",
        "npm --prefix {sibling} run build && rm -rf /",
    ],
)
def test_package_directory_outside_a_repository_is_not_peeled(tmp_path: Path, command: str) -> None:
    home, workspace, sibling = org_home(tmp_path)
    with pytest.raises(ValueError):
        peel_contained_wrapper(
            command.format(home=home, sibling=sibling), workspace=workspace, home=home, cwd=workspace
        )


@pytest.mark.parametrize(
    "command",
    [
        # A trailing flag goes to the script; a repeated flag is ambiguous; `~` is not proved.
        "bun run build --cwd {sibling}",
        "npm --prefix {sibling} --prefix {sibling} run build",
        "bun run --cwd ~/org/service-api build",
        "pnpm -C{sibling} run test",
        "bun run build",
        # Tool runners keep the second node authorization. Rewriting them drops it.
        "bun --cwd {sibling} x vitest run",
        "npm --prefix {sibling} exec vitest",
        "pnpm --dir {sibling} dlx vitest",
    ],
)
def test_other_package_directory_spellings_stay_unwrapped(tmp_path: Path, command: str) -> None:
    home, workspace, sibling = org_home(tmp_path)
    assert (
        peel_contained_wrapper(command.format(sibling=sibling), workspace=workspace, home=home, cwd=workspace) is None
    )

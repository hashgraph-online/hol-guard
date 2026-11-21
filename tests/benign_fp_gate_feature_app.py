"""The repository the static gate reads its sign-in folder from.

The live Gauntlet's sign-in folder and the data files in it that stay under
review sit in a repository of their own, so a recursive search of the shared
worktree does not reach a file Guard holds. Every value is synthetic.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from ci.gauntlet.feature_directory_fixtures import HELD, SOURCES

_ENVIRONMENT = {
    "GIT_AUTHOR_NAME": "Fixture Author",
    "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
    "GIT_COMMITTER_NAME": "Fixture Author",
    "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
    "GIT_CONFIG_NOSYSTEM": "1",
}


def feature_app_path(home: Path) -> Path:
    return home / "Code" / "feature-app"


def build_feature_app(home: Path, path_variable: str) -> Path:
    """Create the repository, with the sign-in folder and its held files committed."""
    repository = feature_app_path(home)
    repository.mkdir(parents=True)
    for relative, text in {**SOURCES, **HELD}.items():
        target = repository / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
    environment = {"PATH": path_variable, "HOME": str(home), **_ENVIRONMENT}
    for arguments in (
        ["init", "--quiet", "--initial-branch=main"],
        ["add", "-A"],
        ["commit", "--quiet", "-m", "feature app base"],
    ):
        subprocess.run(["git", *arguments], cwd=repository, env=environment, check=True, capture_output=True)
    return repository

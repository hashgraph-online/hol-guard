"""A checkout whose configuration names its own exclude file.

Some tools write ``core.excludesFile = .git/info/exclude`` into the repository
configuration. Git reads that file on every ignore check anyway, so a verbose
``git check-ignore`` prints nothing it would not print without the setting.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

OWN_EXCLUDE_CASE = "omp-native-git-check-ignore-verbose-own-exclude-file"


def add_own_exclude_setting(workspace: Path, environment: dict[str, str], scenario_id: str | None) -> None:
    """Name the repository's own exclude file in its configuration."""
    if scenario_id != OWN_EXCLUDE_CASE:
        return
    subprocess.run(
        ["git", "-C", str(workspace), "config", "core.excludesFile", ".git/info/exclude"],
        env=environment,
        check=True,
        capture_output=True,
        timeout=15,
    )

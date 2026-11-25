"""A committed source folder named for the sign-in feature it holds.

Projects keep their login code under folders such as ``src/lib/auth``. A Git
read filtered to that folder lists commits or changed names for ordinary
source, so the live case checks an agent can run it with Guard silent.
"""

from __future__ import annotations

from pathlib import Path

FEATURE_FOLDER_CASE = "omp-native-git-reads-filtered-to-sign-in-folder"
FEATURE_FOLDER_FILE = "src/lib/auth/session.ts"


def add_feature_folder(workspace: Path, scenario_id: str | None) -> None:
    """Write the sign-in source file before the fixture baseline commits ``src``."""
    if scenario_id != FEATURE_FOLDER_CASE:
        return
    target = workspace / FEATURE_FOLDER_FILE
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("export function useSession() {}\n", encoding="utf-8", newline="\n")

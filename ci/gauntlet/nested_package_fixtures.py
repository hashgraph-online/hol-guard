"""A workspace package that reads shared settings from the checkout root.

Agents step into a package of a workspace and search back up from there:
``cd packages/app && rg -n "ready" ..`` or a recursive ``grep`` naming one
file two folders up. Both stay inside the same checkout, so the searches have
to run quietly. The layout matches the benign gate's ``atlas-tools`` workspace
and is committed, as a cloned workspace is.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

# `rg` from a package searching the folder above it, still inside the checkout.
PARENT_FOLDER_SEARCH_CASE = "omp-native-search-rg-parent-folder-from-package"
# A recursive `grep` whose operand is one file two folders up.
PARENT_FILE_SEARCH_CASE = "omp-native-search-grep-recursive-parent-file-from-package"
NESTED_PACKAGE_CASES = (PARENT_FOLDER_SEARCH_CASE, PARENT_FILE_SEARCH_CASE)

_FILES = {
    "package.json": json.dumps({"private": True, "workspaces": ["packages/*"]}) + "\n",
    "tsconfig.base.json": json.dumps({"compilerOptions": {"strict": True, "skipLibCheck": True}}) + "\n",
    "packages/app/tsconfig.json": json.dumps(
        {"extends": "../../tsconfig.base.json", "compilerOptions": {"noEmit": True}, "include": ["src/**/*.ts"]}
    )
    + "\n",
    "packages/app/src/index.ts": "export const ready = true;\n",
}


def add_nested_workspace_package(workspace: Path, environment: dict[str, str], scenario_id: str | None) -> None:
    """Commit the workspace package layout, for its cases only."""
    if scenario_id not in NESTED_PACKAGE_CASES:
        return
    for relative, text in _FILES.items():
        target = workspace / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8", newline="\n")
    identity = ("-c", "user.name=Gauntlet Fixture", "-c", "user.email=gauntlet@example.invalid")
    for args in (
        ("add", "--", *_FILES),
        (*identity, "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "Add the app package"),
    ):
        subprocess.run(
            ["git", "-C", str(workspace), *args], env=environment, check=True, capture_output=True, timeout=15
        )

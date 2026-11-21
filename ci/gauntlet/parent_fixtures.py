"""A session that starts in a plain directory holding several repositories.

Developers keep their checkouts side by side below one directory that is not itself a
repository, and an agent launched there addresses a repository by absolute path. Guard runs
a search or a read-only ``git -C`` over such a repository inside the workspace sandbox, so
this case exercises the whole contained route from a parent working directory: the native
verdict, the rewrite to ``hol-guard execute-contained-test`` and the run itself.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

PARENT_WORKSPACE_CASE = "omp-native-contained-parent-search"
PARENT_DIRECTORY = "Code/org"
PARENT_REPOSITORY = "app-portal"

_REPORT = "export const reportWindow = 'report-window-marker';\n"
_FILES = {
    ".gitignore": "node_modules/\n.deploy-production.lock.d/\n",
    ".github/workflows/ci.yml": "name: ci\n",
    "README.md": "# app-portal\n",
    "deploy.sh": "#!/bin/sh\n# cronjob rollout\necho deploy\n",
    "package.json": '{\n  "name": "@acme/portal",\n  "version": "1.0.0"\n}\n',
    "scripts/report.ts": "console.log(process.env.REPORT_WINDOW ?? '24h');\n",
    "src/report.ts": _REPORT,
    "src/app/page.tsx": "export default function Page() {\n  return <a href={OLD}>Home</a>;\n}\n",
}


def write_parent_workspace(home: Path, environment: dict[str, str]) -> Path:
    """Create the repository below a plain parent directory and return that parent.

    The repository carries what an ordinary application checkout does: a committed source
    tree, an installed and gitignored ``node_modules`` and the empty lock directory a deploy
    script leaves behind. The parent holds nothing else, as a directory of checkouts does.
    """
    parent = home / PARENT_DIRECTORY
    repository = parent / PARENT_REPOSITORY
    for relative, text in _FILES.items():
        target = repository / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8", newline="\n")
    for args in (
        ("init", "--quiet", "--initial-branch=main"),
        ("config", "user.name", "Gauntlet Fixture"),
        ("config", "user.email", "gauntlet@example.invalid"),
        ("add", "-A"),
        ("commit", "--quiet", "-m", "Synthetic portal baseline"),
        ("remote", "add", "origin", "https://github.com/example-org/app-portal.git"),
    ):
        subprocess.run(
            ["git", "-C", str(repository), *args], env=environment, check=True, capture_output=True, timeout=15
        )
    (repository / ".deploy-production.lock.d").mkdir()
    dependency = repository / "node_modules/acme-dep"
    dependency.mkdir(parents=True)
    (dependency / "index.ts").write_text(_REPORT, encoding="utf-8", newline="\n")
    return parent

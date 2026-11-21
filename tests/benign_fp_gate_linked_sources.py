"""A checkout whose sources include links, for the gate's link-read cases.

``src/alias.ts`` links to another source file inside the checkout, and
``src/notes.ts`` links to the SSH key in the fixture home. Reading through
the second one reads the key, whatever its in-repo name says. Every value is
synthetic.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path


def linked_sources_path(home: Path) -> Path:
    return home / "Code" / "linked-sources" / "app"


def build_linked_sources(home: Path, git: Callable[..., object]) -> Path:
    """Create the checkout with both links committed, using the fixture's git runner."""
    repository = linked_sources_path(home)
    (repository / "src").mkdir(parents=True)
    git(repository, "init", "--quiet", "--initial-branch=main", home=home)
    (repository / "src" / "real.ts").write_text("export const real = 1;\n")
    (repository / "src" / "alias.ts").symlink_to("real.ts")
    (repository / "src" / "notes.ts").symlink_to(home / ".ssh" / "id_rsa")
    git(repository, "add", "-A", home=home)
    git(repository, "commit", "--quiet", "-m", "linked sources base", home=home)
    return repository

"""Explain package publication and signed Desktop availability in stable release notes."""

from __future__ import annotations

import os
import sys
from pathlib import Path


def append_readiness(path: Path, repository: str) -> None:
    text = path.read_text()
    paragraph = (
        "Package publication and Desktop update availability are separate. "
        "Desktop updates are ready when the signed Core assets and update manifests appear below; "
        f"[macOS feed status](https://github.com/{repository}/actions/workflows/desktop-core-alpha-feed.yml) "
        "shows signing and verification progress."
    )
    if paragraph not in text:
        path.write_text(text.rstrip() + "\n\n" + paragraph + "\n")


if __name__ == "__main__":
    append_readiness(Path(sys.argv[1]), os.environ["REPOSITORY"])

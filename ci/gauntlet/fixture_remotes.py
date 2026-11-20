"""The origin remote a realistic fixture checkout carries for the cases that read one."""

from __future__ import annotations

import subprocess
from pathlib import Path

INSTEAD_OF_CASE = "omp-native-git-global-instead-of"
# Asks which remote URLs the checkout has configured, so its checkout has one: with no
# remote, `git config --get-regexp` answers with exit 1 and the case fails as a tool error.
REMOTE_URLS_CASE = "omp-native-git-config-regexp-remote-urls"
REMOTE_URLS_ORIGIN = "https://git.example.test/acme/app.git"
# The global `insteadOf` rewrite matches the short `acme:` spelling of this origin.
CHECKOUT_ORIGINS = {
    INSTEAD_OF_CASE: "acme:app.git",
    REMOTE_URLS_CASE: REMOTE_URLS_ORIGIN,
}


def add_checkout_origin(main: Path, environment: dict[str, str], scenario_id: str | None) -> None:
    """Give the main checkout the origin its scenario reads; other scenarios get none."""
    origin = CHECKOUT_ORIGINS.get(scenario_id or "")
    if origin is None:
        return
    subprocess.run(
        ["git", "-C", str(main), "remote", "add", "origin", origin],
        env=environment,
        check=True,
        capture_output=True,
        timeout=15,
    )

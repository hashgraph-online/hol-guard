"""Package-shim intercept probe constants (probing itself is the resident's ``shim_admin``)."""

from __future__ import annotations

SHIM_PROBE_ENV_VAR = "HOL_GUARD_SHIM_PROBE"
SHIM_PROBE_ENV_VALUE = "1"

_PACKAGE_SHIM_PROBE_ARGS: dict[str, tuple[str, ...]] = {
    "brew": ("install", "--dry-run", "jq"),
    "npm": ("install", "--dry-run", "lodash@4.17.21"),
    "npx": ("-y", "lodash@4.17.21"),
    "pnpm": ("add", "--dry-run", "lodash@4.17.21"),
    "yarn": ("add", "--dry-run", "lodash@4.17.21"),
    "bun": ("add", "--dry-run", "lodash@4.17.21"),
    "bunx": ("--version",),
    "pip": ("install", "--dry-run", "requests==2.32.3"),
    "pip3": ("install", "--dry-run", "requests==2.32.3"),
    "uv": ("add", "--dry-run", "requests==2.32.3"),
    "poetry": ("add", "--dry-run", "requests@2.32.3"),
    "pipenv": ("install", "--dry-run", "requests==2.32.3"),
    "pipx": ("install", "--dry-run", "requests==2.32.3"),
    "cargo": ("add", "serde@1.0.203"),
    "go": ("install", "-n", "github.com/pkg/errors@v0.9.1"),
    "composer": ("require", "--dry-run", "monolog/monolog:3.6.0"),
    "bundle": ("add", "rails", "--version", "7.1.3"),
}

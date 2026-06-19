"""Normalize package-manager commands before install/execute parsing."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class _GlobalOptionConfig:
    subcommands: frozenset[str]
    value_options: frozenset[str] = frozenset()


_MANAGER_ALIASES = {
    "pip3": "pip",
}

_MANAGER_GLOBAL_OPTIONS: dict[str, _GlobalOptionConfig] = {
    "npm": _GlobalOptionConfig(
        subcommands=frozenset({"add", "audit", "ci", "exec", "i", "install", "update", "x"}),
        value_options=frozenset(
            {
                "--cache",
                "--config",
                "--prefix",
                "--registry",
                "--userconfig",
                "-C",
            }
        ),
    ),
    "pnpm": _GlobalOptionConfig(
        subcommands=frozenset({"add", "dlx", "i", "install"}),
        value_options=frozenset(
            {
                "--dir",
                "--filter",
                "--registry",
                "--store-dir",
                "--workspace-dir",
                "-C",
                "-F",
            }
        ),
    ),
    "yarn": _GlobalOptionConfig(
        subcommands=frozenset({"add", "dlx", "install", "up", "workspace"}),
        value_options=frozenset(
            {
                "--cache-folder",
                "--cwd",
                "--modules-folder",
                "--registry",
            }
        ),
    ),
    "pip": _GlobalOptionConfig(
        subcommands=frozenset({"install"}),
        value_options=frozenset(
            {
                "--cache-dir",
                "--cert",
                "--client-cert",
                "--extra-index-url",
                "--find-links",
                "--index-url",
                "--proxy",
                "--python",
                "--retries",
                "--timeout",
                "--trusted-host",
                "-f",
                "-i",
            }
        ),
    ),
    "pipx": _GlobalOptionConfig(
        subcommands=frozenset({"install", "run"}),
        value_options=frozenset({"--index-url", "--pip-args", "--python"}),
    ),
    "uv": _GlobalOptionConfig(
        subcommands=frozenset({"add", "pip", "sync"}),
        value_options=frozenset({"--cache-dir", "--directory", "--index", "--python", "--project"}),
    ),
    "poetry": _GlobalOptionConfig(
        subcommands=frozenset({"add", "install"}),
        value_options=frozenset({"--directory", "-C"}),
    ),
    "pipenv": _GlobalOptionConfig(
        subcommands=frozenset({"install", "sync"}),
        value_options=frozenset({"--python"}),
    ),
}


def strip_package_manager_global_options(tokens: Sequence[str]) -> tuple[str, ...]:
    normalized_tokens = tuple(str(token) for token in tokens)
    if len(normalized_tokens) < 2:
        return normalized_tokens
    config = _MANAGER_GLOBAL_OPTIONS.get(_manager_key(normalized_tokens[0]))
    if config is None:
        return normalized_tokens
    index = 1
    while index < len(normalized_tokens):
        token = normalized_tokens[index]
        if token in config.subcommands:
            return (normalized_tokens[0], *normalized_tokens[index:])
        if token == "--":
            break
        if not token.startswith("-"):
            return (normalized_tokens[0], *normalized_tokens[index:])
        index += _leading_option_width(normalized_tokens, index, config)
    return normalized_tokens


def _manager_key(command_name: str) -> str:
    normalized = Path(command_name).name.lower()
    return _MANAGER_ALIASES.get(normalized, normalized)


def _leading_option_width(
    tokens: tuple[str, ...],
    index: int,
    config: _GlobalOptionConfig,
) -> int:
    token = tokens[index]
    if token in config.value_options:
        return 2 if index + 1 < len(tokens) else 1
    if _matches_inline_value_option(token, config.value_options):
        return 1
    next_index = index + 1
    if next_index < len(tokens) and tokens[next_index] in config.subcommands:
        return 1
    next_token = tokens[next_index] if next_index < len(tokens) else None
    if token.startswith("--"):
        if (
            "=" not in token
            and next_token is not None
            and not next_token.startswith("-")
            and next_token not in config.subcommands
        ):
            return 2
        return 1
    if (
        len(token) == 2
        and next_token is not None
        and not next_token.startswith("-")
        and next_token not in config.subcommands
    ):
        return 2
    return 1


def _matches_inline_value_option(token: str, value_options: frozenset[str]) -> bool:
    for option in value_options:
        if option.startswith("--") and token.startswith(f"{option}="):
            return True
        if option.startswith("-") and not option.startswith("--") and token.startswith(option) and token != option:
            return True
    return False

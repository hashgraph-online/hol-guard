"""Whether npm's own configuration adds a package to an ``npx`` launch.

``npm exec``, and so ``npx``, takes the packages it installs from its
``package`` setting (``const packages = this.npm.config.get('package')`` in
``lib/commands/exec.js``), not only from ``--package`` on the command line.
npm reads that setting from the environment and from every ``.npmrc`` it
loads. When the setting names a package, libnpmexec skips the walk through the
project's ``node_modules/.bin`` (``needPackageCommandSwap`` is false), installs
what the setting names, and runs the command with that package's bins first
on ``PATH``.

The pinned-runner verdict only reads the command, so protect asks this module
before it drops a package request for ``npx``. Only setting names are read:
a value is never returned, logged or compared.
"""

from __future__ import annotations

import os
from collections.abc import Iterable, Mapping
from pathlib import Path

#: npm matches this prefix without regard to case (``/^npm_config_/i``).
_ENV_PREFIX = "npm_config_"

#: Settings that add a package, or that move npm to a configuration file this
#: check does not otherwise read. A ``.npmrc`` line naming any of them keeps
#: the package review. In the environment only ``package`` does: the other two
#: are followed to the file they name instead.
_PACKAGE_SETTINGS = frozenset({"package", "userconfig", "globalconfig"})

#: The largest ``.npmrc`` read. A larger one keeps the package review rather
#: than being read in part.
MAX_NPMRC_BYTES = 1024 * 1024


def _environment_settings(environment: Mapping[str, str]) -> dict[str, str]:
    """npm's settings from ``environment``, named the way npm names them.

    Mirrors ``loadEnv`` in ``@npmcli/config``: an empty value is skipped,
    every underscore after the first character becomes a hyphen, and the
    name is lowercased. Registry-scoped (``//host/:key``) names are left out
    because none of them is a package setting.
    """

    settings: dict[str, str] = {}
    for key, value in environment.items():
        if value == "" or key[: len(_ENV_PREFIX)].lower() != _ENV_PREFIX:
            continue
        name = key[len(_ENV_PREFIX) :]
        if not name or name.startswith("//"):
            continue
        settings[(name[0] + name[1:].replace("_", "-")).lower()] = value
    return settings


def _setting_name(line: str) -> str | None:
    """The setting a ``.npmrc`` line assigns, or ``None`` for a comment, a
    blank line or a section header."""

    text = line.strip()
    if not text or text[0] in ";#" or (text.startswith("[") and text.endswith("]")):
        return None
    name = text.split("=", 1)[0].strip()
    if len(name) >= 2 and name[0] == name[-1] and name[0] in "\"'":
        name = name[1:-1].strip()
    name = name.removesuffix("[]")
    return name.lower()


def npmrc_sets_package(path: Path) -> bool:
    """Whether the ``.npmrc`` at ``path`` could add a package to ``npx``.

    A missing file adds nothing. A file that cannot be read, or that is
    larger than :data:`MAX_NPMRC_BYTES`, keeps the review. npm expands
    ``${VAR}`` inside setting names, so a name built that way keeps the review
    too: it could expand to ``package``.
    """

    try:
        with path.open("rb") as handle:
            data = handle.read(MAX_NPMRC_BYTES + 1)
    except (FileNotFoundError, NotADirectoryError):
        return False
    except OSError:
        return True
    if len(data) > MAX_NPMRC_BYTES:
        return True
    for line in data.decode("utf-8", errors="replace").lstrip("﻿").splitlines():
        name = _setting_name(line)
        if name is not None and ("${" in name or name in _PACKAGE_SETTINGS):
            return True
    return False


def _home(environment: Mapping[str, str]) -> Path | None:
    for key in ("HOME", "USERPROFILE"):
        value = environment.get(key)
        if value and os.path.isabs(value):
            return Path(value)
    try:
        return Path.home()
    except (RuntimeError, KeyError):
        return None


def _resolve(cwd: Path, value: str) -> Path:
    return cwd / os.path.expanduser(value)


def _candidate_files(environment: Mapping[str, str], settings: Mapping[str, str], cwd: Path) -> Iterable[Path]:
    # npm reads the project's .npmrc from the nearest folder above the working
    # directory that holds a package.json or a node_modules, or from the
    # workspace root above that. Every .npmrc from the working directory up is
    # a superset of both, and costs a handful of stat calls.
    yield from (directory / ".npmrc" for directory in (cwd, *cwd.parents))
    userconfig = settings.get("userconfig")
    if userconfig is not None:
        yield _resolve(cwd, userconfig)
    else:
        home = _home(environment)
        if home is not None:
            yield home / ".npmrc"
    globalconfig = settings.get("globalconfig")
    if globalconfig is not None:
        yield _resolve(cwd, globalconfig)


def npm_config_adds_package(*, environment: Mapping[str, str], cwd: Path) -> bool:
    """Whether npm's configuration, as ``npx`` would load it from ``cwd`` with
    ``environment``, names a package for ``npm exec`` to install.

    Out of scope: the global ``npmrc`` under npm's install prefix when no
    ``npm_config_globalconfig`` names it, and npm's builtin ``npmrc``. Both
    sit beside the npm install itself, and finding them means resolving
    which node and npm the launch would run.
    """

    settings = _environment_settings(environment)
    if "package" in settings:
        return True
    files = dict.fromkeys(_candidate_files(environment, settings, cwd))
    return any(npmrc_sets_package(path) for path in files)

"""Let a script-free npm registry install continue without review.

The native edge sends every package install to review because it cannot see
what the install will run. The package evaluator can: an npm 11.9+ install
with ``--ignore-scripts --allow-git=none``, or an older npm install with
``--ignore-scripts`` whose dependency tree registry metadata proves free of git
dependencies, only writes registry package files, and a target that resolves
on the public registry is identified well enough to continue. This module
proves which npm the agent will run, hands the request to the evaluator, and
settles the review from its verdict.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shlex
import shutil
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING, cast

from ..hook_execution_environment import HOOK_EXECUTION_ENVIRONMENT_KEY, LIBRARY_SEARCH_PATH_NAMES
from ..native_supply_chain_registry_cache import RegistryDeadlineError, registry_wait_deadline
from .hook_fail_closed import render_pre_tool
from .hook_request_parsing import pre_tool_command

if TYPE_CHECKING:
    from ..runtime.package_request_evaluation import PackageRequestEvaluation
    from ..store import GuardStore

_LOGGER = logging.getLogger(__name__)

PACKAGE_REVIEW_REASON = "native_package_review"
LIFECYCLE_SCRIPTS_ENABLED_CODE = "package_lifecycle_scripts_enabled"
VERIFIED_NPM_VERSION_KEY = "verified_npm_version"
REGISTRY_STILL_LOADING_REASON = (
    "HOL Guard is still fetching registry metadata for this install. Run the same command again."
)

# One plain command: no expansion, quoting, globbing, redirection or chaining.
# A word may not start with `~` or `=`, which shells expand to paths.
_WORD = r"[A-Za-z0-9@/._^:+,-][A-Za-z0-9@/._~^:=+,-]*"
_SIMPLE_COMMAND = re.compile(rf"{_WORD}(?: +{_WORD})*")
# Agents trim install output with `2>&1 | tail -3`. These filters read only
# the pipe: none takes a file operand, and a grep pattern may not start with
# `-`, so it cannot name a pattern file.
_PATTERN = r"[A-Za-z0-9@/._^:+,][A-Za-z0-9@/._~^:=+,-]*"
_OUTPUT_FILTER = rf"(?:tail|head)(?: +-[0-9]+| +-n *[0-9]+)?|grep(?: +-[iEFvcnw]+)* +{_PATTERN}"
_FILTERED_COMMAND = re.compile(
    rf"(?P<command>{_SIMPLE_COMMAND.pattern})(?: +2>&1)?(?P<filters>(?: *\| *(?:{_OUTPUT_FILTER}))*)"
)
_MAX_PACKAGE_JSON_BYTES = 256 * 1024
_MAX_NPMRC_BYTES = 64 * 1024
# npm settings that move where packages come from or how transport is trusted.
# The evaluator checks the project `.npmrc`; these are the files above it.
# `prefix` is left out: outside the command line it only moves global installs.
_FETCH_REDIRECTING_KEYS = frozenset(
    {
        "registry",
        "replace-registry-host",
        "strict-ssl",
        "ca",
        "cafile",
        "proxy",
        "https-proxy",
        "http-proxy",
        "noproxy",
        "no-proxy",
        "global",
        "location",
        "globalconfig",
        "userconfig",
    }
)
# Settings that change what npm or node load before the command line is read,
# where npm finds its global config, or whether node checks certificates at
# all. NODE_EXTRA_CA_CERTS only adds a trusted CA, usually a company's
# TLS-inspecting proxy, and leaves the registry where it was.
_ENVIRONMENT_OVERRIDES = ("npm_config_", "node_options", "node_path")
_ENVIRONMENT_NAMES = frozenset({"prefix", "destdir", "node_tls_reject_unauthorized"})
# npm settings that only say where npm keeps its own cache and how it reports.
# They leave the registry, transport trust and what runs where they were.
# Developer shells and `npx` launches export `npm_config_cache`.
_INERT_NPM_SETTINGS = frozenset({"cache", "update-notifier", "fund", "audit", "loglevel", "progress", "color"})


def native_package_review_response(
    store: object,
    *,
    harness: str,
    payload: Mapping[str, object],
    native_result: Mapping[str, object],
    workspace: Path | None,
    guard_home: Path,
    home_dir: Path | None = None,
    deadline: float | None = None,
) -> dict[str, object] | None:
    """The settled response for a package review, or ``None`` to keep reviewing."""

    if (
        os.name == "nt"
        or workspace is None
        or native_result.get("reason_code") != PACKAGE_REVIEW_REASON
        or native_result.get("minimum_action") != "review"
    ):
        return None
    command = pre_tool_command(payload)
    shape = _FILTERED_COMMAND.fullmatch(command.strip()) if command else None
    if shape is None:
        return None
    tokens = shape.group("command").split()
    if tokens[0] != "npm":
        return None
    environment = payload.get(HOOK_EXECUTION_ENVIRONMENT_KEY)
    version = verified_npm_version(environment, workspace=workspace)
    if version is None or not _filters_outside_workspace(shape.group("filters"), environment, workspace):
        return None
    try:
        with registry_wait_deadline(deadline):
            evaluation = _evaluate(
                store,
                harness=harness,
                tokens=tokens,
                version=version,
                workspace=workspace,
                guard_home=guard_home,
                home_dir=home_dir,
                deadline=deadline,
            )
    except RegistryDeadlineError:
        # The download continues in the background and the next attempt reads
        # it from the cache. Nothing ran, so stopping quietly costs one retry.
        return _blocked(native_result, REGISTRY_STILL_LOADING_REASON, harness, guard_home, deadline)
    except Exception:
        _LOGGER.warning("Package evaluation failed for a native package review", exc_info=True)
        return None
    if evaluation is None:
        return None
    if evaluation.decision == "allow" or _script_free_watch(evaluation):
        allowed = dict(native_result)
        allowed.update(decision="allow", minimum_action="allow", policy_action="allow")
        # The evaluator settled this; no saved approval was reused.
        return render_pre_tool(harness, allowed, guard_home=guard_home, deadline=deadline)
    guidance = next(
        (
            str(reason.get("message"))
            for reason in evaluation.reasons
            if reason.get("code") == LIFECYCLE_SCRIPTS_ENABLED_CODE and reason.get("message")
        ),
        None,
    )
    if evaluation.decision == "block":
        reason = _first_message(evaluation.reasons) or "HOL Guard blocked this package install."
    elif evaluation.decision == "ask" and guidance is not None:
        reason = guidance
    else:
        return None
    return _blocked(native_result, reason, harness, guard_home, deadline)


def _blocked(
    native_result: Mapping[str, object], reason: str, harness: str, guard_home: Path, deadline: float | None
) -> dict[str, object]:
    blocked = dict(native_result)
    blocked.update(decision="deny", minimum_action="block", policy_action="block", reason=reason)
    response = render_pre_tool(harness, blocked, guard_home=guard_home, deadline=deadline)
    response["prompted"] = False
    return response


def _filters_outside_workspace(filters: str, environment: object, workspace: Path) -> bool:
    """Whether each output filter resolves to a program outside the workspace.

    A workspace could otherwise put its own `tail` on ``PATH`` ahead of the
    real one and run code through an install that never runs package code.
    """

    names = {segment.split()[0] for segment in filters.split("|") if segment.strip()}
    if not names:
        return True
    search_path = environment.get("path") if isinstance(environment, Mapping) else None
    if not isinstance(search_path, str) or not search_path:
        return False
    try:
        root = workspace.resolve(strict=True)
        programs = [_resolve_executable(name, search_path) for name in names]
    except (OSError, RuntimeError):
        return False
    return all(program is not None and not program.is_relative_to(root) for program in programs)


def _script_free_watch(evaluation: PackageRequestEvaluation) -> bool:
    """Whether every package is watched only because no package code runs."""
    return (
        evaluation.decision == "monitor"
        and bool(evaluation.packages)
        and all(package.get("scriptFreeRegistryInstall") is True for package in evaluation.packages)
    )


def _evaluate(
    store: object,
    *,
    harness: str,
    tokens: list[str],
    version: str,
    workspace: Path,
    guard_home: Path,
    home_dir: Path | None,
    deadline: float | None,
) -> PackageRequestEvaluation | None:
    from ..local_supply_chain import evaluate_package_request_artifact
    from ..runtime.package_intent_common import build_package_request_artifact
    from ..runtime.package_intent_parser import parse_package_intent

    intent = parse_package_intent(
        shlex.join(tokens),
        workspace=workspace,
        home_dir=home_dir,
        guard_home=guard_home,
        deadline=deadline,
    )
    # The evaluator reads the redacted command, so it must be the command
    # that runs, token for token.
    if (
        intent is None
        or intent.package_manager != "npm"
        or intent.intent_kind != "install"
        or intent.local_executions
        or list(intent.command_tokens) != tokens
        or shlex.split(intent.redacted_command) != tokens
    ):
        return None
    artifact = build_package_request_artifact(
        harness,
        intent,
        config_path="hol-guard.toml",
        source_scope="project",
        guard_home=guard_home,
        deadline_monotonic=deadline,
    )
    artifact = replace(artifact, metadata={**artifact.metadata, VERIFIED_NPM_VERSION_KEY: version})
    return evaluate_package_request_artifact(
        artifact=artifact, store=cast("GuardStore", store), workspace_dir=workspace
    )


def _first_message(reasons: tuple[dict[str, object], ...]) -> str | None:
    return next((str(reason["message"]) for reason in reasons if reason.get("message")), None)


def verified_npm_version(environment: object, *, workspace: Path) -> str | None:
    """The version of the npm the agent's ``PATH`` runs, or ``None``.

    Only a standard npm install qualifies: ``npm`` resolves through absolute
    ``PATH`` entries to ``npm/bin/npm-cli.js`` inside a package named npm,
    neither npm nor node comes from the workspace, and no environment setting
    changes what npm or node load. Shims and wrappers fail closed because
    their version cannot be read without running them.
    """

    if not isinstance(environment, Mapping):
        return None
    names = environment.get("environment_names")
    if not isinstance(names, list) or any(not isinstance(name, str) or _changes_npm(name) for name in names):
        return None
    search_path = environment.get("path")
    if not isinstance(search_path, str) or not search_path:
        return None
    try:
        root = workspace.resolve(strict=True)
        if not _loader_paths_outside(names, environment.get("library_search_paths"), root):
            return None
        npm = _resolve_executable("npm", search_path)
        node = _resolve_executable("node", search_path)
        if npm is None or node is None or any(path.is_relative_to(root) for path in (npm, node)):
            return None
        if npm.name != "npm-cli.js" or npm.parent.name != "bin":
            return None
        package_json = npm.parent.parent / "package.json"
        if package_json.stat().st_size > _MAX_PACKAGE_JSON_BYTES:
            return None
        manifest = json.loads(package_json.read_text(encoding="utf-8"))
    except (OSError, RuntimeError, ValueError):
        return None
    if not isinstance(manifest, dict) or manifest.get("name") != "npm":
        return None
    # Without an absolute HOME the user config cannot be located, so it
    # cannot be shown not to move the fetch.
    home = environment.get("home")
    if not isinstance(home, str) or not os.path.isabs(home):
        return None
    config_files = [npm.parent.parent / "npmrc", node.parent.parent / "etc" / "npmrc", Path(home) / ".npmrc"]
    if any(_npmrc_redirects_fetch(path) for path in config_files):
        return None
    version = manifest.get("version")
    return version if isinstance(version, str) and version else None


def _changes_npm(name: str) -> bool:
    """Whether an environment variable may change what npm or node load or fetch."""

    lowered = name.lower()
    if lowered.startswith("npm_config_"):
        # npm reads `npm_config_update_notifier` as `update-notifier`.
        return lowered.removeprefix("npm_config_").replace("_", "-") not in _INERT_NPM_SETTINGS
    return lowered.startswith(_ENVIRONMENT_OVERRIDES) or lowered in _ENVIRONMENT_NAMES


def _loader_paths_outside(names: list[str], stamped: object, root: Path) -> bool:
    """Whether every exported loader search path stays out of the workspace.

    The same search path reaches `npm test` and every other process the agent
    starts without review, so refusing it only for the install adds an
    approval without keeping a planted library out. A relative or empty entry
    searches the working directory, and an entry inside the workspace names a
    directory the agent writes, so those still fail closed. A loader variable
    exported without its stamped value cannot be checked and fails closed too.
    """

    paths = stamped if isinstance(stamped, Mapping) else {}
    for name in LIBRARY_SEARCH_PATH_NAMES:
        if name not in names and name not in paths:
            continue
        value = paths.get(name)
        if not isinstance(value, str) or not value:
            return False
        for entry in value.split(":"):
            if not os.path.isabs(entry) or Path(os.path.realpath(entry)).is_relative_to(root):
                return False
    return True


def _npmrc_redirects_fetch(path: Path) -> bool:
    """Whether an npm config file may change the fetch; unreadable counts."""

    try:
        if not path.exists():
            return False
        if not path.is_file() or path.stat().st_size > _MAX_NPMRC_BYTES:
            return True
        text = path.read_text(encoding="utf-8")
    except (OSError, ValueError):
        return True
    for line in text.splitlines():
        key = line.split("=", 1)[0].strip()
        if key.startswith(("#", ";")):
            continue
        key = key.strip("\"'").lower()
        if key.endswith(":registry") or key in _FETCH_REDIRECTING_KEYS:
            return True
    return False


def _resolve_executable(name: str, search_path: str) -> Path | None:
    """Resolve ``name`` the way a shell would, refusing relative entries.

    A relative or empty ``PATH`` entry is searched from the working directory,
    so one ahead of the match could pick a different executable per cwd.
    """

    for entry in search_path.split(os.pathsep):
        if not entry or not os.path.isabs(entry):
            return None
        found = shutil.which(name, path=entry)
        if found is not None:
            return Path(found).resolve(strict=True)
    return None

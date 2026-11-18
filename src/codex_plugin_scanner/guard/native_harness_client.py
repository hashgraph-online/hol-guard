"""The thin client every native harness operation goes through.

The ``harness_adapter`` runner-authority kind owns every harness's paths, detection, command lookup, install and
uninstall plans, manifests, launch environment, runtime probe fields and approval flow. This module sends a request
with the context only this process knows and raises the error the runtime's answer names.
"""

from __future__ import annotations

import os
from dataclasses import replace
from functools import cache
from pathlib import Path
from typing import Any

from .command_probes import command_probes_enabled
from .harness_context import HarnessContext
from .native_caller import caller_identity

_KIND = "harness_adapter"


#: ``(harness, aliases, launcher_name)`` in registry order. The runtime's
#: ``describe`` answer carries the same identity; a test keeps them in step,
#: so building the registry never needs a resident call.
NATIVE_HARNESSES: tuple[tuple[str, tuple[str, ...], str], ...] = (
    ("devin", ("devin", "devin-cli", "cognition-devin"), "devin"),
    ("antigravity", (), ""),
    ("gemini", (), ""),
    ("kimi", ("kimi", "kimi-code", "kimi-cli"), "kimi"),
    ("openclaw", (), ""),
    ("paseo", (), ""),
    ("muse", ("muse", "muse-code"), "muse"),
    ("grok", ("grok-build", "grok-build-cli", "xai-grok"), "grok"),
    ("zcode", ("zcode", "zai", "z-code", "zai-zcode"), "zcode"),
    ("pi", ("pi", "pi-agent", "pi-coding-agent"), "pi"),
    ("omp", ("omp", "oh-my-pi"), "omp"),
    ("opencode", (), ""),
    ("cline", ("cline-cli", "cline-vscode"), "cline"),
    ("copilot", (), ""),
    ("cursor", (), "cursor-agent"),
    ("claude-code", ("claude",), "claude"),
    ("hermes", (), ""),
    ("codex", (), ""),
)


#: The order ``list_harnesses`` answers in: Codex first, then the rest as the product names them.
HARNESS_ORDER: tuple[str, ...] = (
    "codex",
    "claude-code",
    "copilot",
    "cursor",
    "cline",
    "devin",
    "antigravity",
    "gemini",
    "grok",
    "hermes",
    "kimi",
    "omp",
    "pi",
    "openclaw",
    "opencode",
    "zcode",
    "paseo",
    "muse",
)

#: Ops that render a Pi-family extension, so they carry this process's facts.
_EXTENSION_OPS = frozenset(
    {
        "apply_install",
        "prepare_install",
        "prepare_uninstall",
        "apply_uninstall",
        "extension_source",
        "extension_current",
        "legacy_omp_verified",
    }
)


class HookOwnershipError(RuntimeError):
    """The native runtime could not say which hook commands Guard wrote."""


@cache
def describe() -> dict[str, Any]:
    """The runtime's description of every adapter it answers."""
    from .native_runner_authority import native_runner_authority

    answer = native_runner_authority(_KIND, {"op": "describe"})
    if not isinstance(answer.get("adapters"), list):
        raise ValueError("Harness adapter description is malformed")
    return answer


def _description(harness: str) -> dict[str, Any]:
    for adapter in describe()["adapters"]:
        if isinstance(adapter, dict) and adapter.get("harness") == harness:
            return adapter
    raise ValueError(f"Unsupported harness: {harness}")


def request_environment() -> dict[str, str]:
    """The variables the runtime reads, and nothing else from this process."""
    description = describe()
    names = set(description.get("env_names", ()))
    prefixes = tuple(description.get("env_prefixes", ()))
    return {name: value for name, value in os.environ.items() if name in names or name.startswith(prefixes)}


def wire_context(context: HarnessContext) -> dict[str, object]:
    """The context a ``harness_adapter`` request carries."""
    try:
        cwd: str | None = os.getcwd()
    except OSError:
        paths = (context.home_dir, context.guard_home, context.workspace_dir)
        if any(path is not None and not path.is_absolute() for path in paths):
            raise
        cwd = None
    return {
        "home": str(context.home_dir),
        "workspace": None if context.workspace_dir is None else str(context.workspace_dir),
        "guard_home": str(context.guard_home),
        "home_override_explicit": bool(getattr(context, "home_override_explicit", False)),
        "cwd": cwd,
        "user_home": str(Path.home()),
        "env": request_environment(),
        "executable_overrides": dict(getattr(context, "executable_overrides", {}) or {}),
        "caller": caller_identity(),
        "probes": command_probes_enabled(),
    }


def ask(
    op: str,
    context: HarnessContext,
    *,
    harness: str | None = None,
    timeout_seconds: float | None = None,
    resident_home: Path | None = None,
    deadline_monotonic: float | None = None,
    **fields: object,
) -> dict[str, Any]:
    """Run one op and raise the error the Python adapter raised for a refusal.

    ``resident_home`` names the home whose resident answers (the ambient one when omitted; ``guard_home``
    stays an ordinary request field) and
    ``deadline_monotonic`` only ever shortens the call.
    """
    from .native_runner_authority import native_runner_authority

    request: dict[str, object] = {"op": op, "context": wire_context(context), **fields}
    if harness is not None:
        request["harness"] = harness
    bounds: dict[str, Any] = {}
    if resident_home is not None:
        bounds["guard_home"] = resident_home
    if deadline_monotonic is not None:
        bounds["deadline_monotonic"] = deadline_monotonic
    answer = native_runner_authority(_KIND, request, timeout_seconds=timeout_seconds, **bounds)
    if answer.get("ok") is False and "failure" in answer:
        # An install op that ran as the owner of the Guard home answers its failure in the owned shape.
        from .native_failure import failure_from_answer

        raise failure_from_answer(answer)
    if len(answer) == 1:
        raise_failure(answer)
    return answer


def _surface(surface: str | None) -> dict[str, object]:
    """The surface field, left out so the runtime applies the harness default."""
    return {} if surface is None else {"surface": surface}


def raise_failure(answer: dict[str, Any]) -> None:
    """Raise the error a one-key failure answer names; return for any other answer."""
    if "refusal" in answer:
        raise ValueError(str(answer["refusal"]))
    if "os_error" in answer:
        raise OSError(str(answer["os_error"]))
    if "not_found" in answer:
        raise FileNotFoundError(str(answer["not_found"]))
    if "runtime_error" in answer:
        raise RuntimeError(str(answer["runtime_error"]))
    if "integrity" in answer:
        from .codex_hook_recovery import _error

        raise _error(str(answer["integrity"]))


def _text(answer: dict[str, Any], key: str) -> str:
    value = answer.get(key)
    if not isinstance(value, str):
        raise ValueError("Harness adapter answer is malformed")
    return value


def _native_context(context: HarnessContext) -> HarnessContext:
    """Paseo installs for the daemon user, not the caller's current worktree."""
    return replace(context, workspace_dir=None, workspace_override_explicit=False)


def canonical_harness(name: str) -> str:
    """The harness a name or alias stands for."""
    for harness, aliases, _launcher in NATIVE_HARNESSES:
        if name == harness or name in aliases:
            return harness
    raise ValueError(f"Unsupported harness: {name}")


def owned_ask(harness: str, owned: object, op: str, context: HarnessContext, **fields: Any) -> dict[str, Any]:
    """``ask``, naming a hook-ownership failure as the harness's spec words it."""
    from .native_runner_authority import NativeRunnerAuthorityError

    if not isinstance(owned, dict):
        return ask(op, context, harness=harness, **fields)
    message = str(owned["message"])
    try:
        return ask(op, context, harness=harness, **fields)
    except NativeRunnerAuthorityError as error:
        if op in owned["ops"]:
            raise HookOwnershipError(message) from error
        raise
    except RuntimeError as error:
        if str(error) == message:
            raise HookOwnershipError(message) from error
        raise


def run_op(harness: str, op: str, context: HarnessContext, **fields: Any) -> dict[str, Any]:
    """One op of ``harness``, with the replies only this process can give answered."""
    spec = _description(harness)
    if op in _EXTENSION_OPS and spec.get("extension"):
        from .extension_runtime import extension_runtime

        fields["runtime"] = extension_runtime()
    answer = owned_ask(harness, spec.get("hook_ownership"), op, context, **fields)
    if answer == {"reply": {"facts": None}} and "facts" not in fields:
        # The daemon URL the hooks reach is only known to this process.
        from .claude_hook_entry import claude_facts

        fields["facts"] = claude_facts(context.guard_home)
        answer = owned_ask(harness, spec.get("hook_ownership"), op, context, **fields)
    return answer

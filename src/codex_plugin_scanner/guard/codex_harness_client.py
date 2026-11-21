"""Codex requests to the native ``harness_adapter`` runtime, and their answers.

The native runtime owns the Codex paths, the hook groups and bridge argv Guard
registers, the hook-group identities a migration compares, the MCP and hook
rewrites of a config, the hook state launch and doctor read, the files an
install plans besides the config, and the proxy test over MCP servers. This
module sends what only this process knows (the home mode, the Guard home, the
caller stamp, the transition journal) and renders what comes back: it builds no
decision of its own.
"""

from __future__ import annotations

import base64
import json
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from .codex_hook_file_integrity import CodexHookIntegrityError
from .codex_hook_integrity import hook_manifest_file
from .codex_hook_manifest import CodexHookManifestSpec
from .config import MAX_APPROVAL_WAIT_TIMEOUT_SECONDS, load_guard_config, resolve_guard_home
from .harness_context import HarnessContext
from .native_harness_client import ask

if TYPE_CHECKING:
    from .runtime_transition import TransitionFile

_MANAGED_HOOK_TIMEOUT_GRACE_SECONDS = 5
_LIVE_STATE_TIMEOUT_SECONDS = 10.0
# A spent budget still needs the runtime to read the files and decide.
_LIVE_STATE_MIN_SECONDS = 5.0
# Publication writes and verifies every file under the resident's lease.
_PUBLISH_TIMEOUT_SECONDS = 60.0


def _codex(op: str, context: HarnessContext, **fields: Any) -> dict[str, Any]:
    return ask(op, context, harness="codex", **fields)


def _reply_text(answer: Mapping[str, object], key: str) -> str:
    value = answer.get(key)
    if not isinstance(value, str):
        raise ValueError("Harness adapter answer is malformed")
    return value


def _b64(data: bytes | None) -> str | None:
    return None if data is None else base64.b64encode(data).decode("ascii")


@dataclass(frozen=True, slots=True)
class CodexSources:
    """One config file and its hooks file, with the scope the runtime names for them."""

    config: Path
    hooks: Path
    scope: str


@dataclass(frozen=True, slots=True)
class CodexPaths:
    """The Codex files the runtime reads: the global pair first, then the workspace's."""

    config: Path
    hooks: Path
    backup: Path
    sources: tuple[CodexSources, ...]


def codex_paths(context: HarnessContext) -> CodexPaths:
    """The runtime's ``paths`` answer for this context."""
    answer = _codex("paths", context)
    pairs = answer.get("pairs")
    if not isinstance(pairs, list) or not pairs:
        raise ValueError("Harness adapter answer is malformed")
    sources = tuple(
        CodexSources(Path(_reply_text(pair, "config")), Path(_reply_text(pair, "hooks")), _reply_text(pair, "scope"))
        for pair in pairs
    )
    return CodexPaths(
        Path(_reply_text(answer, "config")),
        Path(_reply_text(answer, "hooks")),
        Path(_reply_text(answer, "backup")),
        sources,
    )


def guard_proxy_server_names(servers: Mapping[str, object]) -> frozenset[str]:
    """The servers whose launch is a Guard MCP proxy, as the native runtime reads the table."""
    from .native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

    named = {name: server for name, server in servers.items() if isinstance(name, str)}
    if not named:
        return frozenset()
    names = native_runner_authority("codex_install_plan", {"op": "guard_proxies", "servers": named}).get("names")
    if not isinstance(names, list) or not all(isinstance(name, str) and name in named for name in names):
        raise NativeRunnerAuthorityError("Codex install plan answer is malformed")
    return frozenset(names)


def _hook_workspace_dir(context: HarnessContext) -> Path | None:
    return context.workspace_dir if context.workspace_override_explicit else None


def _home_is_current(context: HarnessContext) -> bool:
    return not context.home_override_explicit and context.home_dir.resolve() == Path.home().resolve()


def _runtime_guard_home(context: HarnessContext, *, home_is_current: bool | None = None) -> Path:
    current = _home_is_current(context) if home_is_current is None else home_is_current
    guard_home = resolve_guard_home() if current else context.guard_home
    return guard_home.resolve(strict=False)


def _post_tool_hook_timeout_seconds(context: HarnessContext) -> int:
    configured_wait_timeout = load_guard_config(
        context.guard_home,
        _hook_workspace_dir(context),
        create_home=False,
    ).approval_wait_timeout_seconds
    return (
        min(
            max(configured_wait_timeout, 0),
            MAX_APPROVAL_WAIT_TIMEOUT_SECONDS,
        )
        + _MANAGED_HOOK_TIMEOUT_GRACE_SECONDS
    )


def _launch_facts(context: HarnessContext, *, home_is_current: bool | None = None) -> dict[str, object]:
    """The facts about this launch only this process knows: the home mode and Guard home, the workspace
    mode and the hook timeout. The runtime derives the argv, the native runtime, the interpreter, the package
    paths, the manifest path and the manifest spec from these and the caller stamp."""

    current = _home_is_current(context) if home_is_current is None else home_is_current
    return {
        "home_is_current": current,
        "runtime_guard_home": str(_runtime_guard_home(context, home_is_current=current)),
        "workspace_explicit": context.workspace_override_explicit,
        "long_timeout": _post_tool_hook_timeout_seconds(context),
    }


def _launch_fields(context: HarnessContext, *, home_is_current: bool | None = None) -> dict[str, object]:
    """What the runtime cannot see of this launch, with the manifest path the hook reads."""

    fields = _launch_facts(context, home_is_current=home_is_current)
    guard_home = Path(str(fields["runtime_guard_home"]))
    return {**fields, "manifest_path": str(hook_manifest_file(guard_home, codex_paths(context).config))}


def codex_native_request(context: HarnessContext) -> dict[str, object]:
    """What a native Codex read or plan asks of this process: its facts and the transition budget."""
    from .native_transition_files import _budget, _package_roots

    return {
        "facts": {"codex": codex_install_facts(context)},
        "transition": {"package_roots": _package_roots(), "budget": _budget()},
    }


def raise_untrusted(untrusted: object) -> None:
    """Raise the integrity error for a baseline the runtime refused to trust."""
    from .codex_hook_file_integrity import CodexHookIntegrityError

    if not isinstance(untrusted, Mapping):
        raise CodexHookIntegrityError("native_transition_invalid", "Guard could not read the managed-hook baseline.")
    error = CodexHookIntegrityError(str(untrusted["reason"]), str(untrusted["message"]))
    cause = untrusted.get("cause")
    if isinstance(cause, str):
        raise error from CodexHookIntegrityError(cause, cause)
    raise error


def codex_install_facts(context: HarnessContext) -> dict[str, object]:
    """What the runtime's Codex install and uninstall cannot read: this launch and the installed package's root."""
    from . import codex_hook_self_binding

    return {
        "launch": _launch_facts(context),
        "package_root": str(codex_hook_self_binding.install_package_root()),
    }


def _launch(context: HarnessContext, *, home_is_current: bool) -> dict[str, Any]:
    """The bridge argv with the fallback and daemon start commands it launches through."""

    return _codex("argv", context, **_launch_fields(context, home_is_current=home_is_current))


def _hook_command_parts_for_home_mode(context: HarnessContext, *, home_is_current: bool) -> tuple[str, ...]:
    answer = _launch(context, home_is_current=home_is_current)
    return tuple(str(part) for part in answer["argv"])


def _hook_command_parts(context: HarnessContext) -> tuple[str, ...]:
    return _hook_command_parts_for_home_mode(context, home_is_current=_home_is_current(context))


@dataclass(frozen=True, slots=True)
class _HookRegistration:
    """The argv, groups and manifest bindings of the hooks Guard registers."""

    argv: tuple[str, ...]
    groups: str
    bindings: str


def _hook_registration(context: HarnessContext) -> _HookRegistration:
    argv = _hook_command_parts(context)
    fields: dict[str, object] = {"argv": list(argv), "long_timeout": _post_tool_hook_timeout_seconds(context)}
    answer = _codex("groups", context, **fields)
    return _HookRegistration(argv, _reply_text(answer, "groups"), _reply_text(answer, "bindings"))


def _managed_hook_groups(context: HarnessContext) -> dict[str, dict[str, object]]:
    return json.loads(_hook_registration(context).groups)


def _hook_manifest_spec(context: HarnessContext) -> CodexHookManifestSpec:
    """The installation the runtime expects, as it builds it from this launch."""

    fields: dict[str, object] = {"launch": _launch_fields(context)}
    answer = _codex("manifest_spec", context, **fields)
    spec = answer.get("spec")
    if not isinstance(spec, dict):
        raise ValueError("Harness adapter answer is malformed")
    return CodexHookManifestSpec(
        guard_home=Path(str(spec["guard_home"])),
        home_dir=Path(str(spec["home_dir"])),
        runtime_guard_home=Path(str(spec["runtime_guard_home"])),
        workspace_dir=None if spec["workspace_dir"] is None else Path(str(spec["workspace_dir"])),
        config_path=Path(str(spec["config_path"])),
        interpreter_path=Path(str(spec["interpreter_path"])),
        package_version=str(spec["package_version"]),
        packaged_file_paths=tuple((str(role), Path(str(path))) for role, path in spec["packaged_file_paths"]),
        fallback_argv=tuple(str(part) for part in spec["fallback_argv"]),
        daemon_start_argv=tuple(str(part) for part in spec["daemon_start_argv"]),
        event_bindings=tuple(dict(binding) for binding in spec["event_bindings"]),
        workspace_rebinding_allowed=not context.workspace_override_explicit,
    )


def _plan_file(item: Mapping[str, Any]) -> TransitionFile:
    """One file an ``install_plan`` answer plans."""
    from .runtime_transition import TransitionFile

    return TransitionFile(
        Path(str(item["path"])),
        None if item["before"] is None else base64.b64decode(str(item["before"])),
        None if item["after"] is None else base64.b64decode(str(item["after"])),
        before_mode=int(item["before_mode"]),
        after_mode=int(item["after_mode"]),
        no_follow=bool(item["no_follow"]),
        expected_digest=cast("str | None", item.get("expected_digest")),
        artifact_identity=cast("dict[str, object] | None", item.get("artifact_identity")),
        invocation_identity=cast("dict[str, object] | None", item.get("invocation_identity")),
    )


def _live_budget() -> tuple[float, bool]:
    """Verification gets ten seconds, or what is left of a hook's budget; a
    spent budget leaves the installation unverified."""
    from .codex_hook_file_integrity import active_hook_validation_deadline

    timeout = _LIVE_STATE_TIMEOUT_SECONDS
    deadline = active_hook_validation_deadline()
    if deadline is not None:
        timeout = min(timeout, deadline - time.monotonic())
    return max(timeout, _LIVE_STATE_MIN_SECONDS), timeout <= 0


def live_hook_fields(context: HarnessContext) -> tuple[dict[str, Any], float]:
    """The facts a live hook state op needs, and the time it may take."""
    from .codex_hook_file_integrity import _python_package_roots

    timeout, spent = _live_budget()
    request: dict[str, Any] = {
        "launch": _launch_fields(context),
        "package_roots": [str(root) for root in _python_package_roots()],
        "budget_spent": spent,
    }
    return request, timeout


def live_hook_ask(op: str, context: HarnessContext) -> dict[str, Any]:
    """Ask a live hook state op: the runtime reads the config and hooks files,
    authenticates and verifies the hook manifest, and decides which managed
    events Guard owns."""
    request, timeout = live_hook_fields(context)
    return dict(ask(op, context, harness="codex", timeout_seconds=timeout, **request))


def _group_text(group: object) -> str | None:
    """One hook group as JSON text; the runtime reads what JSON can carry."""
    try:
        return json.dumps(group, allow_nan=False)
    except (TypeError, ValueError, RecursionError):
        return None


def verify_manifest_state(
    spec: CodexHookManifestSpec, *, hooks: object, captured_text: str | None = None
) -> dict[str, object]:
    """The integrity state of the manifest on disk, or of ``captured_text``,
    against ``spec``. The runtime authenticates it under its own key."""
    from .codex_hook_events import MANAGED_CODEX_HOOK_EVENTS
    from .codex_hook_file_integrity import _python_package_roots

    context = HarnessContext(home_dir=spec.home_dir, workspace_dir=spec.workspace_dir, guard_home=spec.guard_home)
    wire_hooks: dict[str, list[str | None]] | None = None
    if isinstance(hooks, dict):
        wire_hooks = {
            event: [_group_text(group) for group in hooks[event]]
            for event in MANAGED_CODEX_HOOK_EVENTS
            if isinstance(hooks.get(event), list)
        }
    timeout, spent = _live_budget()
    try:
        answer = ask(
            "verify_manifest",
            context,
            harness="codex",
            timeout_seconds=timeout,
            spec=spec.payload(),
            hooks=wire_hooks,
            manifest_text=captured_text,
            package_roots=[str(root) for root in _python_package_roots()],
            budget_spent=spent,
        )
    except (TypeError, ValueError, OSError, RuntimeError):
        answer = {}
    state = answer.get("state")
    if not isinstance(state, dict):
        # A runtime that does not answer leaves the installation unverified,
        # never valid; status and doctor report it rather than fail.
        try:
            manifest_text_path = str(hook_manifest_file(spec.guard_home, spec.config_path))
        except CodexHookIntegrityError:
            # The runtime that names the path did not answer either.
            manifest_text_path = ""
        return _unavailable_state(manifest_text_path)
    return dict(state)


_UNAVAILABLE_REASON = "codex_hook_manifest_verification_unavailable"
_UNAVAILABLE_MESSAGE = "Guard could not verify the Codex hook installation; run repair and retry."


def _unavailable_state(manifest_path: str) -> dict[str, object]:
    """The integrity state of an installation the runtime could not verify."""
    from .codex_hook_events import MANAGED_CODEX_HOOK_EVENTS

    return {
        "event_matches": dict.fromkeys(MANAGED_CODEX_HOOK_EVENTS, False),
        "foreign_hook_entries_present": False,
        "foreign_hook_group_count": 0,
        "integrity_message": _UNAVAILABLE_MESSAGE,
        "integrity_reason": _UNAVAILABLE_REASON,
        "integrity_status": "tampered",
        "manifest_schema_version": None,
        "manifest_package_version": None,
        "manifest_generated_at": None,
        "bridge_sha256": None,
        "interpreter_sha256": None,
        "manifest_path": manifest_path,
    }


def codex_native_hook_state(context: HarnessContext) -> dict[str, object]:
    """The live Codex hook state, decided natively."""
    state = json.loads(_reply_text(live_hook_ask("live_hook_state", context), "state"))
    if not isinstance(state, dict):
        raise ValueError("Harness adapter answer is malformed")
    return state

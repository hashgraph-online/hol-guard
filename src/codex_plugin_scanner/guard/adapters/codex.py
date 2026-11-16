"""Codex harness adapter.

The native runtime owns the hook groups and bridge argv Guard registers, the
hook-group identities a migration compares, the MCP and hook rewrites of a
config, the hook state launch and doctor read, and the files an install plans
besides the config. Python keeps the TOML reads and renders, the authenticated
hook manifest, the ownership strips over existing hooks and every publication.
"""

from __future__ import annotations

import base64
import json
import os
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from ...version import __version__
from ..aibom_detection import (
    detection_from_payload,
    extend_codex_runtime_inventory,
    extend_detection_with_workspace_aibom,
    native_adapter_detection_payload,
)
from ..codex_config import _restore_native, _Wire, dump_toml, read_toml_payload
from ..codex_hook_command_line import short_path_facts
from ..codex_hook_compatibility import NATIVE_CODEX_HOOK_FEATURE, python_bridge_argv
from ..codex_hook_integrity import (
    atomic_write_text,
    canonical_manifest_bytes,
    hook_authority_receipt_path,
    hook_manifest_path,
    remove_hook_secret_if_unused,
)
from ..codex_hook_manifest import (
    CodexHookManifestSpec,
    PreparedCodexHookPublication,
    generation_request,
    load_hook_manifest_baseline,
    prepare_authenticated_hook_publication,
)
from ..codex_hook_manifest import (
    manifest_bindings as _manifest_bindings,
)
from ..codex_hook_recovery import (
    recover_hook_publication,
)
from ..codex_hook_registration import (
    codex_doctor_result,
    legacy_binding_fields,
)
from ..codex_hook_self_binding import (
    expanded_short_paths,
    install_fields,
    settle_short_paths,
    short_path_fields,
)
from ..codex_hook_trust import apply_codex_hook_trust_doctor
from ..codex_install_transaction import codex_install_transaction
from ..config import MAX_APPROVAL_WAIT_TIMEOUT_SECONDS, load_guard_config, resolve_guard_home
from ..launcher import merge_guard_launcher_env
from ..models import HarnessDetection
from ..native_codex_hook_identity import wire_codex_hook_bindings as _wire_bindings
from ..native_path_anchor import anchor_to_process_directory
from ..shims import shim_interpreter
from ..stable_guard_cli import resolve_frozen_guard_cli
from .base import HarnessContext, PreparedHarnessInstall
from .codex_detect_sources import path_restorations, read_source_bytes
from .codex_remote_control import (
    codex_remote_launch_environment,
    guarded_codex_launch_command,
    guarded_codex_launch_command_candidates,
    guarded_codex_launch_command_from_prefix,
)
from .mcp_relay_native import mcp_proxy_launch, python_proxy_launch
from .mcp_servers import (
    ManagedMcpServer,
    managed_stdio_servers,
    proxy_launcher_entry,
    skipped_stdio_server_names,
)
from .native_harness import NativeHarnessAdapter, ask, planned_files
from .native_hook_bridge import native_hook_bridge_executable

if TYPE_CHECKING:
    from ..codex_hook_manifest import PreparedCodexHookPublication
    from ..runtime_transition import TransitionFile

__all__ = ("_command_available", "atomic_write_text", "sys")

_read_toml = read_toml_payload

_LEGACY_MANAGED_HOOK_STATUS_MESSAGES = {
    "HOL Guard checking Bash command",
    "HOL Guard checking tool action",
    "HOL Guard checking prompt",
    "HOL Guard checking Codex approval request",
    "HOL Guard checking tool result",
}
_MANAGED_HOOK_TIMEOUT_GRACE_SECONDS = 5
_CODEX_GUARD_TOOL_MATCHER = "Bash|Read|Write|Edit|MultiEdit|^apply_patch$|mcp__.*"
_AUTHORITATIVE_HOOK_UNAVAILABLE_REASON = "codex_authoritative_hook_unavailable"
_LIVE_STATE_TIMEOUT_SECONDS = 10.0
# A spent budget still needs the runtime to read the files and decide.
_LIVE_STATE_MIN_SECONDS = 5.0
# Publication writes and verifies every file under the resident's lease.
_PUBLISH_TIMEOUT_SECONDS = 60.0


def _codex(op: str, context: HarnessContext, **fields: Any) -> dict[str, Any]:
    return ask(op, context, harness="codex", **fields)


def _command_available(context: HarnessContext) -> bool:
    """Whether the Codex CLI is on the caller's PATH or in a user install directory."""

    return _codex("command_available", context).get("available") is True


def _publish_hooks(
    context: HarnessContext, request: Mapping[str, Any], files: Sequence[TransitionFile]
) -> dict[str, Any]:
    """One ``publish_hooks`` request, its journal records replayed."""
    from ..native_transition_files import _replay

    answer = dict(ask("publish_hooks", context, harness="codex", timeout_seconds=_PUBLISH_TIMEOUT_SECONDS, **request))
    _replay(answer.get("events"), files, None)
    return answer


def _publication_fault(fault: object) -> BaseException:
    """The exception a ``publish_hooks`` fault names."""
    from ..native_transition_files import _exception

    if isinstance(fault, Mapping) and isinstance(fault.get("runtime"), str):
        return RuntimeError(fault["runtime"])
    return _exception(fault)


def _reply_text(answer: Mapping[str, object], key: str) -> str:
    value = answer.get(key)
    if not isinstance(value, str):
        raise ValueError("Harness adapter answer is malformed")
    return value


def _hook_workspace_dir(context: HarnessContext) -> Path | None:
    return context.workspace_dir if context.workspace_override_explicit else None


def _json_object(path: Path) -> dict[str, object]:
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _argv_fields(context: HarnessContext, *, home_is_current: bool) -> dict[str, object]:
    guard_home = resolve_guard_home() if home_is_current else context.guard_home
    return {
        "home_is_current": home_is_current,
        "runtime_guard_home": str(guard_home.resolve(strict=False)),
        "workspace_explicit": context.workspace_override_explicit,
    }


def _guard_python_executable() -> str:
    """Use a prune-safe frozen launcher, else the current interpreter identity."""

    if bool(getattr(sys, "frozen", False)):
        return resolve_frozen_guard_cli()
    return str(Path(sys.executable).expanduser().absolute())


def _home_is_current(context: HarnessContext) -> bool:
    return not context.home_override_explicit and context.home_dir.resolve() == Path.home().resolve()


def _runtime_guard_home(context: HarnessContext) -> Path:
    guard_home = resolve_guard_home() if _home_is_current(context) else context.guard_home
    return guard_home.resolve(strict=False)


def _native_bridge_executable(guard_home: Path) -> Path | None:
    return native_hook_bridge_executable(NATIVE_CODEX_HOOK_FEATURE, guard_home=guard_home)


def _frozen_contract() -> bool:
    return globals().get("_HOL_GUARD_FROZEN_CODEX_RUNTIME") is True


def _launch(context: HarnessContext, *, home_is_current: bool, python_executable: str) -> dict[str, Any]:
    """The bridge argv with the fallback and daemon start commands it launches through."""

    fields = _argv_fields(context, home_is_current=home_is_current)
    guard_home = Path(str(fields["runtime_guard_home"]))
    # The native runtime answers each hook from the daemon without starting
    # Python. Without one, the adapter refuses and asks for repair.
    native_bridge = _native_bridge_executable(guard_home)
    return _codex(
        "argv",
        context,
        **fields,
        python=python_executable,
        frozen=_frozen_contract(),
        package_root=str(Path(__file__).resolve().parents[3]),
        native_bridge=None if native_bridge is None else str(native_bridge),
        manifest_path=str(hook_manifest_path(guard_home, CodexHarnessAdapter._hook_config_path(context))),
        long_timeout=_post_tool_hook_timeout_seconds(context),
    )


def _hook_command_parts_for_home_mode(
    context: HarnessContext,
    *,
    home_is_current: bool,
    python_executable: str,
) -> tuple[str, ...]:
    answer = _launch(context, home_is_current=home_is_current, python_executable=python_executable)
    return tuple(str(part) for part in answer["argv"])


def _current_launch(context: HarnessContext) -> dict[str, Any]:
    return _launch(context, home_is_current=_home_is_current(context), python_executable=_guard_python_executable())


def _hook_command_parts(context: HarnessContext) -> tuple[str, ...]:
    return _hook_command_parts_for_home_mode(
        context,
        home_is_current=_home_is_current(context),
        python_executable=_guard_python_executable(),
    )


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


@dataclass(frozen=True, slots=True)
class _HookRegistration:
    """The argv, groups and manifest bindings of the hooks Guard registers."""

    argv: tuple[str, ...]
    groups: str
    bindings: str


def _hook_registration(context: HarnessContext) -> _HookRegistration:
    argv = _hook_command_parts(context)
    environment = merge_guard_launcher_env(pin_package=True)
    environment.update(codex_remote_launch_environment(context.home_dir))
    fields: dict[str, object] = {
        "argv": list(argv),
        "env": json.dumps(environment),
        "long_timeout": _post_tool_hook_timeout_seconds(context),
    }
    answer = _codex("groups", context, **fields)
    if set(answer) == {"reply"}:
        # A Windows path is rendered by its 8.3 name, which only this host knows.
        answer = _codex("groups", context, **fields, short_names=short_path_facts(answer["reply"]["shorten"]))
    return _HookRegistration(argv, _reply_text(answer, "groups"), _reply_text(answer, "bindings"))


def _managed_hook_groups(context: HarnessContext) -> dict[str, dict[str, object]]:
    return json.loads(_hook_registration(context).groups)


def _manifest_event_bindings(context: HarnessContext) -> list[dict[str, object]]:
    return json.loads(_hook_registration(context).bindings)


def _hook_packaged_file_paths(native_bridge: Path) -> tuple[tuple[str, Path], ...]:
    """Each authenticated role's file; ``bridge`` is the native runtime the hook runs."""
    scanner_root = Path(__file__).resolve().parents[2]
    guard_root = Path(__file__).resolve().parents[1]
    return (
        ("bridge", native_bridge.resolve()),
        ("bridge_runtime", guard_root / "codex_hook_bridge_runtime.py"),
        ("hook_probe", guard_root / "runtime_transition_hook_probe.py"),
        ("native_receipt", guard_root / "native_decision_receipt.py"),
        ("fallback_entrypoint", scanner_root / "cli.py"),
        ("daemon_entrypoint", guard_root / "cli" / "daemon_serve.py"),
        ("daemon_manager", guard_root / "native_daemon_manage.py"),
        ("launch_runtime", guard_root / "codex_hook_launch_runtime.py"),
        ("runtime_trust", guard_root / "codex_hook_runtime_trust.py"),
        ("windows_job", guard_root / "codex_hook_windows_job.py"),
    )


def _hook_manifest_spec(context: HarnessContext) -> CodexHookManifestSpec:
    launch = _current_launch(context)
    return CodexHookManifestSpec(
        guard_home=context.guard_home,
        home_dir=context.home_dir,
        runtime_guard_home=_runtime_guard_home(context),
        workspace_dir=_hook_workspace_dir(context),
        config_path=CodexHarnessAdapter._hook_config_path(context),
        interpreter_path=Path(_guard_python_executable()),
        package_version=__version__,
        packaged_file_paths=_hook_packaged_file_paths(Path(str(launch["argv"][0]))),
        fallback_argv=tuple(str(part) for part in launch["fallback"]),
        daemon_start_argv=tuple(str(part) for part in launch["start"]),
        event_bindings=tuple(_manifest_event_bindings(context)),
        workspace_rebinding_allowed=not context.workspace_override_explicit,
    )


def _legacy_fields(context: HarnessContext, registration: _HookRegistration | None = None) -> dict[str, Any]:
    """What an exact current bridge entry is matched against for legacy re-adoption."""

    registration = registration or _hook_registration(context)
    current_argv = list(registration.argv)
    # python_bridge_argv keeps the object sequence it was given. This argv is
    # a string command, so only those strings identify the legacy registration.
    legacy_tail = [part for part in python_bridge_argv(current_argv)[1:] if isinstance(part, str)]
    return legacy_binding_fields(
        expected_bindings=json.loads(registration.bindings),
        current_argv=current_argv,
        legacy_argv=[sys.executable, *legacy_tail],
        legacy_status_messages=_LEGACY_MANAGED_HOOK_STATUS_MESSAGES,
    )


def _one_planned_file(answer: dict[str, Any]) -> TransitionFile:
    return planned_files({"files": [answer["file"]]})[0]


def _b64(data: bytes | None) -> str | None:
    return None if data is None else base64.b64encode(data).decode("ascii")


def _check_sources(
    context: HarnessContext,
    pairs: Sequence[tuple[Path, Path]],
    captured: Mapping[Path, bytes | None] | None = None,
) -> None:
    """Refuse a config or hooks source that is not a readable regular file or
    does not parse strictly; captured bytes are checked as they were captured."""
    sources: list[dict[str, object]] = []
    for config, hooks in pairs:
        for path, label, kind in ((config, "Codex config file", "toml"), (hooks, "Codex hooks file", "json")):
            source: dict[str, object] = {"path": str(path), "label": label, "kind": kind}
            if captured is not None:
                source["data"] = _b64(captured[path])
            sources.append(source)
    _codex("check_sources", context, sources=sources)


@dataclass(frozen=True, slots=True)
class PreparedCodexHookMigration:
    """Captured JSON migration segment; publication requires the complete install."""

    config_payload: dict[str, object]
    files: tuple[TransitionFile, ...]


def _withdraw_publication(context: HarnessContext, publication: PreparedCodexHookPublication) -> None:
    """Publish a committed hook generation's inverse, as long as nobody changed it since."""

    inverse = tuple(
        replace(
            change,
            before=change.after,
            after=change.before,
            before_mode=change.after_mode,
            after_mode=change.before_mode,
        )
        for change in publication.files
    )
    try:
        PreparedHarnessInstall(inverse, {}).publish(context.guard_home, removals=True)
        remove_hook_secret_if_unused(context.guard_home)
    except BaseException as error:
        raise RuntimeError(
            "codex_hook_migration_rollback_failed: Guard could not fully restore Codex hook sources after "
            "legacy JSON removal failed. Run `hol-guard install codex` to repair the installation."
        ) from error


@dataclass(frozen=True, slots=True)
class _CodexInstallPlan:
    """A prepared install, with what publishing it as an ordinary install needs."""

    prepared: PreparedHarnessInstall
    publication: PreparedCodexHookPublication
    backups: frozenset[Path]
    shim_manifest: Mapping[str, object]
    fields: dict[str, object]


def prepare_codex_hook_migration(
    context: HarnessContext,
    *,
    config_path: Path,
    hooks_path: Path,
    owned_bindings: Sequence[Mapping[str, object]] = (),
    require_owners: bool = False,
) -> PreparedCodexHookMigration:
    """Fold one ``hooks.json`` into its ``config.toml``, as the native
    ``hook_migration`` op plans it: the config rewrite, the retired JSON
    source and a backup of the config it replaces."""
    from ..runtime_transition import RuntimeTransition

    request: dict[str, Any] = {
        "config": str(config_path),
        "hooks": str(hooks_path),
        "owned": json.dumps(list(owned_bindings), separators=(",", ":")),
        "require_owners": require_owners,
        **_legacy_fields(context),
        **install_fields(_runtime_guard_home(context), None),
        **short_path_fields(),
    }
    answer = settle_short_paths(lambda: _codex("hook_migration", context, **request), request, "hook_migration")
    tokens = answer.get("tokens")
    if not isinstance(tokens, dict):
        raise ValueError("Harness adapter answer is malformed")
    config = _restore_native(json.loads(_reply_text(answer, "config")), tokens)
    if not isinstance(config, dict):
        raise ValueError("Harness adapter answer is malformed")
    files = planned_files({"files": answer.get("files")})
    RuntimeTransition._compare({"files": [change.payload() for change in files]}, "before")
    return PreparedCodexHookMigration(config, tuple(files))


def _relaunch(asked: Mapping[str, object]) -> dict[str, object]:
    """Each Guard proxy's launch, the way this process would write it."""
    python = _guard_python_executable()
    relaunch: dict[str, object] = {}
    for name, args in asked.items():
        _, python_args = python_proxy_launch(None, tuple(str(arg) for arg in cast(Sequence[object], args)))
        launcher, launch_args = mcp_proxy_launch(python, python_args)
        relaunch[str(name)] = [launcher, list(launch_args)]
    return relaunch


def _plan_file(item: Mapping[str, Any]) -> TransitionFile:
    """One file an ``install_plan`` answer plans."""
    from ..runtime_transition import TransitionFile

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


def _ask_install_plan(context: HarnessContext, request: dict[str, Any], enroll_home: Path | None) -> dict[str, Any]:
    """One ``install_plan`` answer, asked again with each reply it needs.

    An enrolling plan may create the hook key, so it runs under the key's
    ordinary writer, as the generation always has."""
    from ..codex_hook_file_integrity import check_hook_validation_deadline
    from ..codex_hook_integrity import _ordinary_hook_writer, hook_secret_path
    from ..native_transition_files import _budget, _exception, _package_roots, _replay
    from ..runtime_transition import TransitionError

    request["package_roots"] = _package_roots()
    request["budget"] = _budget()
    for _ in range(4):
        check_hook_validation_deadline()
        if enroll_home is None:
            answer = ask("install_plan", context, harness="codex", timeout_seconds=_PUBLISH_TIMEOUT_SECONDS, **request)
        else:
            with _ordinary_hook_writer(enroll_home, hook_secret_path(enroll_home), actor="codex.authority-key"):
                answer = ask(
                    "install_plan", context, harness="codex", timeout_seconds=_PUBLISH_TIMEOUT_SECONDS, **request
                )
        reply = answer.get("reply")
        if not isinstance(reply, Mapping):
            break
        if "relaunch" in reply:
            request["relaunch"] = _relaunch(cast(Mapping[str, object], reply["relaunch"]))
        if "expand" in reply:
            request["long_paths"] = {**request.get("long_paths", {}), **expanded_short_paths(reply)}
    else:
        raise RuntimeError("install_plan did not settle its replies")
    check_hook_validation_deadline()
    _replay(answer.get("events"), None, None)
    if answer.get("conflict") is True:
        raise TransitionError("adapter_preparation_generation_conflict")
    if "fault" in answer:
        raise _exception(answer["fault"])
    return answer


def render_codex_managed_mcp(
    context: HarnessContext,
    payload: dict[str, object],
    *,
    managed_servers: tuple[ManagedMcpServer, ...],
    workspace_payload: dict[str, object],
) -> tuple[dict[str, object], tuple[str, ...]]:
    """Render proxy refresh and workspace precedence from captured payloads."""
    adapter = CodexHarnessAdapter()
    entries = [(server, adapter._proxy_server_entry(context, server)) for server in managed_servers]
    wire = _Wire(payload, workspace_payload, *(entry for _server, entry in entries))
    fields: dict[str, object] = {
        "payload": wire.text(payload),
        "workspace_payload": None if context.workspace_dir is None else wire.text(workspace_payload),
        "servers": [
            {"name": server.name, "source_scope": server.source_scope, "entry": wire.text(entry)}
            for server, entry in entries
        ],
    }
    answer = _codex("managed_mcp", context, **fields)
    if set(answer) == {"reply"}:
        answer = _codex("managed_mcp", context, **fields, relaunch=_relaunch(answer["reply"]["relaunch"]))
    rendered = wire.decode(_reply_text(answer, "rendered"))
    return rendered, tuple(str(name) for name in answer["migrated"])


def prepare_codex_alternate_cleanup(
    context: HarnessContext,
    *,
    config_path: Path,
    remove_hooks: bool = True,
    managed_server_names: Sequence[str] = (),
) -> TransitionFile:
    """Capture one cleanup segment; this is not a complete Codex install plan."""
    from ..runtime_transition import RuntimeTransition

    request: dict[str, Any] = {
        "config": str(config_path),
        "remove_hooks": remove_hooks,
        "managed_server_names": list(managed_server_names),
        **_legacy_fields(context),
        **install_fields(_runtime_guard_home(context), None),
        **short_path_fields(),
    }
    answer = settle_short_paths(lambda: _codex("alternate_change", context, **request), request, "alternate_change")
    change = _one_planned_file(answer)
    RuntimeTransition._compare({"files": [change.payload()]}, "before")
    return change


def _payload_has_hooks_feature_enabled(config_payload: Mapping[str, object]) -> bool:
    features = config_payload.get("features")
    if not isinstance(features, Mapping):
        return True
    return features.get("hooks") is not False


def prepare_codex_shell_cleanup(context: HarnessContext) -> tuple[TransitionFile, ...]:
    """Capture all legacy shell removals without reading through symlinks or publishing."""
    from ..runtime_transition import RuntimeTransition

    files = tuple(planned_files(_codex("shell_cleanup", context)))
    RuntimeTransition._compare({"files": [change.payload() for change in files]}, "before")
    return files


def live_hook_ask(op: str, context: HarnessContext) -> dict[str, Any]:
    """Ask a live hook state op: the runtime reads the config and hooks files,
    authenticates and verifies the hook manifest, and decides which managed
    events Guard owns."""
    from ..codex_hook_file_integrity import _python_package_roots, active_hook_validation_deadline
    from ..codex_hook_manifest import _spec_payload

    # Verification gets ten seconds, or what is left of a hook's budget; a
    # spent budget leaves the installation unverified.
    timeout = _LIVE_STATE_TIMEOUT_SECONDS
    deadline = active_hook_validation_deadline()
    if deadline is not None:
        timeout = min(timeout, deadline - time.monotonic())
    request: dict[str, Any] = {
        "spec": _spec_payload(_hook_manifest_spec(context)),
        "package_roots": [str(root) for root in _python_package_roots()],
        "budget_spent": timeout <= 0,
        **short_path_fields(),
    }
    timeout = max(timeout, _LIVE_STATE_MIN_SECONDS)
    return settle_short_paths(
        lambda: ask(op, context, harness="codex", timeout_seconds=timeout, **request),
        request,
        op,
    )


def codex_native_hook_state(context: HarnessContext) -> dict[str, object]:
    """The live Codex hook state, decided natively."""
    state = json.loads(_reply_text(live_hook_ask("live_hook_state", context), "state"))
    if not isinstance(state, dict):
        raise ValueError("Harness adapter answer is malformed")
    return state


def _require_codex_authoritative_shell_hook(context: HarnessContext) -> None:
    hook_state = codex_native_hook_state(context)
    if bool(hook_state["shell_protection_active"]):
        return
    raise RuntimeError(
        f"{_AUTHORITATIVE_HOOK_UNAVAILABLE_REASON}: Guard refused to launch Codex because the managed "
        "PreToolUse and PermissionRequest hooks are missing or disabled. Run `hol-guard install codex` "
        "or `hol-guard update` to repair the native-hook enforcement boundary."
    )


def _located(path: Path) -> Path:
    return path.parent.resolve(strict=False) / path.name


def _install_manifest(
    context: HarnessContext, kind: str, shim_manifest: Mapping[str, object], **fields: object
) -> dict[str, object]:
    fields.setdefault("hooks_path", str(CodexHarnessAdapter._hooks_path(context)))
    answer = _codex(
        "manifest",
        context,
        kind=kind,
        shim=json.dumps(shim_manifest),
        config_path=str(CodexHarnessAdapter._target_config_path(context)),
        hook_config_path=str(CodexHarnessAdapter._hook_config_path(context)),
        workspace_explicit=context.workspace_override_explicit,
        **fields,
    )
    return json.loads(_reply_text(answer, "manifest"))


def _server_fields(
    detection: HarnessDetection, managed_servers: Sequence[ManagedMcpServer], migrated: Sequence[str]
) -> dict[str, object]:
    return {
        "managed": [server.name for server in managed_servers],
        "migrated": list(migrated),
        "skipped": list(skipped_stdio_server_names(detection)),
        "source_config_paths": list(detection.config_paths),
    }


class CodexHarnessAdapter(NativeHarnessAdapter):
    """Discover Codex MCP servers and wrapper surfaces."""

    def __init__(self) -> None:
        super().__init__("codex", (), "")

    def launch_command(self, context: HarnessContext, passthrough_args: list[str]) -> list[str]:
        _require_codex_authoritative_shell_hook(context)
        return guarded_codex_launch_command(
            executable=self.resolved_executable(context) or self.executable,
            home_dir=context.home_dir,
            passthrough_args=passthrough_args,
        )

    def preview_launch_commands(
        self,
        context: HarnessContext,
        passthrough_args: list[str],
    ) -> tuple[list[str], ...]:
        _require_codex_authoritative_shell_hook(context)
        return guarded_codex_launch_command_candidates(
            executable=self.resolved_executable(context) or self.executable,
            home_dir=context.home_dir,
            passthrough_args=passthrough_args,
        )

    def launch_command_from_authorized_plan(
        self,
        context: HarnessContext,
        passthrough_args: list[str],
        *,
        authorized_executable_prefixes: Sequence[Sequence[str]],
        launch_environment: Mapping[str, str],
    ) -> list[str]:
        _require_codex_authoritative_shell_hook(context)
        prefixes = {tuple(prefix) for prefix in authorized_executable_prefixes if prefix}
        if len(prefixes) != 1:
            raise ValueError("Codex launch candidates do not share one authorized executable prefix.")
        return guarded_codex_launch_command_from_prefix(
            executable_prefix=prefixes.pop(),
            home_dir=context.home_dir,
            passthrough_args=passthrough_args,
            environ=launch_environment,
        )

    def launch_environment(self, context: HarnessContext) -> dict[str, str]:
        return codex_remote_launch_environment(context.home_dir)

    @staticmethod
    def _scope_for(context: HarnessContext, path: Path) -> str:
        if context.workspace_dir is not None and path.is_relative_to(context.workspace_dir):
            return "project"
        return "global"

    @staticmethod
    def _hooks_path(context: HarnessContext) -> Path:
        return context.home_dir / ".codex" / "hooks.json"

    @staticmethod
    def _all_hook_paths(context: HarnessContext) -> tuple[Path, ...]:
        paths = [context.home_dir / ".codex" / "hooks.json"]
        if context.workspace_dir is not None:
            paths.append(context.workspace_dir / ".codex" / "hooks.json")
        return tuple(paths)

    @staticmethod
    def _config_hook_pairs(context: HarnessContext) -> tuple[tuple[Path, Path], ...]:
        pairs = [(context.home_dir / ".codex" / "config.toml", context.home_dir / ".codex" / "hooks.json")]
        if context.workspace_dir is not None:
            pairs.append(
                (context.workspace_dir / ".codex" / "config.toml", context.workspace_dir / ".codex" / "hooks.json")
            )
        return tuple(pairs)

    def detect(
        self,
        context: HarnessContext,
        *,
        config_contents: Mapping[Path, bytes | None] | None = None,
    ) -> HarnessDetection:
        pairs = self._config_hook_pairs(context)
        if config_contents is None:
            # One read per file feeds both the legacy-ownership bindings and the
            # native inventory, so a file changing in between cannot split them.
            captured = {path: read_source_bytes(path) for pair in pairs for path in pair}
        else:
            captured = {path: config_contents[path] for pair in pairs for path in pair}
            # An install refuses a captured generation it cannot parse strictly.
            _check_sources(context, pairs, captured)
        authenticated_manifest = load_hook_manifest_baseline(_hook_manifest_spec(context))
        hook_config_path = self._hook_config_path(context)
        request: dict[str, object] = {
            "harness": self.harness,
            "authenticated_bindings": _wire_bindings(_manifest_bindings(authenticated_manifest)),
            "sources": [
                {
                    "config_path": anchor_to_process_directory(config_path),
                    "hooks_path": anchor_to_process_directory(hooks_path),
                    "config_scope": self._scope_for(context, config_path),
                    "hooks_scope": self._scope_for(context, hooks_path),
                    "authenticated": config_path == hook_config_path,
                }
                for config_path, hooks_path in pairs
            ],
            "contents": {
                anchor_to_process_directory(path): None if data is None else data.hex()
                for path, data in captured.items()
            },
            "restore": [
                list(item) for item in path_restorations(tuple(path for pair in pairs for path in pair)).items()
            ],
        }
        legacy: dict[str, object] = {**_legacy_fields(context), **short_path_fields()}
        payload = settle_short_paths(
            lambda: native_adapter_detection_payload("codex_detect", {**request, "legacy": legacy}),
            legacy,
            "codex_detect",
        )
        artifacts, found_paths, warnings = detection_from_payload(payload)
        command_available = _command_available(context)
        detection = HarnessDetection(
            harness=self.harness,
            installed=bool(found_paths) or command_available,
            command_available=command_available,
            config_paths=found_paths,
            artifacts=artifacts,
            warnings=warnings,
        )
        extended = extend_detection_with_workspace_aibom(
            detection,
            home_dir=context.home_dir,
            workspace_dir=context.workspace_dir,
        )
        return extend_codex_runtime_inventory(
            extended,
            home_dir=context.home_dir,
            workspace_dir=context.workspace_dir,
        )

    def prepare_install(self, context: HarnessContext) -> PreparedHarnessInstall:
        """Prepare the enrolled native installation, including retirements, without publication."""
        return self._prepare_plan(context, enroll=False).prepared

    def _prepare_plan(self, context: HarnessContext, *, enroll: bool) -> _CodexInstallPlan:
        """The whole install as one plan. ``enroll`` may create the hook key and
        checks every active handler's owner, as an ordinary install does; the
        runtime's ``install_plan`` op composes it."""
        from ..codex_hook_recovery import _snapshot

        spec = _hook_manifest_spec(context)
        previous_manifest = load_hook_manifest_baseline(spec)
        pairs = self._config_hook_pairs(context)
        contents = {path: _snapshot(path) for pair in pairs for path in pair}
        detection = self.detect(context, config_contents=contents)
        managed_servers = managed_stdio_servers(detection)
        registration = _hook_registration(context)
        workspace = context.workspace_dir / ".codex/config.toml" if context.workspace_dir is not None else None
        request: dict[str, Any] = {
            "pairs": [[str(config), str(hooks)] for config, hooks in pairs],
            "contents": {str(path): _b64(data) for path, data in contents.items()},
            "workspace_config": None if workspace is None else str(workspace),
            "owned": json.dumps(_manifest_bindings(previous_manifest), separators=(",", ":")),
            "managed": registration.groups,
            "require_owners": enroll,
            "servers": [
                {
                    "name": server.name,
                    "source_scope": server.source_scope,
                    "config_path": str(Path(server.config_path)),
                    "entry": json.dumps(self._proxy_server_entry(context, server)),
                }
                for server in managed_servers
            ],
            "generation": {
                "home": os.path.abspath(spec.guard_home),
                **generation_request(spec, previous_manifest=previous_manifest, create_key=enroll),
            },
            "interpreter": shim_interpreter(),
            **_legacy_fields(context, registration),
            **install_fields(_runtime_guard_home(context), None),
            **short_path_fields(),
        }
        answer = _ask_install_plan(context, request, spec.guard_home if enroll else None)
        files = tuple(_plan_file(item) for item in answer["files"])
        # The plan leads with the publication: authority, manifest, receipt, config.
        authority, manifest_change, receipt_change, config_change = files[:4]
        publication = PreparedCodexHookPublication(
            json.loads(bytes(manifest_change.after or b"")),
            str(answer["rendered_config"]),
            config_change,
            manifest_change,
            authority,
            receipt_change,
        )
        shim_manifest = json.loads(str(answer["shim_manifest"]))
        fields = {
            "backup_path": str(answer["backup_path"]),
            **_server_fields(detection, managed_servers, [str(name) for name in answer["migrated"]]),
        }
        prepared = PreparedHarnessInstall(
            files,
            _install_manifest(
                context,
                "prepare",
                shim_manifest,
                manifest_path=str(manifest_change.path),
                integrity="authenticated",
                **fields,
            ),
        )
        # The backups an install writes before its authenticated generation.
        backups = frozenset(Path(str(path)) for path in answer["backups"])
        return _CodexInstallPlan(prepared, publication, backups, shim_manifest, fields)

    def install(self, context: HarnessContext) -> dict[str, object]:
        from ..runtime_transition import assert_transition_mutation_allowed

        with codex_install_transaction(context.guard_home, self._target_config_path(context), actor="install"):
            assert_transition_mutation_allowed(context.guard_home)
            recover_hook_publication(context.guard_home)
            return self._install_owned(context)

    def _install_owned(self, context: HarnessContext) -> dict[str, object]:
        """Publish the prepared plan: the authenticated generation and its
        backups under the hook publication journal, then, once committed, the
        retirements and launchers it planned beside them."""
        from ..runtime_transition import assert_transition_mutation_allowed

        assert_transition_mutation_allowed(context.guard_home)
        spec = _hook_manifest_spec(context)
        if self._hook_config_path(context) != self._target_config_path(context):
            raise RuntimeError("Codex hook authentication currently requires one canonical global config target.")
        # A source that is not a readable regular file refuses before the journal opens.
        _check_sources(context, self._config_hook_pairs(context))
        plans: list[_CodexInstallPlan] = []

        def plan() -> tuple[PreparedCodexHookPublication, tuple[TransitionFile, ...]]:
            planned = self._prepare_plan(context, enroll=True)
            plans.append(planned)
            backups = tuple(change for change in planned.prepared.files if change.path in planned.backups)
            return planned.publication, backups

        hook_state = self._write_authenticated_hook_config_owned(
            context,
            config_path=spec.config_path,
            payload=None,
            previous_manifest=load_hook_manifest_baseline(spec),
            plan=plan,
        )
        planned = plans[0]
        published = {change.path for change in planned.publication.files} | planned.backups
        remaining = tuple(change for change in planned.prepared.files if change.path not in published)
        try:
            PreparedHarnessInstall(remaining, planned.prepared.manifest).publish(context.guard_home, removals=True)
        except BaseException:
            # The retirements restored themselves; withdraw the committed
            # generation too, so legacy hooks never run beside their migration.
            _withdraw_publication(context, planned.publication)
            raise
        _require_codex_authoritative_shell_hook(context)
        return _install_manifest(
            context,
            "install",
            planned.shim_manifest,
            manifest_path=str(hook_state["manifest_path"]),
            integrity=str(hook_state["integrity_status"]),
            **planned.fields,
        )

    def uninstall(self, context: HarnessContext) -> dict[str, object]:
        from ..runtime_transition import assert_transition_mutation_allowed

        with codex_install_transaction(context.guard_home, self._target_config_path(context), actor="uninstall"):
            assert_transition_mutation_allowed(context.guard_home)
            recover_hook_publication(context.guard_home)
            return self._uninstall_owned(context)

    def _uninstall_owned(self, context: HarnessContext) -> dict[str, object]:
        from ..codex_install_transaction import record_codex_mutation

        prepared = self._prepare_uninstall(context)
        config_path = self._hook_config_path(context)
        operations = {
            _located(hook_authority_receipt_path(context.guard_home, config_path)): "remove_authority_receipt",
            _located(hook_manifest_path(context.guard_home, config_path)): "remove_manifest",
        }

        def audit(change: TransitionFile) -> None:
            operation = operations.get(change.path)
            if operation is not None:
                record_codex_mutation(operation, change.path, change.before, None)

        prepared.publish(context.guard_home, removals=True, on_write=audit)
        remove_hook_secret_if_unused(context.guard_home)
        return _install_manifest(
            context,
            "uninstall",
            prepared.manifest,
            hooks_path=str(self._hooks_path(context)),
            backup_path=str(self._backup_path(context)),
        )

    def _prepare_uninstall(self, context: HarnessContext) -> PreparedHarnessInstall:
        """Every file uninstall restores or deletes, captured before any of them changes."""
        from ..runtime_transition import RuntimeTransition

        hook_config_path = self._hook_config_path(context)
        owned = _manifest_bindings(load_hook_manifest_baseline(_hook_manifest_spec(context)))
        request: dict[str, Any] = {
            "owned": json.dumps(list(owned), separators=(",", ":")),
            "authority_files": [
                str(_located(hook_authority_receipt_path(context.guard_home, hook_config_path))),
                str(_located(hook_manifest_path(context.guard_home, hook_config_path))),
            ],
            **_legacy_fields(context),
            **install_fields(_runtime_guard_home(context), None),
            **short_path_fields(),
        }
        answer = settle_short_paths(lambda: _codex("uninstall_plan", context, **request), request, "uninstall_plan")
        files = tuple(planned_files(answer))
        compared = cast(list[int], answer["compared"])
        RuntimeTransition._compare({"files": [files[index].payload() for index in compared]}, "before")
        return PreparedHarnessInstall(files, json.loads(str(answer["manifest"])))

    def diagnostics(self, context: HarnessContext) -> dict[str, object]:
        payload = super().diagnostics(context)
        hook_state = codex_native_hook_state(context)
        warning_items = payload.get("warnings")
        items = warning_items if isinstance(warning_items, list) else []
        warnings, setup_status = codex_doctor_result(
            [str(item) for item in items if isinstance(item, str)], hook_state, payload.get("setup_status")
        )
        payload["warnings"] = warnings
        payload["setup_status"] = setup_status
        apply_codex_hook_trust_doctor(payload, hook_state)
        payload["native_hook_state"] = hook_state
        return payload

    @staticmethod
    def _target_config_path(context: HarnessContext) -> Path:
        return context.home_dir / ".codex" / "config.toml"

    @staticmethod
    def _hook_config_path(context: HarnessContext) -> Path:
        return context.home_dir / ".codex" / "config.toml"

    @staticmethod
    def _backup_path(context: HarnessContext) -> Path:
        return Path(str(_codex("backup_path", context)["path"]))

    def _proxy_server_entry(self, context: HarnessContext, server: ManagedMcpServer) -> dict[str, object]:
        return proxy_launcher_entry(
            proxy_command="codex-mcp-proxy",
            context=context,
            server=server,
        )

    @staticmethod
    def _install_config_hooks(
        payload: dict[str, object],
        context: HarnessContext,
        *,
        config_path: Path,
        owned_bindings: Sequence[Mapping[str, object]] = (),
    ) -> None:
        # Codex hooks are switched on, Guard's earlier handlers go, the managed
        # groups are written, each hook's state follows its handler and the
        # Guard handlers just written are trusted, all in the native runtime.
        # Codex skips a hook it has no trusted hash for, so an install that
        # cannot record trust refuses.
        owned = list(owned_bindings)
        wire = _Wire(payload, owned)
        request: dict[str, object] = {
            "payload": wire.text(payload),
            "tokens": wire.meanings,
            "owned": wire.text(owned),
            "managed": _hook_registration(context).groups,
            "config": str(config_path),
            **_legacy_fields(context),
            **install_fields(_runtime_guard_home(context), None),
            **short_path_fields(),
        }
        answer = settle_short_paths(lambda: _codex("config_hooks", context, **request), request, "config_hooks")
        installed = wire.decode(_reply_text(answer, "payload"))
        payload.clear()
        payload.update(installed)

    @staticmethod
    def _write_authenticated_hook_config(
        context: HarnessContext,
        *,
        config_path: Path,
        payload: dict[str, object],
        previous_manifest: dict[str, object] | None,
    ) -> dict[str, object]:
        from ..runtime_transition import assert_transition_mutation_allowed

        with codex_install_transaction(context.guard_home, config_path, actor="publish"):
            assert_transition_mutation_allowed(context.guard_home)
            return CodexHarnessAdapter._write_authenticated_hook_config_owned(
                context, config_path=config_path, payload=payload, previous_manifest=previous_manifest
            )

    @staticmethod
    def _write_authenticated_hook_config_owned(
        context: HarnessContext,
        *,
        config_path: Path,
        payload: dict[str, object] | None,
        previous_manifest: dict[str, object] | None,
        plan: Callable[[], tuple[PreparedCodexHookPublication, tuple[TransitionFile, ...]]] | None = None,
    ) -> dict[str, object]:
        """Commit manifest first, then config, rolling both back on any failure.

        During the short manifest-first window an old config fails closed against
        the new manifest.  Codex never observes a newly registered hook before
        its complete authenticated identity has been durably committed. ``plan``
        prepares the generation in place of rendering ``payload``, with the
        files written ahead of it. The runtime's ``publish_hooks`` op prepares
        the record, writes the files, reads the hooks back, verifies them and
        commits, or runs the durable inverse.
        """
        from ..codex_hook_file_integrity import _python_package_roots
        from ..codex_hook_manifest import _spec_payload
        from ..codex_hook_recovery import _owned
        from ..native_transition_files import publication as publication_op
        from ..runtime_transition import TransitionError

        spec = _hook_manifest_spec(context)
        config = os.path.abspath(config_path.expanduser())
        if config_path.resolve(strict=False) != spec.config_path.resolve(strict=False):
            raise RuntimeError("Codex authenticated publication requires its canonical config target.")

        def publish() -> dict[str, Any]:
            # The runtime refuses a pending publication and snapshots the config.
            target = publication_op("target", context.guard_home, config=config)
            if not isinstance(target, dict):
                raise TransitionError("native_transition_invalid")
            before = target.get("before")
            if plan is not None:
                publication, ahead = plan()
            else:
                assert payload is not None
                original = None if before is None else base64.b64decode(str(before))
                publication = prepare_authenticated_hook_publication(
                    spec,
                    rendered_config=dump_toml(payload, original=original),
                    previous_manifest=previous_manifest,
                    create_key=True,
                )
                ahead = ()
            files = (*ahead, *publication.files)
            request.update(
                home=os.path.abspath(context.guard_home),
                config=config,
                operation_id=_owned(context.guard_home),
                original=before,
                original_identity=target.get("identity"),
                key_present=target.get("key_present") is True,
                files=[change.payload() for change in files],
                config_index=files.index(publication.config_change),
                manifest_index=files.index(publication.manifest_change),
                receipt_index=files.index(publication.receipt_change),
                after_manifest=base64.b64encode(canonical_manifest_bytes(publication.manifest) + b"\n").decode(),
            )
            return _publish_hooks(context, request, files)

        request: dict[str, Any] = {
            "spec": _spec_payload(spec),
            "package_roots": [str(root) for root in _python_package_roots()],
            "budget_spent": False,
            **short_path_fields(),
        }
        answer = settle_short_paths(publish, request, "publish_hooks")
        error, rollback = answer.get("error"), answer.get("rollback_error")
        if error is not None:
            failure = _publication_fault(error)
            if rollback is not None:
                rollback_error = _publication_fault(rollback)
                raised = RuntimeError(
                    "Codex hook transaction failed and rollback could not be completed: "
                    f"{type(rollback_error).__name__}: {rollback_error}"
                )
                add_note = getattr(raised, "add_note", None)
                if callable(add_note):
                    add_note(f"rollback error: {rollback_error!r}")
                raise raised from failure
            raise failure
        state = json.loads(_reply_text(answer, "state"))
        if not isinstance(state, dict):
            raise TransitionError("native_transition_invalid")
        return state

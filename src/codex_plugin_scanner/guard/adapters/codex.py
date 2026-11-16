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
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from ...version import __version__
from ..aibom_detection import (
    detection_from_payload,
    extend_codex_runtime_inventory,
    extend_detection_with_workspace_aibom,
    native_adapter_detection_payload,
)
from ..codex_config import read_toml_payload
from ..codex_hook_command_line import short_path_facts
from ..codex_hook_compatibility import NATIVE_CODEX_HOOK_FEATURE, python_bridge_argv
from ..codex_hook_integrity import (
    atomic_write_text,
    hook_authority_receipt_path,
    hook_manifest_path,
)
from ..codex_hook_manifest import (
    CodexHookManifestSpec,
    PreparedCodexHookPublication,
    generation_request,
    load_hook_manifest_baseline,
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
from .native_harness import NativeHarnessAdapter, ask
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


def _launch(context: HarnessContext, *, home_is_current: bool) -> dict[str, Any]:
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
        native_bridge=None if native_bridge is None else str(native_bridge),
        manifest_path=str(hook_manifest_path(guard_home, CodexHarnessAdapter._hook_config_path(context))),
        long_timeout=_post_tool_hook_timeout_seconds(context),
    )


def _hook_command_parts_for_home_mode(context: HarnessContext, *, home_is_current: bool) -> tuple[str, ...]:
    answer = _launch(context, home_is_current=home_is_current)
    return tuple(str(part) for part in answer["argv"])


def _current_launch(context: HarnessContext) -> dict[str, Any]:
    return _launch(context, home_is_current=_home_is_current(context))


def _hook_command_parts(context: HarnessContext) -> tuple[str, ...]:
    return _hook_command_parts_for_home_mode(context, home_is_current=_home_is_current(context))


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
    fields: dict[str, object] = {"argv": list(argv), "long_timeout": _post_tool_hook_timeout_seconds(context)}
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
class _CodexInstallPlan:
    """A prepared install, with what publishing it as an ordinary install needs."""

    prepared: PreparedHarnessInstall
    publication: PreparedCodexHookPublication
    backups: frozenset[Path]
    shim_manifest: Mapping[str, object]
    fields: dict[str, object]


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


def _ask_install_plan(
    context: HarnessContext, request: dict[str, Any], enroll_home: Path | None, op: str = "install_plan"
) -> dict[str, Any]:
    """One ``install_plan`` (or whole ``install``) answer, asked again with
    each reply it needs.

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
            answer = ask(op, context, harness="codex", timeout_seconds=_PUBLISH_TIMEOUT_SECONDS, **request)
        else:
            with _ordinary_hook_writer(enroll_home, hook_secret_path(enroll_home), actor="codex.authority-key"):
                answer = ask(op, context, harness="codex", timeout_seconds=_PUBLISH_TIMEOUT_SECONDS, **request)
        reply = answer.get("reply")
        if not isinstance(reply, Mapping):
            break
        if "relaunch" in reply:
            request["relaunch"] = _relaunch(cast(Mapping[str, object], reply["relaunch"]))
        if "expand" in reply:
            request["long_paths"] = {**request.get("long_paths", {}), **expanded_short_paths(reply)}
    else:
        raise RuntimeError(f"{op} did not settle its replies")
    check_hook_validation_deadline()
    _replay(answer.get("events"), None, None)
    if answer.get("conflict") is True:
        raise TransitionError("adapter_preparation_generation_conflict")
    if "fault" in answer:
        raise _exception(answer["fault"])
    _raise_publication_error(answer)
    if "retire_error" in answer:
        failure = _exception(answer["retire_error"])
        if answer.get("withdrawn") is not True:
            raise RuntimeError(
                "codex_hook_migration_rollback_failed: Guard could not fully restore Codex hook sources after "
                "legacy JSON removal failed. Run `hol-guard install codex` to repair the installation."
            ) from failure
        raise failure
    return answer


def _plan_report(
    answer: Mapping[str, Any], detection: Any, managed_servers: Any
) -> tuple[dict[str, Any], dict[str, object]]:
    """The launcher manifest and the reported fields of a planned install."""
    fields = {
        "backup_path": str(answer["backup_path"]),
        **_server_fields(detection, managed_servers, [str(name) for name in answer["migrated"]]),
    }
    return json.loads(str(answer["shim_manifest"])), fields


def _raise_publication_error(answer: Mapping[str, object]) -> None:
    """Raise a ``publish_hooks`` error, chained to its rollback's when that failed too."""
    error, rollback = answer.get("error"), answer.get("rollback_error")
    if error is None:
        return
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
        request, detection, managed_servers = self._plan_request(context, enroll=enroll)
        enroll_home = _hook_manifest_spec(context).guard_home if enroll else None
        answer = _ask_install_plan(context, request, enroll_home)
        return self._planned(context, answer, detection, managed_servers)

    def _plan_request(self, context: HarnessContext, *, enroll: bool) -> tuple[dict[str, Any], Any, Any]:
        """The ``install_plan`` request over freshly captured sources, with the
        detection and managed servers the prepared manifest reports."""
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
        return request, detection, managed_servers

    def _planned(
        self, context: HarnessContext, answer: Mapping[str, Any], detection: Any, managed_servers: Any
    ) -> _CodexInstallPlan:
        """The prepared install an ``install_plan`` answer describes."""
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
        shim_manifest, fields = _plan_report(answer, detection, managed_servers)
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
        """Publish the prepared plan in the runtime's ``install`` op: the
        authenticated generation and its backups under the hook publication
        journal, then, once committed, the retirements and launchers planned
        beside them. When those fail they restore themselves and the op
        withdraws the committed generation too, so legacy hooks never run
        beside their migration."""
        from ..codex_hook_manifest import _spec_payload
        from ..codex_hook_recovery import _owned
        from ..runtime_transition import TransitionError, assert_transition_mutation_allowed

        assert_transition_mutation_allowed(context.guard_home)
        spec = _hook_manifest_spec(context)
        if self._hook_config_path(context) != self._target_config_path(context):
            raise RuntimeError("Codex hook authentication currently requires one canonical global config target.")
        # A source that is not a readable regular file refuses before the journal opens.
        _check_sources(context, self._config_hook_pairs(context))
        request, detection, managed_servers = self._plan_request(context, enroll=True)
        request.update(
            home=os.path.abspath(context.guard_home),
            config=os.path.abspath(spec.config_path.expanduser()),
            operation_id=_owned(context.guard_home),
            spec=_spec_payload(spec),
            budget_spent=False,
        )
        answer = _ask_install_plan(context, request, spec.guard_home, op="install")
        shim_manifest, fields = _plan_report(answer["plan"], detection, managed_servers)
        hook_state = json.loads(_reply_text(answer, "state"))
        if not isinstance(hook_state, dict):
            raise TransitionError("native_transition_invalid")
        _require_codex_authoritative_shell_hook(context)
        return _install_manifest(
            context,
            "install",
            shim_manifest,
            manifest_path=str(hook_state["manifest_path"]),
            integrity=str(hook_state["integrity_status"]),
            **fields,
        )

    def uninstall(self, context: HarnessContext) -> dict[str, object]:
        from ..runtime_transition import assert_transition_mutation_allowed

        with codex_install_transaction(context.guard_home, self._target_config_path(context), actor="uninstall"):
            assert_transition_mutation_allowed(context.guard_home)
            recover_hook_publication(context.guard_home)
            return self._uninstall_owned(context)

    def _uninstall_owned(self, context: HarnessContext) -> dict[str, object]:
        """Uninstall in the runtime's ``uninstall`` op: every file it restores or
        deletes is captured and compared before any of them changes, the
        receipt and manifest removals are journaled as they are written, and
        the hook key goes once no manifest uses it."""
        from ..codex_hook_integrity import hook_key_refusal
        from ..native_transition_files import _budget, _exception, _package_roots, _replay

        hook_config_path = self._hook_config_path(context)
        owned = _manifest_bindings(load_hook_manifest_baseline(_hook_manifest_spec(context)))
        request: dict[str, Any] = {
            "owned": json.dumps(list(owned), separators=(",", ":")),
            "authority_files": [
                str(_located(hook_authority_receipt_path(context.guard_home, hook_config_path))),
                str(_located(hook_manifest_path(context.guard_home, hook_config_path))),
            ],
            "home": os.path.abspath(context.guard_home),
            "package_roots": _package_roots(),
            "budget": _budget(),
            **_legacy_fields(context),
            **install_fields(_runtime_guard_home(context), None),
            **short_path_fields(),
        }
        answer = settle_short_paths(lambda: _codex("uninstall", context, **request), request, "uninstall")
        _replay(answer.get("events"), None, None)
        if "fault" in answer:
            raise _exception(answer["fault"])
        if "key_error" in answer:
            raise hook_key_refusal(str(answer["key_error"]))
        return _install_manifest(
            context,
            "uninstall",
            json.loads(str(answer["manifest"])),
            hooks_path=str(self._hooks_path(context)),
            backup_path=str(self._backup_path(context)),
        )

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

"""Codex install, uninstall, detection and launch, run through the native runtime.

The runtime plans every file, decides every refusal and answers every launch
question (see ``codex_harness_client``). This class runs what must run in the
Guard process: the install transaction and its locks, the authenticated hook
manifest baseline and key, the transition journal that publishes a plan, and
the launch processes the runtime names.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import codex_harness_client
from .aibom_detection import (
    detection_from_payload,
    extend_codex_runtime_inventory,
    extend_detection_with_workspace_aibom,
    native_adapter_detection_payload,
)
from .codex_harness_client import (
    _ask_install_plan,
    _b64,
    _check_sources,
    _codex,
    _hook_manifest_spec,
    _hook_registration,
    _install_manifest,
    _launch_fields,
    _legacy_fields,
    _plan_file,
    _reply_text,
    _runtime_guard_home,
    codex_paths,
)
from .codex_hook_integrity import hook_authority_receipt_path, hook_manifest_path
from .codex_hook_manifest import (
    PreparedCodexHookPublication,
    generation_request,
    load_hook_manifest_baseline,
)
from .codex_hook_manifest import (
    manifest_bindings as _manifest_bindings,
)
from .codex_hook_recovery import recover_hook_publication
from .codex_hook_registration import codex_doctor_result
from .codex_hook_self_binding import install_fields, short_path_fields
from .codex_hook_trust import apply_codex_hook_trust_doctor
from .codex_install_transaction import codex_install_transaction
from .codex_remote_client import (
    codex_remote_launch_environment,
    guarded_codex_launch_command,
    guarded_codex_launch_command_candidates,
    guarded_codex_launch_command_from_prefix,
)
from .harness.base import HarnessContext, PreparedHarnessInstall
from .harness.native_harness import NativeHarnessAdapter
from .models import GuardArtifact, HarnessDetection
from .native_codex_hook_identity import wire_codex_hook_bindings as _wire_bindings
from .native_path_anchor import anchor_to_process_directory
from .shims import shim_interpreter

_AUTHORITATIVE_HOOK_UNAVAILABLE_REASON = "codex_authoritative_hook_unavailable"


def _command_available(context: HarnessContext) -> bool:
    """Whether the Codex CLI is on the caller's PATH or in a user install directory."""

    return _codex("command_available", context).get("available") is True


def _require_codex_authoritative_shell_hook(context: HarnessContext) -> None:
    hook_state = codex_harness_client.codex_native_hook_state(context)
    if bool(hook_state["shell_protection_active"]):
        return
    raise RuntimeError(
        f"{_AUTHORITATIVE_HOOK_UNAVAILABLE_REASON}: Guard refused to launch Codex because the managed "
        "PreToolUse and PermissionRequest hooks are missing or disabled. Run `hol-guard install codex` "
        "or `hol-guard update` to repair the native-hook enforcement boundary."
    )


def _path_restorations(paths: tuple[Path, ...]) -> dict[str, str]:
    """Anchored (absolute) spelling to the spelling the context used."""

    restore: dict[str, str] = {}
    for path in paths:
        anchored = anchor_to_process_directory(path)
        if anchored != str(path):
            restore[anchored] = str(path)
    return restore


def _located(path: Path) -> Path:
    return path.parent.resolve(strict=False) / path.name


def _wire_artifact(artifact: GuardArtifact) -> dict[str, object]:
    """A detected MCP server as the runtime reads it, private launch metadata included."""
    return {**artifact.to_dict(), "runtime_private_metadata": dict(artifact.runtime_private_metadata)}


def _plan_report(answer: Mapping[str, Any], detection: HarnessDetection) -> tuple[dict[str, Any], dict[str, object]]:
    """The launcher manifest and the reported fields of a planned install."""
    fields: dict[str, object] = {
        "backup_path": str(answer["backup_path"]),
        "managed": [str(name) for name in answer["managed_servers"]],
        "migrated": [str(name) for name in answer["migrated"]],
        "skipped": [str(name) for name in answer["skipped_servers"]],
        "source_config_paths": list(detection.config_paths),
    }
    return json.loads(str(answer["shim_manifest"])), fields


@dataclass(frozen=True, slots=True)
class _CodexInstallPlan:
    """A prepared install, with what publishing it as an ordinary install needs."""

    prepared: PreparedHarnessInstall
    publication: PreparedCodexHookPublication
    backups: frozenset[Path]
    shim_manifest: Mapping[str, object]
    fields: dict[str, object]


class CodexHarnessAdapter(NativeHarnessAdapter):
    """The Codex harness: the runtime answers it, this process publishes and launches."""

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
    def _hooks_path(context: HarnessContext) -> Path:
        return codex_paths(context).hooks

    @staticmethod
    def _config_hook_pairs(context: HarnessContext) -> tuple[tuple[Path, Path], ...]:
        return tuple((source.config, source.hooks) for source in codex_paths(context).sources)

    @staticmethod
    def _target_config_path(context: HarnessContext) -> Path:
        return codex_paths(context).config

    @staticmethod
    def _hook_config_path(context: HarnessContext) -> Path:
        return codex_paths(context).config

    @staticmethod
    def _backup_path(context: HarnessContext) -> Path:
        return codex_paths(context).backup

    def detect(
        self,
        context: HarnessContext,
        *,
        config_contents: Mapping[Path, bytes | None] | None = None,
    ) -> HarnessDetection:
        paths = codex_paths(context)
        pairs = tuple((source.config, source.hooks) for source in paths.sources)
        request: dict[str, object] = {}
        if config_contents is not None:
            captured = {path: config_contents[path] for pair in pairs for path in pair}
            # An install refuses a captured generation it cannot parse strictly.
            _check_sources(context, pairs, captured)
            request["contents"] = {
                anchor_to_process_directory(path): None if data is None else data.hex()
                for path, data in captured.items()
            }
        # Without a capture the runtime reads each file once for both the
        # legacy-ownership bindings and the inventory.
        authenticated_manifest = load_hook_manifest_baseline(_hook_manifest_spec(context))
        request.update(
            harness=self.harness,
            authenticated_bindings=_wire_bindings(_manifest_bindings(authenticated_manifest)),
            sources=[
                {
                    "config_path": anchor_to_process_directory(source.config),
                    "hooks_path": anchor_to_process_directory(source.hooks),
                    "config_scope": source.scope,
                    "hooks_scope": source.scope,
                    "authenticated": source.config == paths.config,
                }
                for source in paths.sources
            ],
            restore=[list(item) for item in _path_restorations(tuple(path for pair in pairs for path in pair)).items()],
        )
        legacy: dict[str, object] = {**_legacy_fields(context), **short_path_fields()}
        payload = native_adapter_detection_payload("codex_detect", {**request, "legacy": legacy})
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
        request, detection = self._plan_request(context, enroll=enroll)
        enroll_home = _hook_manifest_spec(context).guard_home if enroll else None
        answer = _ask_install_plan(context, request, enroll_home)
        return self._planned(context, answer, detection)

    def _plan_request(self, context: HarnessContext, *, enroll: bool) -> tuple[dict[str, Any], HarnessDetection]:
        """The ``install_plan`` request over freshly captured sources, with the
        detection the prepared manifest reports. The runtime chooses the
        managed servers and their proxy launches from the detected artifacts."""
        from .codex_hook_recovery import _snapshot

        spec = _hook_manifest_spec(context)
        previous_manifest = load_hook_manifest_baseline(spec)
        pairs = self._config_hook_pairs(context)
        contents = {path: _snapshot(path) for pair in pairs for path in pair}
        detection = self.detect(context, config_contents=contents)
        registration = _hook_registration(context)
        workspace = pairs[1][0] if len(pairs) > 1 else None
        generation = generation_request(spec, previous_manifest=previous_manifest, create_key=enroll)
        # The runtime builds the spec from the launch below.
        generation.pop("spec")
        request: dict[str, Any] = {
            "launch": _launch_fields(context),
            "pairs": [[str(config), str(hooks)] for config, hooks in pairs],
            "contents": {str(path): _b64(data) for path, data in contents.items()},
            "workspace_config": None if workspace is None else str(workspace),
            "owned": json.dumps(_manifest_bindings(previous_manifest), separators=(",", ":")),
            "managed": registration.groups,
            "require_owners": enroll,
            "artifacts": [
                _wire_artifact(artifact) for artifact in detection.artifacts if artifact.artifact_type == "mcp_server"
            ],
            "generation": {
                "home": os.path.abspath(spec.guard_home),
                **generation,
            },
            "interpreter": shim_interpreter(),
            **_legacy_fields(context, registration),
            **install_fields(_runtime_guard_home(context), None),
            **short_path_fields(),
        }
        return request, detection

    def _planned(
        self, context: HarnessContext, answer: Mapping[str, Any], detection: HarnessDetection
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
        shim_manifest, fields = _plan_report(answer, detection)
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

    def install(self, context: HarnessContext, *, surface: str | None = None) -> dict[str, object]:
        from .runtime_transition import assert_transition_mutation_allowed

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
        from .codex_hook_recovery import _owned
        from .runtime_transition import TransitionError, assert_transition_mutation_allowed

        assert_transition_mutation_allowed(context.guard_home)
        spec = _hook_manifest_spec(context)
        if self._hook_config_path(context) != self._target_config_path(context):
            raise RuntimeError("Codex hook authentication currently requires one canonical global config target.")
        # A source that is not a readable regular file refuses before the journal opens.
        _check_sources(context, self._config_hook_pairs(context))
        request, detection = self._plan_request(context, enroll=True)
        request.update(
            home=os.path.abspath(context.guard_home),
            config=os.path.abspath(spec.config_path.expanduser()),
            operation_id=_owned(context.guard_home),
            budget_spent=False,
        )
        answer = _ask_install_plan(context, request, spec.guard_home, op="install")
        shim_manifest, fields = _plan_report(answer["plan"], detection)
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

    def uninstall(self, context: HarnessContext, *, surface: str | None = None) -> dict[str, object]:
        from .runtime_transition import assert_transition_mutation_allowed

        with codex_install_transaction(context.guard_home, self._target_config_path(context), actor="uninstall"):
            assert_transition_mutation_allowed(context.guard_home)
            recover_hook_publication(context.guard_home)
            return self._uninstall_owned(context)

    def _uninstall_owned(self, context: HarnessContext) -> dict[str, object]:
        """Uninstall in the runtime's ``uninstall`` op: every file it restores or
        deletes is captured and compared before any of them changes, the
        receipt and manifest removals are journaled as they are written, and
        the hook key goes once no manifest uses it."""
        from .codex_hook_integrity import hook_key_refusal
        from .native_transition_files import _budget, _exception, _package_roots, _replay

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
        answer = _codex("uninstall", context, **request)
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
        hook_state = codex_harness_client.codex_native_hook_state(context)
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

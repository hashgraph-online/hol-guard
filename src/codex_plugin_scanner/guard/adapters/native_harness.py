"""Harness adapters the native runtime answers: Devin, Antigravity, Gemini, Kimi, OpenClaw, Paseo and Muse.

The ``harness_adapter`` runner-authority kind owns their paths, detection,
command lookup, install and uninstall plans, manifests, launch environment,
runtime probe fields, approval flow and Paseo's delegated install steps. This
class keeps what must run in the Guard process: the ownership locks the base
class wraps around install and uninstall, the launcher shim, the bounded hook
argv, the transition journal that publishes a plan, the probe subprocess and
the managed-install records in the Guard store.
"""

from __future__ import annotations

import base64
import json
import os
import sys
from dataclasses import replace
from datetime import datetime, timezone
from functools import cache
from pathlib import Path
from typing import Any

from ..models import HarnessDetection
from .base import HarnessAdapter, HarnessContext, PreparedHarnessInstall, _run_command_probe

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
)


@cache
def describe() -> dict[str, Any]:
    """The runtime's description of every adapter it answers."""
    from ..native_runner_authority import native_runner_authority

    answer = native_runner_authority(_KIND, {"op": "describe"})
    if not isinstance(answer.get("adapters"), list):
        raise ValueError("Harness adapter description is malformed")
    return answer


def _description(harness: str) -> dict[str, Any]:
    for adapter in describe()["adapters"]:
        if isinstance(adapter, dict) and adapter.get("harness") == harness:
            return adapter
    raise ValueError(f"Unsupported harness: {harness}")


def _environment() -> dict[str, str]:
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
        "home_override_explicit": context.home_override_explicit,
        "cwd": cwd,
        "user_home": str(Path.home()),
        "env": _environment(),
    }


def ask(op: str, context: HarnessContext, *, harness: str | None = None, **fields: object) -> dict[str, Any]:
    """Run one op and raise the error the Python adapter raised for a refusal."""
    from ..native_runner_authority import native_runner_authority

    request: dict[str, object] = {"op": op, "context": wire_context(context), **fields}
    if harness is not None:
        request["harness"] = harness
    answer = native_runner_authority(_KIND, request)
    if len(answer) == 1:
        if "refusal" in answer:
            raise ValueError(str(answer["refusal"]))
        if "os_error" in answer:
            raise OSError(str(answer["os_error"]))
        if "integrity" in answer:
            from ..codex_hook_recovery import _error

            raise _error(str(answer["integrity"]))
    return answer


def _text(answer: dict[str, Any], key: str) -> str:
    value = answer.get(key)
    if not isinstance(value, str):
        raise ValueError("Harness adapter answer is malformed")
    return value


def _decoded(value: object) -> bytes | None:
    return None if value is None else base64.b64decode(str(value))


def _native_context(context: HarnessContext) -> HarnessContext:
    """Paseo installs for the daemon user, not the caller's current worktree."""
    return replace(context, workspace_dir=None, workspace_override_explicit=False)


class NativeHarnessAdapter(HarnessAdapter):
    """One harness the ``harness_adapter`` kind answers."""

    def __init__(self, harness: str, aliases: tuple[str, ...], launcher_name: str) -> None:
        self.harness = harness
        self.aliases = aliases
        self.executable = harness
        self.launcher_name = launcher_name

    @property
    def _spec(self) -> dict[str, Any]:
        return _description(self.harness)

    def _ask(self, op: str, context: HarnessContext, **fields: object) -> dict[str, Any]:
        return ask(op, context, harness=self.harness, **fields)

    def _shim_names(self) -> dict[str, Any]:
        return {"launcher_name": self.launcher_name or None, "display_name": self._spec.get("display_name")}

    def policy_path(self, context: HarnessContext) -> Path:
        return Path(_text(self._ask("policy_path", context), "path"))

    def resolved_executable(self, context: HarnessContext) -> str | None:
        path = self._ask("resolved_executable", context).get("path")
        return path if isinstance(path, str) else None

    def detect(self, context: HarnessContext) -> HarnessDetection:
        from ..aibom_detection import _artifacts_from_payload, extend_detection_with_workspace_aibom

        answer = self._ask("detect", context)
        detection = HarnessDetection(
            harness=self.harness,
            installed=answer.get("installed") is True,
            command_available=answer.get("command_available") is True,
            config_paths=tuple(str(path) for path in answer.get("config_paths", ())),
            artifacts=_artifacts_from_payload(answer),
            warnings=tuple(str(warning) for warning in answer.get("warnings", ())),
        )
        if answer.get("workspace_aibom") is not True:
            return detection
        return extend_detection_with_workspace_aibom(
            detection, home_dir=context.home_dir, workspace_dir=context.workspace_dir
        )

    def launch_environment(self, context: HarnessContext) -> dict[str, str]:
        if not self._spec.get("dynamic"):
            return {}
        environment = self._ask("launch_env", context).get("env")
        return {str(key): str(value) for key, value in environment.items()} if isinstance(environment, dict) else {}

    def runtime_probe(self, context: HarnessContext) -> dict[str, object] | None:
        if not self._spec.get("dynamic"):
            return None
        answer = self._ask("runtime_probe", context)
        probe = answer.get("probe")
        if not isinstance(probe, dict):
            return None
        argv = answer.get("command_argv")
        command = _run_command_probe([str(part) for part in argv]) if isinstance(argv, list) else None
        return {"command": command, **probe}

    def approval_flow(self, *, managed_install: dict[str, object] | None = None) -> dict[str, object]:
        if not self._spec.get("dynamic"):
            return dict(self._spec["approval"])
        from ..native_runner_authority import native_runner_authority

        # The flow reads only the managed install record, never the filesystem.
        request = {
            "op": "approval_flow",
            "harness": self.harness,
            "context": {"home": "", "guard_home": "", "user_home": ""},
            "managed_install": json.loads(json.dumps(managed_install, default=lambda _: None)),
        }
        return native_runner_authority(_KIND, request)

    def _hook_argv(self, context: HarnessContext, hook_files: list[Any] | None = None) -> list[str]:
        from .bounded_cli_hook_bridge import bounded_cli_hook_command

        spec = self._ask("hook_spec", context)
        return list(
            bounded_cli_hook_command(
                python_executable=sys.executable,
                package_root=Path(__file__).resolve().parents[3],
                guard_home=context.guard_home,
                cli_args=[str(part) for part in spec["cli_args"]],
                harness=self.harness,
                timeout_seconds=int(spec["timeout_seconds"]),
                prepared_files=hook_files,
            )
        )

    def prepare_install(self, context: HarnessContext) -> PreparedHarnessInstall:
        from ..runtime_transition import TransitionError, TransitionFile
        from ..shims import prepare_guard_shim

        mode = self._spec.get("install")
        if mode == "delegated":
            raise TransitionError("adapter_preparation_unavailable")
        shim = prepare_guard_shim(self.harness, context, **self._shim_names())
        if mode == "shim":
            manifest = {"harness": self.harness, "active": True, "config_path": shim.manifest["shim_path"]}
            return PreparedHarnessInstall(shim.files, {**manifest, **shim.manifest})
        hook_files: list[TransitionFile] = []
        fields: dict[str, object] = {"shim": json.dumps(shim.manifest)}
        if self._spec.get("hook") is not None:
            fields["hook_argv"] = self._hook_argv(context, hook_files)
        answer = self._ask("prepare_install", context, **fields)
        files: list[TransitionFile] = []
        for change in answer["files"]:
            planned = TransitionFile(
                Path(change["path"]),
                _decoded(change["before"]),
                _decoded(change["after"]),
                before_mode=change["before_mode"],
                after_mode=change["after_mode"],
                no_follow=change["no_follow"],
            )
            planned.payload()
            files.append(planned)
        return PreparedHarnessInstall((*shim.files, *hook_files, *files), json.loads(_text(answer, "manifest")))

    def preflight_management(self, context: HarnessContext, *, operation: str) -> None:
        if operation == "install" and self._spec.get("install") == "delegated":
            self._delegated_targets(context)

    def install(self, context: HarnessContext) -> dict[str, object]:
        mode = self._spec.get("install")
        if mode == "delegated":
            return self._install_delegated(context)
        if mode == "shim":
            from ..shims import install_guard_shim

            shim = install_guard_shim(self.harness, context)
            return {"harness": self.harness, "active": True, "config_path": shim["shim_path"], **shim}
        return self.prepare_install(context).publish(context.guard_home)

    def uninstall(self, context: HarnessContext) -> dict[str, object]:
        from ..codex_hook_integrity import atomic_write_text
        from ..shims import remove_guard_shim

        if self._spec.get("install") == "shim":
            shim = remove_guard_shim(self.harness, context)
            return {"harness": self.harness, "active": False, "config_path": shim["shim_path"], **shim}
        # Ask for the plan first, so a refusal leaves the launcher in place.
        plan = self._ask("prepare_uninstall", context)
        shim = remove_guard_shim(self.harness, context, **self._shim_names())
        for write in plan["writes"]:
            target = Path(write["path"])
            if write.get("mode") is None:
                target.write_text(write["text"], encoding="utf-8")
            else:
                atomic_write_text(target, write["text"], mode=write["mode"])
        removed: list[str] = []
        for value in plan["deletes"]:
            Path(value).unlink(missing_ok=True)
            removed.append(value)
        answer = self._ask("finish_uninstall", context, shim=json.dumps(shim), finish=plan["finish"], removed=removed)
        return json.loads(_text(answer, "manifest"))

    def diagnostics(self, context: HarnessContext) -> dict[str, object]:
        payload = super().diagnostics(context)
        if self._spec.get("install") != "delegated":
            return payload
        found = bool(payload.get("installed") or payload.get("config_paths"))
        answer = self._ask("diagnostics", context, found=found, **self._delegate_fields(context))
        payload.update(json.loads(_text(answer, "update")))
        return payload

    def _delegate_fields(self, context: HarnessContext) -> dict[str, object]:
        """Which native runtimes Paseo could hand a session to on this host."""
        if self._spec.get("install") != "delegated":
            return {}
        from . import get_adapter

        native = _native_context(context)
        return {
            "delegates": {
                str(name): get_adapter(str(name)).resolved_executable(native) is not None
                for name in self._spec.get("delegates", ())
            }
        }

    def _delegated_targets(self, context: HarnessContext) -> dict[str, Any]:
        return self._ask("prepare_install", context, **self._delegate_fields(context))

    def _install_delegated(self, context: HarnessContext) -> dict[str, object]:
        """Install each native provider, bind its proof, then publish the receipt."""
        from ..codex_hook_integrity import atomic_write_text
        from ..shims import install_guard_shim
        from ..store import GuardStore
        from . import get_adapter

        # Repeat preparation under the shared owner; the earlier read-only
        # check does not authorize mutation.
        delegates = self._delegate_fields(context)
        prepared = self._delegated_targets(context)
        native = _native_context(context)
        proofs: dict[str, str] = {}
        for target in prepared["targets"]:
            self._ask("delegate_preflight", context, target=target, **delegates)
            manifest = get_adapter(target).install(native)
            bound = self._ask(
                "delegate_bind",
                context,
                target=target,
                manifest=json.dumps(manifest, default=lambda _: None),
                **delegates,
            )
            GuardStore(context.guard_home).set_managed_install(
                target, True, None, json.loads(_text(bound, "bound")), datetime.now(timezone.utc).isoformat()
            )
            proofs[target] = _text(bound, "proof")
        receipt = self._ask("delegate_receipt", context, providers=prepared["providers"], proofs=proofs, **delegates)
        shim = install_guard_shim(self.harness, native)
        atomic_write_text(Path(_text(receipt, "path")), _text(receipt, "text"))
        answer = self._ask(
            "finish_install",
            context,
            shim=json.dumps(shim),
            providers=prepared["providers"],
            receipt=_text(receipt, "text"),
            **delegates,
        )
        return json.loads(_text(answer, "manifest"))


__all__ = ["NATIVE_HARNESSES", "NativeHarnessAdapter", "ask", "describe", "wire_context"]

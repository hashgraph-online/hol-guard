"""TermCoder harness adapter.

TermCoder keeps its own per-command confirmation prompt.  Guard is deliberately
invoked beside that prompt with the command text exactly as it will be
executed, plus the current working directory; it does not consume or reproduce
TermCoder's risk classification.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from ..models import GuardArtifact, HarnessDetection
from ..shims import install_guard_shim, remove_guard_shim
from .base import (
    HarnessAdapter,
    HarnessContext,
    _command_available,
    _ensure_path_within_root,
    _json_payload,
    _shell_command,
)
from .bounded_cli_hook_bridge import bounded_cli_hook_command

TERMCODER_CONFIG_DIR = ".config/termcoder"
TERMCODER_CONFIG_FILE = "config.json"
TERMCODER_GUARD_CONFIG_FILE = "guard.json"
TERMCODER_GUARD_MARKER = "HOL Guard managed TermCoder pre-exec"
_GUARD_HOOK_INTERNAL_TIMEOUT_SECONDS = 25


def termcoder_hook_payload(*, command: str, cwd: str, operation: str = "run") -> dict[str, object]:
    """Build the small, raw pre-exec payload TermCoder sends to Guard."""

    return {
        "hook_event_name": "PreToolUse",
        "tool_name": "shell",
        "tool_input": {"command": command},
        "cwd": cwd,
        "termcoder_operation": operation,
    }


class TermCoderHarnessAdapter(HarnessAdapter):
    """Connect TermCoder's execution surfaces to Guard's independent policy."""

    harness = "termcoder"
    aliases = ("termcoder", "term-code")
    executable = "termcoder"
    launcher_name = "termcoder"
    approval_tier = "approval-center"
    approval_summary = (
        "Guard receives TermCoder's raw command and cwd before execution while TermCoder keeps its "
        "existing per-command confirmation."
    )
    fallback_hint = "TermCoder keeps its confirmation prompt; use the Guard approval center for Guard decisions."

    @staticmethod
    def _config_dir(context: HarnessContext) -> Path:
        return context.home_dir / TERMCODER_CONFIG_DIR

    @classmethod
    def _config_path(cls, context: HarnessContext) -> Path:
        return cls._config_dir(context) / TERMCODER_CONFIG_FILE

    @classmethod
    def _guard_config_path(cls, context: HarnessContext) -> Path:
        return cls._config_dir(context) / TERMCODER_GUARD_CONFIG_FILE

    def policy_path(self, context: HarnessContext) -> Path:
        return self._config_path(context)

    def detect(self, context: HarnessContext) -> HarnessDetection:
        config_path = self._config_path(context)
        artifacts: list[GuardArtifact] = []
        found_paths: list[str] = []
        if config_path.is_file():
            found_paths.append(str(config_path))
            payload = _json_payload(config_path)
            if payload:
                artifacts.append(
                    GuardArtifact(
                        artifact_id="termcoder:global:config",
                        name="TermCoder config",
                        harness=self.harness,
                        artifact_type="config",
                        source_scope="global",
                        config_path=str(config_path),
                        metadata={"keys": sorted(payload)},
                    )
                )
        guard_config = self._guard_config_path(context)
        if guard_config.is_file():
            found_paths.append(str(guard_config))
        command_available = _command_available(self.executable)
        return HarnessDetection(
            harness=self.harness,
            installed=bool(found_paths) or command_available,
            command_available=command_available,
            config_paths=tuple(found_paths),
            artifacts=tuple(artifacts),
            warnings=(),
        )

    @staticmethod
    def _hook_command_parts(context: HarnessContext) -> tuple[str, ...]:
        args = [
            "guard",
            "hook",
            "--guard-home",
            str(context.guard_home),
            "--harness",
            "termcoder",
        ]
        if context.home_dir.resolve() != Path.home().resolve():
            args.extend(["--home", str(context.home_dir)])
        if context.workspace_dir is not None:
            args.extend(["--workspace", str(context.workspace_dir)])
        return bounded_cli_hook_command(
            python_executable=sys.executable,
            package_root=Path(__file__).resolve().parents[3],
            guard_home=context.guard_home,
            cli_args=args,
            harness="termcoder",
            timeout_seconds=_GUARD_HOOK_INTERNAL_TIMEOUT_SECONDS,
        )

    def install(self, context: HarnessContext) -> dict[str, object]:
        shim_manifest = install_guard_shim(
            self.harness,
            context,
            launcher_name=self.launcher_name,
            display_name="TermCoder",
        )
        guard_config = self._guard_config_path(context)
        _ensure_path_within_root(context.home_dir, guard_config, label="TermCoder")
        guard_config.parent.mkdir(parents=True, exist_ok=True)
        hook_command = _shell_command(self._hook_command_parts(context))
        guard_config.write_text(
            json.dumps(
                {
                    "marker": TERMCODER_GUARD_MARKER,
                    "pre_exec": {
                        "command": hook_command,
                        "events": ["run", "build", "chat", "install", "uninstall"],
                        "payload": "termcoder_hook_payload(command, cwd, operation)",
                    },
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        return {
            "harness": self.harness,
            "active": True,
            "config_path": str(guard_config),
            "managed_config_path": str(guard_config),
            **shim_manifest,
            "notes": [
                "Guard receives the raw command and cwd immediately before TermCoder executes it",
                "TermCoder's per-command confirmation remains enabled",
                "Guard coverage includes /run, BUILD/CHAT commands, /install, and /uninstall",
                "Read-only /doctor, /packages, and /git operations are outside this hook",
            ],
        }

    def uninstall(self, context: HarnessContext) -> dict[str, object]:
        shim_manifest = remove_guard_shim(
            self.harness,
            context,
            launcher_name=self.launcher_name,
            display_name="TermCoder",
        )
        guard_config = self._guard_config_path(context)
        if guard_config.is_file():
            payload = _json_payload(guard_config)
            if payload.get("marker") == TERMCODER_GUARD_MARKER:
                guard_config.unlink()
        return {
            "harness": self.harness,
            "active": False,
            "config_path": str(guard_config),
            **shim_manifest,
        }


__all__ = ["TermCoderHarnessAdapter", "termcoder_hook_payload"]

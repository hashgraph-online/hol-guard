"""Pi harness adapter for HOL Guard."""

from __future__ import annotations

import json
from pathlib import Path

from ..aibom_detection import extend_detection_with_workspace_aibom
from ..models import GuardArtifact, HarnessDetection
from ..shims import install_guard_shim, remove_guard_shim
from .base import HarnessAdapter, HarnessContext, _command_available

_PI_DIR = ".pi"
_PI_AGENT_DIR = ".pi/agent"
_PI_SETTINGS_FILE = "settings.json"
_PI_MANAGED_EXTENSION_NAME = "hol-guard.ts"
_EXTENSION_SUFFIXES = (".ts", ".js", ".mts", ".cts", ".mjs", ".cjs")
_THEME_SUFFIXES = (".json", ".js", ".ts", ".yaml", ".yml")


def _append_found_path(found_paths: list[str], path: Path) -> None:
    candidate = str(path)
    if candidate not in found_paths:
        found_paths.append(candidate)


def _json_payload(path: Path) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _artifact(
    *,
    artifact_id: str,
    name: str,
    artifact_type: str,
    scope: str,
    path: Path,
    metadata: dict[str, object] | None = None,
    publisher: str | None = None,
) -> GuardArtifact:
    return GuardArtifact(
        artifact_id=artifact_id,
        name=name,
        harness="pi",
        artifact_type=artifact_type,
        source_scope=scope,
        config_path=str(path),
        publisher=publisher,
        metadata=metadata or {},
    )


class PiHarnessAdapter(HarnessAdapter):
    """Discover Pi settings, packages, extensions, skills, prompts, and themes."""

    harness = "pi"
    aliases = ("pi", "pi-agent", "pi-coding-agent")
    executable = "pi"
    launcher_name = "pi"
    approval_tier = "approval-center"
    approval_summary = (
        "Guard scans Pi packages, extensions, skills, prompts, and themes before launch "
        "and uses a managed Pi extension to review prompts and tool calls inline."
    )
    fallback_hint = "Pi keeps the blocked request in Guard and shows the reason inline before you retry."

    @staticmethod
    def _global_root(context: HarnessContext) -> Path:
        return context.home_dir / _PI_AGENT_DIR

    @staticmethod
    def _project_root(context: HarnessContext) -> Path | None:
        if context.workspace_dir is None:
            return None
        return context.workspace_dir / _PI_DIR

    @staticmethod
    def _scope_for(context: HarnessContext, path: Path) -> str:
        if context.workspace_dir is not None and path.is_relative_to(context.workspace_dir):
            return "project"
        return "global"

    @staticmethod
    def _relative_label(root: Path, path: Path) -> str:
        return path.relative_to(root).as_posix()

    def policy_path(self, context: HarnessContext) -> Path:
        project_root = self._project_root(context)
        if project_root is not None:
            return project_root / _PI_SETTINGS_FILE
        return self._global_root(context) / _PI_SETTINGS_FILE

    def _managed_extension_path(self, context: HarnessContext) -> Path:
        return self._global_root(context) / "extensions" / _PI_MANAGED_EXTENSION_NAME

    def detect(self, context: HarnessContext) -> HarnessDetection:
        artifacts: list[GuardArtifact] = []
        found_paths: list[str] = []
        roots = [(self._global_root(context), "global")]
        project_root = self._project_root(context)
        if project_root is not None:
            roots.append((project_root, "project"))
        for root, scope in roots:
            self._append_settings_artifacts(context, artifacts, found_paths, root / _PI_SETTINGS_FILE, scope)
            self._append_extension_artifacts(artifacts, found_paths, root / "extensions", scope)
            self._append_skill_artifacts(artifacts, found_paths, root / "skills", scope)
            self._append_prompt_artifacts(artifacts, found_paths, root / "prompts", scope)
            self._append_theme_artifacts(artifacts, found_paths, root / "themes", scope)
        detection = HarnessDetection(
            harness=self.harness,
            installed=bool(found_paths) or _command_available(self.executable),
            command_available=_command_available(self.executable),
            config_paths=tuple(found_paths),
            artifacts=tuple(artifacts),
            warnings=(),
        )
        return extend_detection_with_workspace_aibom(
            detection,
            home_dir=context.home_dir,
            workspace_dir=context.workspace_dir,
        )

    def _append_settings_artifacts(
        self,
        context: HarnessContext,
        artifacts: list[GuardArtifact],
        found_paths: list[str],
        settings_path: Path,
        scope: str,
    ) -> None:
        payload = _json_payload(settings_path)
        if not payload:
            return
        _append_found_path(found_paths, settings_path)
        for key, artifact_type in (
            ("packages", "package"),
            ("extensions", "extension"),
            ("skills", "skill"),
            ("prompts", "prompt"),
            ("themes", "theme"),
        ):
            values = payload.get(key)
            if not isinstance(values, list):
                continue
            for index, value in enumerate(values):
                if not isinstance(value, str) or not value.strip():
                    continue
                artifacts.append(
                    _artifact(
                        artifact_id=f"pi:{scope}:{artifact_type}:{index}",
                        name=value,
                        artifact_type=artifact_type,
                        scope=scope,
                        path=settings_path,
                        metadata={"source": "settings.json", "key": key, "value": value},
                    )
                )
        del context

    def _append_extension_artifacts(
        self,
        artifacts: list[GuardArtifact],
        found_paths: list[str],
        extension_root: Path,
        scope: str,
    ) -> None:
        if not extension_root.is_dir():
            return
        for path in sorted(extension_root.rglob("*")):
            if not path.is_file() or path.suffix not in _EXTENSION_SUFFIXES:
                continue
            relative = self._relative_label(extension_root, path)
            _append_found_path(found_paths, path)
            artifacts.append(
                _artifact(
                    artifact_id=f"pi:{scope}:extension:{relative}",
                    name=relative,
                    artifact_type="extension",
                    scope=scope,
                    path=path,
                )
            )

    def _append_skill_artifacts(
        self,
        artifacts: list[GuardArtifact],
        found_paths: list[str],
        skill_root: Path,
        scope: str,
    ) -> None:
        if not skill_root.is_dir():
            return
        for skill_path in sorted(skill_root.rglob("SKILL.md")):
            _append_found_path(found_paths, skill_path)
            relative = f"skills/{skill_path.parent.relative_to(skill_root).as_posix()}"
            artifacts.append(
                _artifact(
                    artifact_id=f"pi:{scope}:skill:{relative}",
                    name=relative,
                    artifact_type="skill",
                    scope=scope,
                    path=skill_path,
                )
            )

    def _append_prompt_artifacts(
        self,
        artifacts: list[GuardArtifact],
        found_paths: list[str],
        prompt_root: Path,
        scope: str,
    ) -> None:
        if not prompt_root.is_dir():
            return
        for prompt_path in sorted(prompt_root.rglob("*.md")):
            _append_found_path(found_paths, prompt_path)
            relative = self._relative_label(prompt_root, prompt_path)
            artifacts.append(
                _artifact(
                    artifact_id=f"pi:{scope}:prompt:{relative}",
                    name=relative,
                    artifact_type="prompt",
                    scope=scope,
                    path=prompt_path,
                )
            )

    def _append_theme_artifacts(
        self,
        artifacts: list[GuardArtifact],
        found_paths: list[str],
        theme_root: Path,
        scope: str,
    ) -> None:
        if not theme_root.is_dir():
            return
        for theme_path in sorted(theme_root.rglob("*")):
            if not theme_path.is_file() or theme_path.suffix not in _THEME_SUFFIXES:
                continue
            _append_found_path(found_paths, theme_path)
            relative = self._relative_label(theme_root, theme_path)
            artifacts.append(
                _artifact(
                    artifact_id=f"pi:{scope}:theme:{relative}",
                    name=relative,
                    artifact_type="theme",
                    scope=scope,
                    path=theme_path,
                )
            )

    def install(self, context: HarnessContext) -> dict[str, object]:
        shim_manifest = install_guard_shim(
            self.harness,
            context,
            launcher_name=self.launcher_name,
            display_name="pi",
        )
        extension_path = self._managed_extension_path(context)
        extension_path.parent.mkdir(parents=True, exist_ok=True)
        extension_path.write_text(self._managed_extension_source(context), encoding="utf-8")
        raw_notes = shim_manifest.get("notes")
        shim_notes = (
            [str(note) for note in raw_notes if isinstance(note, str)] if isinstance(raw_notes, (list, tuple)) else []
        )
        return {
            "harness": self.harness,
            "active": True,
            "config_path": str(extension_path),
            **shim_manifest,
            "notes": [
                "Guard installed a managed Pi extension that reviews prompts and tool calls before Pi executes them.",
                *shim_notes,
            ],
        }

    def uninstall(self, context: HarnessContext) -> dict[str, object]:
        shim_manifest = remove_guard_shim(
            self.harness,
            context,
            launcher_name=self.launcher_name,
            display_name="pi",
        )
        extension_path = self._managed_extension_path(context)
        if extension_path.exists():
            extension_path.unlink()
        raw_notes = shim_manifest.get("notes")
        shim_notes = (
            [str(note) for note in raw_notes if isinstance(note, str)] if isinstance(raw_notes, (list, tuple)) else []
        )
        return {
            "harness": self.harness,
            "active": False,
            "config_path": str(extension_path),
            **shim_manifest,
            "notes": [
                "Guard removed the managed Pi extension and left your Pi resources unchanged.",
                *shim_notes,
            ],
        }

    def _managed_extension_source(self, context: HarnessContext) -> str:
        guard_args = ["guard", "hook", "--guard-home", str(context.guard_home), "--harness", "pi"]
        guard_args_json = json.dumps(guard_args)
        return (
            'import { spawnSync } from "node:child_process";\n'
            'import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";\n'
            "\n"
            f"const GUARD_ARGS = {guard_args_json};\n"
            "\n"
            "type GuardResponse = { decision?: string; reason?: string };\n"
            "\n"
            "function runGuard(payload: Record<string, unknown>): GuardResponse {\n"
            "  const args = [...GUARD_ARGS];\n"
            "  const workspace = process.cwd();\n"
            "  if (workspace) args.push(\"--workspace\", workspace);\n"
            "  const result = spawnSync(\"hol-guard\", args, {\n"
            "    input: `${JSON.stringify(payload)}\\n`,\n"
            "    encoding: \"utf-8\",\n"
            "  });\n"
            "  if (result.error) return { decision: \"allow\" };\n"
            "  const lines = (result.stdout ?? \"\").split(/\\r?\\n/).map((line) => line.trim()).filter(Boolean);\n"
            "  const lastLine = lines.length > 0 ? lines[lines.length - 1] : null;\n"
            "  if (lastLine) {\n"
            "    try {\n"
            "      const parsed = JSON.parse(lastLine) as GuardResponse;\n"
            "      if (parsed && typeof parsed === \"object\") return parsed;\n"
            "    } catch {}\n"
            "  }\n"
            "  if ((result.status ?? 0) !== 0) {\n"
            "    return {\n"
            "      decision: \"deny\",\n"
            "      reason: (result.stderr ?? \"\").trim() || \"Blocked by HOL Guard.\",\n"
            "    };\n"
            "  }\n"
            "  return { decision: \"allow\" };\n"
            "}\n"
            "\n"
            "export default function (pi: ExtensionAPI) {\n"
            "  pi.on(\"input\", async (event, ctx) => {\n"
            "    if (event.source === \"extension\") return { action: \"continue\" };\n"
            "    const response = runGuard({ hook_event_name: \"UserPromptSubmit\", prompt: event.text });\n"
            "    if (response.decision === \"deny\") {\n"
            "      ctx.ui.notify(response.reason ?? \"Blocked by HOL Guard.\", \"warning\");\n"
            "      return { action: \"handled\" };\n"
            "    }\n"
            "    return { action: \"continue\" };\n"
            "  });\n"
            "  pi.on(\"tool_call\", async (event, ctx) => {\n"
            "    const toolInput =\n"
            "      (event as { input?: Record<string, unknown> }).input ??\n"
            "      (event as { toolInput?: Record<string, unknown> }).toolInput ??\n"
            "      (event as { arguments?: Record<string, unknown> }).arguments ??\n"
            "      {};\n"
            "    const response = runGuard({\n"
            "      hook_event_name: \"PreToolUse\",\n"
            "      tool_name: event.toolName,\n"
            "      tool_input: toolInput,\n"
            "    });\n"
            "    if (response.decision === \"deny\") {\n"
            "      ctx.ui.notify(response.reason ?? \"Blocked by HOL Guard.\", \"warning\");\n"
            "      return { block: true, reason: response.reason ?? \"Blocked by HOL Guard.\" };\n"
            "    }\n"
            "    return undefined;\n"
            "  });\n"
            "}\n"
        )


__all__ = ["PiHarnessAdapter"]

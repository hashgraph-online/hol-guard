"""Hermes harness adapter."""

from __future__ import annotations

import json
import re

from ..models import GuardArtifact, HarnessDetection
from .base import HarnessAdapter, HarnessContext, _command_available


class HermesHarnessAdapter(HarnessAdapter):
    """Discover Hermes skills and MCP servers."""

    harness = "hermes"
    executable = "hermes"
    approval_tier = "approval-center"
    approval_summary = (
        "Guard can scan Hermes skills before execution and hand blocked "
        "artifacts to the local approval center."
    )
    fallback_hint = "Configure Hermes to use Guard-launched sessions for skill execution."

    def detect(self, context: HarnessContext) -> HarnessDetection:
        hermes_home = context.home_dir / ".hermes"
        artifacts: list[GuardArtifact] = []
        found_paths: list[str] = []

        # Detect Hermes config
        config_path = hermes_home / "config.toml"
        if config_path.is_file():
            found_paths.append(str(config_path))

        # Discover skills in ~/.hermes/skills/<category>/<skill>/
        skills_dir = hermes_home / "skills"
        if skills_dir.is_dir():
            for category_dir in skills_dir.iterdir():
                if not category_dir.is_dir():
                    continue
                for skill_dir in category_dir.iterdir():
                    if not skill_dir.is_dir():
                        continue
                    skill_md = skill_dir / "SKILL.md"
                    if not skill_md.is_file():
                        continue

                    # Read full skill content for risk analysis
                    try:
                        content = skill_md.read_text(encoding="utf-8")
                        frontmatter = self._parse_frontmatter(content)
                        # Extract code blocks for risk scanning
                        code_blocks = self._extract_code_blocks(content)
                    except (OSError, UnicodeDecodeError):
                        content = ""
                        frontmatter = {}
                        code_blocks = []

                    skill_name = frontmatter.get("name") or skill_dir.name
                    description = frontmatter.get("description", "")

                    # Include full skill content for comprehensive risk analysis
                    # (not just fenced code blocks, so plain-text instructions are caught)
                    risk_content = content

                    artifacts.append(
                        GuardArtifact(
                            artifact_id=f"hermes:skill:{category_dir.name}:{skill_dir.name}",
                            name=skill_name,
                            harness=self.harness,
                            artifact_type="skill",
                            source_scope="global",
                            config_path=str(skill_md),
                            command=str(skill_md),
                            url=None,
                            transport=None,
                            args=tuple(code_blocks) if code_blocks else (),
                            metadata={
                                "category": category_dir.name,
                                "description": description[:200] if description else "",
                                "content_snippet": content[:500] if content else "",
                            },
                        )
                    )
                    found_paths.append(str(skill_md))

        # Discover Hermes MCP servers if configured
        mcp_config = hermes_home / "mcp_servers.json"
        if mcp_config.is_file():
            try:
                mcp_data = json.loads(mcp_config.read_text(encoding="utf-8"))
                if isinstance(mcp_data, dict):
                    for name, server_config in mcp_data.items():
                        if not isinstance(name, str) or not isinstance(server_config, dict):
                            continue
                        command = server_config.get("command")
                        url = server_config.get("url")
                        args = server_config.get("args", [])
                        env = server_config.get("env", {})

                        # Validate args is a list before iterating
                        if not isinstance(args, list):
                            args = []
                        if not isinstance(env, dict):
                            env = {}

                        # Convert args list to tuple for artifact
                        args_tuple = tuple(str(a) for a in args if isinstance(a, str))

                        artifacts.append(
                            GuardArtifact(
                                artifact_id=f"hermes:mcp:{name}",
                                name=name,
                                harness=self.harness,
                                artifact_type="mcp_server",
                                source_scope="global",
                                config_path=str(mcp_config),
                                command=command if isinstance(command, str) else None,
                                url=url if isinstance(url, str) else None,
                                transport="http" if isinstance(url, str) else "stdio",
                                args=args_tuple,
                                metadata={"env_keys": sorted(env.keys()) if isinstance(env, dict) else []},
                            )
                        )
                        found_paths.append(str(mcp_config))
            except (OSError, json.JSONDecodeError):
                pass

        return HarnessDetection(
            harness=self.harness,
            installed=bool(found_paths) or _command_available(self.executable),
            command_available=_command_available(self.executable),
            artifacts=tuple(artifacts),
            config_paths=tuple(found_paths),
        )

    def _parse_frontmatter(self, content: str) -> dict[str, object]:
        """Parse YAML frontmatter from SKILL.md content."""
        if not content.startswith("---"):
            return {}
        parts = content[3:].split("---", 1)
        if len(parts) != 2:
            return {}
        # Simple key: value parser for frontmatter
        frontmatter: dict[str, object] = {}
        for line in parts[0].strip().split("\n"):
            if not line or ":" not in line:
                continue
            key, _, value = line.partition(":")
            frontmatter[key.strip()] = value.strip()
        return frontmatter

    def _extract_code_blocks(self, content: str) -> list[str]:
        """Extract code blocks from SKILL.md for risk analysis."""
        blocks = []
        # Match ```bash, ```python, ``` etc blocks, allowing trailing spaces
        pattern = r"```[^\n]*\n(.*?)\n?```"
        for match in re.finditer(pattern, content, re.DOTALL):
            code = match.group(1).strip()
            if code:
                blocks.append(code)
        return blocks


__all__ = ["HermesHarnessAdapter"]

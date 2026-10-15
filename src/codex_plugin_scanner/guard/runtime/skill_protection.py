"""Skill identity and native skill content risk detection for Guard.

Rust owns the skill content detector. Python builds the content-addressed
skill identity and asks the resident for the risk signals; it never runs a
Python evaluator.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

from codex_plugin_scanner.guard.native_runner_authority import NativeRunnerAuthorityError, native_runner_authority
from codex_plugin_scanner.guard.runtime.signals import RiskSignalV2

_SHELL_COMMAND_PATTERN = re.compile(
    r"```(?:bash|sh|shell|zsh)\s(.*?)```",
    re.DOTALL,
)
_MAX_SIGNALS = 64


@dataclass(frozen=True, slots=True)
class SkillIdentity:
    """Stable content-addressed identity for a Guard skill file."""

    root_path: str | None
    skill_path: str | None
    skill_hash: str
    reference_hashes: tuple[str, ...]
    template_hashes: tuple[str, ...]
    script_hashes: tuple[str, ...]

    @property
    def identity_hash(self) -> str:
        payload = "|".join(
            [
                self.skill_hash,
                ",".join(sorted(self.reference_hashes)),
                ",".join(sorted(self.template_hashes)),
                ",".join(sorted(self.script_hashes)),
            ]
        )
        return sha256(payload.encode()).hexdigest()


def skill_identity_metadata(
    identity: SkillIdentity,
    *,
    publisher: str | None = None,
) -> dict[str, object]:
    """Serialize a skill identity for Guard metadata and Cloud firewall sync."""

    from .mcp_skill_firewall import skill_identity_metadata as export_skill_identity_metadata

    return export_skill_identity_metadata(identity, publisher=publisher)


def build_skill_identity(
    skill_content: str,
    *,
    skill_path: str | None = None,
    root_path: str | None = None,
) -> SkillIdentity:
    """Build a stable identity from SKILL.md content and related artifacts."""
    skill_hash = sha256(skill_content.encode()).hexdigest()
    reference_hashes = tuple(sha256(ref.encode()).hexdigest() for ref in _extract_references(skill_content))
    template_hashes = tuple(sha256(tmpl.encode()).hexdigest() for tmpl in _extract_templates(skill_content))
    script_hashes = tuple(sha256(block.encode()).hexdigest() for block in _extract_shell_blocks(skill_content))
    return SkillIdentity(
        root_path=root_path,
        skill_path=skill_path,
        skill_hash=skill_hash,
        reference_hashes=reference_hashes,
        template_hashes=template_hashes,
        script_hashes=script_hashes,
    )


def detect_skill_content_risk(
    content: str,
    *,
    guard_home: Path | None = None,
) -> tuple[RiskSignalV2, ...]:
    """Return the native risk signals for SKILL.md content."""
    payload = native_runner_authority("skill_content_risk", {"content": content}, guard_home)
    signals = payload.get("signals")
    if not isinstance(signals, list) or len(signals) > _MAX_SIGNALS:
        raise NativeRunnerAuthorityError("native_runner_authority_result_invalid")
    try:
        return tuple(RiskSignalV2.from_dict(signal) for signal in signals)
    except (AttributeError, TypeError, ValueError) as error:
        raise NativeRunnerAuthorityError("native_runner_authority_result_invalid") from error


def _extract_references(content: str) -> list[str]:
    return re.findall(r"\[.*?\]\((.*?)\)", content)


def _extract_templates(content: str) -> list[str]:
    return re.findall(r"{{(.*?)}}", content)


def _extract_shell_blocks(content: str) -> list[str]:
    return _SHELL_COMMAND_PATTERN.findall(content)

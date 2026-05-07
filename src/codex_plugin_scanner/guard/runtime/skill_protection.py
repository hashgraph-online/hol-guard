"""Skill content risk detection for Guard runtime protection."""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass
from hashlib import sha256

from codex_plugin_scanner.guard.runtime.signals import (
    RiskConfidenceLabel,
    RiskSeverityLabel,
    RiskSignalCategory,
    RiskSignalV2,
)

_FRONTMATTER_COMMAND_PATTERN = re.compile(
    r"---\s.*?---",
    re.DOTALL,
)
_SHELL_COMMAND_PATTERN = re.compile(
    r"```(?:bash|sh|shell|zsh)\s(.*?)```",
    re.DOTALL,
)
_SECRET_READ_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bcat\s+\.env\b", re.IGNORECASE),
    re.compile(r"\bcat\s+~?/[^\s]*(?:\.env|secret|credential|password|token|key)\b", re.IGNORECASE),
    re.compile(r"\breadFile\s*\(['\"].*?(?:\.env|secret|credential|password|key)['\"]", re.IGNORECASE),
    re.compile(r"\bopen\s*\(['\"].*?(?:\.env|secret|credential|password|key)['\"]", re.IGNORECASE),
)
_EXFIL_SINK_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bcurl\s+.*?https?://[^\s`\"']+", re.IGNORECASE),
    re.compile(r"\bwget\s+.*?https?://[^\s`\"']+", re.IGNORECASE),
    re.compile(r"\bfetch\s*\(\s*['\"]https?://", re.IGNORECASE),
    re.compile(r"\baxios\.[a-z]+\s*\(\s*['\"]https?://", re.IGNORECASE),
)
_REMOTE_FETCH_EXEC_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"curl\s+.*?\|\s*(?:bash|sh|python|node|ruby)\b", re.IGNORECASE),
    re.compile(r"wget\s+.*?-O\s*-\s*\|\s*(?:bash|sh|python|node)\b", re.IGNORECASE),
    re.compile(r"\bnpx\s+[^\s]+@[^\s]+", re.IGNORECASE),
    re.compile(r"\beval\s*\(\s*(?:fetch|curl|wget)", re.IGNORECASE),
)
_GIT_HOOK_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\.git/hooks/[a-z\-]+", re.IGNORECASE),
    re.compile(r"\bcore\.hooksPath\b", re.IGNORECASE),
)
_SHELL_PROFILE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"~?/\.(?:bashrc|bash_profile|zshrc|profile|zprofile|bash_login)\b"),
    re.compile(r"\becho\b.*>>\s*~?/\.(?:bashrc|zshrc|profile)\b", re.IGNORECASE),
)
_LAUNCHAGENT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"~/Library/LaunchAgents/", re.IGNORECASE),
    re.compile(r"\blaunchctl\s+(?:load|submit|start)\b", re.IGNORECASE),
)
_CRON_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bcrontab\s+-[el]\b", re.IGNORECASE),
    re.compile(r"/etc/cron\.", re.IGNORECASE),
    re.compile(r"/var/spool/cron/", re.IGNORECASE),
)
_GUARD_BYPASS_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b(?:disable|uninstall|bypass|remove)\s+HOL\s+Guard\b", re.IGNORECASE),
    re.compile(r"\b(?:delete|rm)\b.*?\.claude/settings\.local\.json", re.IGNORECASE),
    re.compile(r"\b(?:delete|rm)\b.*?\.codex/config\.toml", re.IGNORECASE),
    re.compile(r"\bpre-(?:push|commit)\s+hook\b.*?\b(?:remove|delete|disable)\b", re.IGNORECASE),
)
_HIDE_ACTIONS_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b(?:do\s+not|don't)\s+(?:tell|notify|mention|show)\s+.*?(?:user|human)\b", re.IGNORECASE),
    re.compile(r"\bhide\s+(?:this|these|the\s+action|your\s+actions?)\s+from\b", re.IGNORECASE),
    re.compile(r"\bdo\s+this\s+(?:silently|without\s+notif)", re.IGNORECASE),
)
_BASE64_CANDIDATE = re.compile(r"\b(?:[A-Za-z0-9+/]{40,}={0,2})\b")
_HEX_CANDIDATE = re.compile(r"\b(?:[0-9a-fA-F]{2}){30,}\b")
_UNICODE_CONTROL_PATTERN = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]")


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
    skill_path: str | None = None,
) -> tuple[RiskSignalV2, ...]:
    """Classify malicious patterns in SKILL.md content and return typed risk signals."""
    signals: list[RiskSignalV2] = []
    _check_shell_in_frontmatter(content, signals)
    _check_secret_read(content, signals)
    _check_exfil_sinks(content, signals)
    _check_remote_fetch_exec(content, signals)
    _check_git_hooks(content, signals)
    _check_shell_profile_persistence(content, signals)
    _check_launchagent_persistence(content, signals)
    _check_cron_persistence(content, signals)
    _check_guard_bypass(content, signals)
    _check_hide_actions(content, signals)
    _check_encoded_payloads(content, signals)
    _check_unicode_controls(content, signals)
    return tuple(signals)


_SKILL_FRONTMATTER_GATE = re.compile(r"---\s+\w", re.DOTALL)
_SKILL_HEADING_GATE = re.compile(r"^#+\s+\S", re.MULTILINE)
_SKILL_NAME_FIELD_GATE = re.compile(r"^name\s*:", re.MULTILINE | re.IGNORECASE)


def has_skill_structure(content: str) -> bool:
    """Return True if content has structural markers consistent with a SKILL.md file."""
    if "SKILL.md" in content or "skill:" in content.lower():
        return True
    if _SKILL_FRONTMATTER_GATE.search(content):
        return True
    return bool(_SKILL_NAME_FIELD_GATE.search(content) and _SKILL_HEADING_GATE.search(content))


def _check_shell_in_frontmatter(content: str, signals: list[RiskSignalV2]) -> None:
    frontmatter = _FRONTMATTER_COMMAND_PATTERN.match(content)
    if frontmatter and _SHELL_COMMAND_PATTERN.search(frontmatter.group(0)):
        signals.append(
            _skill_signal(
                "skill.shell-in-frontmatter",
                "execution",
                "high",
                "strong",
                "Skill YAML frontmatter contains shell code blocks",
                "This skill embeds shell commands inside its YAML frontmatter section.",
                "shell code block found in frontmatter",
            )
        )


def _check_secret_read(content: str, signals: list[RiskSignalV2]) -> None:
    for pattern in _SECRET_READ_PATTERNS:
        if pattern.search(content):
            signals.append(
                _skill_signal(
                    "skill.secret-read",
                    "secret",
                    "high",
                    "strong",
                    "Skill content reads local secret files",
                    "This skill contains instructions to read secret files such as .env or credential stores.",
                    "secret read pattern in skill content",
                )
            )
            return


def _check_exfil_sinks(content: str, signals: list[RiskSignalV2]) -> None:
    for pattern in _EXFIL_SINK_PATTERNS:
        if pattern.search(content):
            signals.append(
                _skill_signal(
                    "skill.exfil-sink",
                    "network",
                    "high",
                    "strong",
                    "Skill content sends data to a remote endpoint",
                    "This skill contains HTTP upload or network exfiltration instructions.",
                    "outbound HTTP sink in skill content",
                )
            )
            return


def _check_remote_fetch_exec(content: str, signals: list[RiskSignalV2]) -> None:
    for pattern in _REMOTE_FETCH_EXEC_PATTERNS:
        if pattern.search(content):
            signals.append(
                _skill_signal(
                    "skill.remote-fetch-exec",
                    "execution",
                    "critical",
                    "strong",
                    "Skill fetches and executes remote code",
                    "This skill pipes remote content into a shell or interpreter.",
                    "fetch-and-execute pattern in skill content",
                )
            )
            return


def _check_git_hooks(content: str, signals: list[RiskSignalV2]) -> None:
    for pattern in _GIT_HOOK_PATTERNS:
        if pattern.search(content):
            signals.append(
                _skill_signal(
                    "skill.git-hooks",
                    "persistence",
                    "high",
                    "strong",
                    "Skill installs or modifies Git hooks",
                    "This skill creates or modifies Git hooks, which persist across commits.",
                    "git hook reference in skill content",
                )
            )
            return


def _check_shell_profile_persistence(content: str, signals: list[RiskSignalV2]) -> None:
    for pattern in _SHELL_PROFILE_PATTERNS:
        if pattern.search(content):
            signals.append(
                _skill_signal(
                    "skill.shell-profile",
                    "persistence",
                    "high",
                    "strong",
                    "Skill modifies shell profile for persistence",
                    "This skill appends to shell profiles such as .bashrc or .zshrc.",
                    "shell profile modification in skill content",
                )
            )
            return


def _check_launchagent_persistence(content: str, signals: list[RiskSignalV2]) -> None:
    for pattern in _LAUNCHAGENT_PATTERNS:
        if pattern.search(content):
            signals.append(
                _skill_signal(
                    "skill.launchagent",
                    "persistence",
                    "critical",
                    "strong",
                    "Skill installs a macOS LaunchAgent",
                    "This skill writes or loads a macOS LaunchAgent for persistent execution.",
                    "LaunchAgent install pattern in skill content",
                )
            )
            return


def _check_cron_persistence(content: str, signals: list[RiskSignalV2]) -> None:
    for pattern in _CRON_PATTERNS:
        if pattern.search(content):
            signals.append(
                _skill_signal(
                    "skill.cron",
                    "persistence",
                    "high",
                    "strong",
                    "Skill installs a cron job",
                    "This skill modifies crontab or system cron directories for persistent execution.",
                    "cron persistence pattern in skill content",
                )
            )
            return


def _check_guard_bypass(content: str, signals: list[RiskSignalV2]) -> None:
    for pattern in _GUARD_BYPASS_PATTERNS:
        if pattern.search(content):
            signals.append(
                _skill_signal(
                    "skill.guard-bypass",
                    "bypass",
                    "critical",
                    "strong",
                    "Skill instructs agent to disable HOL Guard",
                    "This skill contains instructions to remove, disable, or bypass HOL Guard protection.",
                    "guard bypass instruction in skill content",
                )
            )
            return


def _check_hide_actions(content: str, signals: list[RiskSignalV2]) -> None:
    for pattern in _HIDE_ACTIONS_PATTERNS:
        if pattern.search(content):
            signals.append(
                _skill_signal(
                    "skill.hide-actions",
                    "bypass",
                    "high",
                    "likely",
                    "Skill instructs agent to hide its actions",
                    "This skill tells the agent to act silently without notifying the user.",
                    "stealth instruction in skill content",
                    false_positive_hint="may be documentation explaining what not to do",
                )
            )
            return


def _check_encoded_payloads(content: str, signals: list[RiskSignalV2]) -> None:
    for match in _BASE64_CANDIDATE.finditer(content):
        candidate = match.group(0)
        try:
            decoded = base64.b64decode(candidate + "=" * (-len(candidate) % 4)).decode("utf-8", errors="strict")
            _all_patterns = (*_SECRET_READ_PATTERNS, *_EXFIL_SINK_PATTERNS, *_REMOTE_FETCH_EXEC_PATTERNS)
            if any(pattern.search(decoded) for pattern in _all_patterns):
                signals.append(
                    _skill_signal(
                        "skill.encoded-payload",
                        "encoded",
                        "critical",
                        "strong",
                        "Skill contains an encoded malicious payload",
                        "This skill includes a base64-encoded string that decodes to a dangerous command.",
                        f"encoded payload: {candidate[:40]}…",
                    )
                )
                return
        except (ValueError, UnicodeDecodeError, binascii.Error):
            pass
    for match in _HEX_CANDIDATE.finditer(content):
        candidate = match.group(0)
        try:
            decoded = bytes.fromhex(candidate).decode("utf-8", errors="strict")
            _all_patterns = (*_SECRET_READ_PATTERNS, *_EXFIL_SINK_PATTERNS, *_REMOTE_FETCH_EXEC_PATTERNS)
            if any(pattern.search(decoded) for pattern in _all_patterns):
                signals.append(
                    _skill_signal(
                        "skill.encoded-payload",
                        "encoded",
                        "critical",
                        "strong",
                        "Skill contains a hex-encoded malicious payload",
                        "This skill includes a hex-encoded string that decodes to a dangerous command.",
                        f"hex payload: {candidate[:40]}…",
                    )
                )
                return
        except (ValueError, UnicodeDecodeError):
            pass


def _check_unicode_controls(content: str, signals: list[RiskSignalV2]) -> None:
    matches = _UNICODE_CONTROL_PATTERN.findall(content)
    if matches:
        names = ", ".join(unicodedata.name(ch, f"U+{ord(ch):04X}") for ch in set(matches))
        signals.append(
            _skill_signal(
                "skill.unicode-controls",
                "encoded",
                "medium",
                "likely",
                "Skill content contains Unicode control characters",
                "Hidden Unicode characters may conceal instructions from human reviewers.",
                f"Unicode controls found: {names[:120]}",
                false_positive_hint="may be legitimate bidirectional text in multilingual content",
            )
        )


def _skill_signal(
    signal_id: str,
    category: RiskSignalCategory,
    severity: RiskSeverityLabel,
    confidence: RiskConfidenceLabel,
    title: str,
    plain_reason: str,
    technical_detail: str,
    false_positive_hint: str | None = None,
) -> RiskSignalV2:
    return RiskSignalV2(
        signal_id=signal_id,
        category=category,
        severity=severity,
        confidence=confidence,
        detector="skill.content",
        title=title,
        plain_reason=plain_reason,
        technical_detail=technical_detail,
        evidence_ref="skill_content",
        redaction_level="summary",
        false_positive_hint=false_positive_hint,
        advisory_id=None,
    )


def _extract_references(content: str) -> list[str]:
    return re.findall(r"\[.*?\]\((.*?)\)", content)


def _extract_templates(content: str) -> list[str]:
    return re.findall(r"{{(.*?)}}", content)


def _extract_shell_blocks(content: str) -> list[str]:
    return _SHELL_COMMAND_PATTERN.findall(content)

"""Starter policies for ``hol-guard policy init``.

The starters mirror the Policy Studio starter gallery so a policy begun in the browser and one begun
with ``policy init`` read the same. ``docs/policy/STARTERS.md`` lists the cross-reference.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone

# The schema's ``$id`` stays https://guard.hashgraphonline.com/schema/policy/v1alpha1; this is where it is served.
POLICY_SCHEMA_URL = "https://hol.org/schema/policy/v1alpha1"
POLICY_MODELINE = f"# yaml-language-server: $schema={POLICY_SCHEMA_URL}"
# Modelines written by earlier releases; ``policy fmt --check`` still accepts them.
LEGACY_POLICY_MODELINES = ("# yaml-language-server: $schema=https://guard.hashgraphonline.com/schema/policy/v1alpha1",)
DEFAULT_STARTER = "safe-defaults"

_COMPROMISED_PACKAGES = ("pkg:npm/event-stream", "pkg:npm/flatmap-stream", "pkg:npm/ua-parser-js")


@dataclass(frozen=True, slots=True)
class StarterEvent:
    harness: str
    tool: str | None = None
    artifact: str | None = None


@dataclass(frozen=True, slots=True)
class StarterRule:
    slug: str
    effect: str
    description: str
    match_field: str
    match_values: tuple[str, ...]
    example_name: str
    example: StarterEvent


@dataclass(frozen=True, slots=True)
class PolicyStarter:
    id: str
    name: str
    summary: str
    defaults: tuple[tuple[str, str], ...]
    rules: tuple[StarterRule, ...]


_BLOCK_ENV_SECRETS = StarterRule(
    slug="env-secrets",
    effect="block",
    description="Agents may not read environment variables, where API keys usually live.",
    match_field="tools",
    match_values=("prompt-env-read",),
    example_name="Codex reads environment variables",
    example=StarterEvent(harness="codex", tool="prompt-env-read"),
)
_BLOCK_SECRET_FILES = StarterRule(
    slug="secret-files",
    effect="block",
    description="Agents may not read files into prompts.",
    match_field="tools",
    match_values=("prompt-file",),
    example_name="Claude Code reads a file into a prompt",
    example=StarterEvent(harness="claude-code", tool="prompt-file"),
)
_BLOCK_COMPROMISED = StarterRule(
    slug="compromised-packages",
    effect="block",
    description="Known compromised npm packages.",
    match_field="artifacts",
    match_values=_COMPROMISED_PACKAGES,
    example_name="Installing event-stream",
    example=StarterEvent(harness="codex", artifact="pkg:npm/event-stream"),
)

POLICY_STARTERS: tuple[PolicyStarter, ...] = (
    PolicyStarter(
        id="safe-defaults",
        name="Safe defaults",
        summary="Blocks agents from reading environment variables; unknown publishers default to block.",
        defaults=(("mode", "prompt"), ("defaultAction", "warn"), ("unknownPublisherAction", "block")),
        rules=(_BLOCK_ENV_SECRETS,),
    ),
    PolicyStarter(
        id="package-firewall",
        name="Package firewall",
        summary="Blocks known compromised packages and sets new publishers to review in the defaults.",
        defaults=(("mode", "enforce"), ("defaultAction", "warn"), ("unknownPublisherAction", "review")),
        rules=(_BLOCK_COMPROMISED,),
    ),
    PolicyStarter(
        id="secrets-guard",
        name="Secrets guard",
        summary="Blocks agents from reading environment variables or files into a prompt.",
        defaults=(("mode", "prompt"), ("defaultAction", "allow"), ("unknownPublisherAction", "review")),
        rules=(_BLOCK_ENV_SECRETS, _BLOCK_SECRET_FILES),
    ),
    PolicyStarter(
        id="mcp-guard",
        name="MCP server guard",
        summary="Blocks agents from starting MCP servers until you narrow or remove the rule.",
        defaults=(("mode", "prompt"), ("defaultAction", "allow"), ("unknownPublisherAction", "review")),
        rules=(
            StarterRule(
                slug="mcp-servers",
                effect="block",
                description="Agents may not start MCP servers until this rule is narrowed or removed.",
                match_field="tools",
                match_values=("mcp",),
                example_name="Cursor starts an MCP server",
                example=StarterEvent(harness="cursor", tool="mcp"),
            ),
        ),
    ),
    PolicyStarter(
        id="team-baseline",
        name="Team baseline",
        summary="A shared floor for every device: compromised packages and secret reads are blocked outright.",
        defaults=(("mode", "enforce"), ("defaultAction", "warn"), ("unknownPublisherAction", "review")),
        rules=(_BLOCK_COMPROMISED, _BLOCK_ENV_SECRETS),
    ),
    PolicyStarter(
        id="blank",
        name="Blank",
        summary="No rules. Guard asks at the device and you add rules as you learn what your agents do.",
        defaults=(("mode", "prompt"),),
        rules=(),
    ),
)

# Events no starter rule matches, so each starter can show the "default" outcome as a second example.
_FALLTHROUGH_EXAMPLES: tuple[tuple[str, str, StarterEvent], ...] = (
    (
        "fallthrough-package",
        "An unlisted package falls through to the defaults",
        StarterEvent("codex", None, "pkg:npm/left-pad"),
    ),
    ("fallthrough-shell", "An unlisted tool falls through to the defaults", StarterEvent("codex", "shell")),
)


def starter_ids() -> tuple[str, ...]:
    return tuple(starter.id for starter in POLICY_STARTERS)


def with_modeline(text: str) -> str:
    """Prefix canonical policy YAML with the editor schema modeline unless it is already there."""

    return text if text.startswith(POLICY_MODELINE) else f"{POLICY_MODELINE}\n{text}"


def find_starter(starter_id: str) -> PolicyStarter | None:
    return next((starter for starter in POLICY_STARTERS if starter.id == starter_id), None)


def _quote(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def _event_lines(event: StarterEvent, indent: str) -> list[str]:
    lines = [f"{indent}harness: {event.harness}"]
    if event.tool is not None:
        lines.append(f"{indent}tool: {event.tool}")
    if event.artifact is not None:
        lines.append(f"{indent}artifact: {event.artifact}")
    return lines


def render_starter_yaml(starter: PolicyStarter, *, now: datetime | None = None) -> str:
    """The text of a new ``guard-policy.yaml``: modeline, defaults, rules and at least two example tests."""

    created_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines = [
        POLICY_MODELINE,
        "# Edit the rules, then run: hol-guard policy test guard-policy.yaml",
        "apiVersion: guard.hashgraphonline.com/v1alpha1",
        "kind: GuardPolicy",
        "metadata:",
        f"  id: policy.{starter.id}",
        f"  name: {_quote(starter.name)}",
        "  revision: 1",
        "spec:",
        "  defaults:",
    ]
    lines.extend(f"    {key}: {value}" for key, value in starter.defaults)
    if starter.rules:
        lines.append("  rules:")
    else:
        lines.append("  rules: []")
    for rule in starter.rules:
        lines.extend(
            [
                f"    - id: rule-{starter.id}-{rule.slug}",
                f"      description: {_quote(rule.description)}",
                "      enabled: true",
                f"      effect: {rule.effect}",
                "      match:",
                f"        {rule.match_field}:",
                *(f"          - {value}" for value in rule.match_values),
                "      lifetime:",
                "        mode: permanent",
                "      provenance:",
                "        source: builder",
                f"        createdAt: {created_at}",
            ]
        )
    lines.append("  x-hol.tests:")
    emitted = 0
    for rule in starter.rules:
        lines.extend(
            [
                f"    - id: test-{starter.id}-{rule.slug}",
                f"      name: {_quote(rule.example_name)}",
                "      event:",
                *_event_lines(rule.example, "        "),
                "      expect:",
                f"        effect: {rule.effect}",
                f"        ruleId: rule-{starter.id}-{rule.slug}",
            ]
        )
        emitted += 1
    for test_id, name, event in _FALLTHROUGH_EXAMPLES:
        if emitted >= 2:
            break
        lines.extend(
            [
                f"    - id: test-{starter.id}-{test_id}",
                f"      name: {_quote(name)}",
                "      event:",
                *_event_lines(event, "        "),
                "      expect:",
                "        effect: default",
            ]
        )
        emitted += 1
    return "\n".join(lines) + "\n"


__all__ = [
    "DEFAULT_STARTER",
    "LEGACY_POLICY_MODELINES",
    "POLICY_MODELINE",
    "POLICY_SCHEMA_URL",
    "POLICY_STARTERS",
    "PolicyStarter",
    "find_starter",
    "render_starter_yaml",
    "starter_ids",
    "with_modeline",
]

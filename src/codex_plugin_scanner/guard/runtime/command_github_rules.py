"""Compatibility rules for distinct GitHub remote capability classes."""

from __future__ import annotations

from typing import Final

from .command_extension_specs import CommandExtensionSpec
from .command_rules import CommandSafetyRule

_REMOTE_MUTATION_RISKS: Final = ("destructive_shell", "network_egress")
GITHUB_ACTION_RISK_CLASSES: Final[dict[str, tuple[str, ...]]] = {
    "github bounded maintenance command": _REMOTE_MUTATION_RISKS,
    "github content mutation command": _REMOTE_MUTATION_RISKS,
    "github merge command": _REMOTE_MUTATION_RISKS,
    "github release publication command": _REMOTE_MUTATION_RISKS,
    "github workflow mutation command": _REMOTE_MUTATION_RISKS,
    "github force mutation command": _REMOTE_MUTATION_RISKS,
    "github delete command": _REMOTE_MUTATION_RISKS,
    "github secret mutation command": _REMOTE_MUTATION_RISKS,
    "github access mutation command": _REMOTE_MUTATION_RISKS,
    "github remote mutation command": _REMOTE_MUTATION_RISKS,
    "unverified github command capability": _REMOTE_MUTATION_RISKS,
}

_RULE_DEFINITIONS: Final = (
    ("maintenance", "Bounded GitHub maintenance", "GitHub bounded maintenance command"),
    ("content", "GitHub content mutation", "GitHub content mutation command"),
    ("merge", "GitHub pull-request merge", "GitHub merge command"),
    ("publish", "GitHub release publication", "GitHub release publication command"),
    ("workflow", "GitHub workflow mutation", "GitHub workflow mutation command"),
    ("force", "Forced GitHub mutation", "GitHub force mutation command"),
    ("delete", "GitHub deletion", "GitHub delete command"),
    ("secret", "GitHub secret mutation", "GitHub secret mutation command"),
    ("access", "GitHub access mutation", "GitHub access mutation command"),
    ("mutation", "GitHub remote mutation", "GitHub remote mutation command"),
    ("unknown", "Unverified GitHub command capability", "Unverified GitHub command capability"),
)

GITHUB_COMMAND_RULES: Final = tuple(
    CommandSafetyRule(
        rule_id=f"command.github.{suffix}",
        title=title,
        description=f"Identifies {title.lower()} operations that change or may change GitHub-hosted state.",
        severity="high",
        risk_classes=GITHUB_ACTION_RISK_CLASSES[action_class.lower()],
        action_classes=(action_class,),
        safer_alternatives=("Inspect the exact repository, resource, and operation before confirming it.",),
        compatibility_fallback=True,
    )
    for suffix, title, action_class in _RULE_DEFINITIONS
)

GITHUB_COMMAND_EXTENSION_SPECS: Final = (
    CommandExtensionSpec(
        extension_id="command.github",
        name="GitHub capability protection",
        description="Reviews distinct GitHub maintenance, content, merge, publication, workflow, and control effects.",
        action_classes=tuple(action_class for _suffix, _title, action_class in _RULE_DEFINITIONS),
        risk_classes=_REMOTE_MUTATION_RISKS,
        safer_alternatives=("Inspect the exact repository, resource, and operation before confirming it.",),
        reference_urls=("https://cli.github.com/manual/",),
    ),
)

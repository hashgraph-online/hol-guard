"""Structured rules and metadata for Ollama CLI publication and removal."""

from __future__ import annotations

from .command_extension_matchers import executable_matcher, safe_flag_variant
from .command_extension_specs import CommandExtensionSpec
from .command_rules import AnyMatcher, CommandSafetyRule, CommandSafeVariant

# CLI surface verified against ollama/ollama `cmd/cmd.go` `NewCLI()`:
# `push MODEL` is ExactArgs(1) and documented as "Push a model to a registry";
# `rm MODEL [MODEL...]` is MinimumNArgs(1) and documented as "Remove a model".
# `push` accepts `--insecure`. Root `--version`/`-v`, `--verbose`, and
# `--nowordwrap` are not persistent flags, so they cannot precede a subcommand
# in the current Cobra registration. Missing model operands still match: an
# incomplete `ollama push` or `ollama rm` remains a publication or removal
# attempt, so those forms stay fail-secure review instead of no_match. v1 does
# not review run, list, show, ps, serve, launch, or other inventory commands.
# https://github.com/ollama/ollama/blob/main/cmd/cmd.go
# https://docs.ollama.com/cli

_OLLAMA_PUSH_FLAGS = frozenset({"--insecure"})

_OLLAMA_PUSH = AnyMatcher(
    matchers=(
        executable_matcher(
            "ollama",
            "push",
            global_flags=_OLLAMA_PUSH_FLAGS,
            fail_secure_unknown_options=True,
        ),
    )
)
_OLLAMA_RM = AnyMatcher(
    matchers=(
        executable_matcher(
            "ollama",
            "rm",
            fail_secure_unknown_options=True,
        ),
    )
)


def _help_variants(matcher: AnyMatcher, *, title: str) -> tuple[CommandSafeVariant, ...]:
    return (
        safe_flag_variant(matcher, variant_id="help", title=title, flag="--help"),
        safe_flag_variant(matcher, variant_id="short-help", title=title, flag="-h"),
    )


OLLAMA_ACTION_RISK_CLASSES: dict[str, tuple[str, ...]] = {
    "ollama model publication command": ("network_egress",),
    "ollama model removal command": ("destructive_shell",),
}

OLLAMA_COMMAND_RULES = (
    CommandSafetyRule(
        rule_id="command.ollama.push",
        title="Ollama model publication",
        description=(
            "Identifies `ollama push`, which publishes a local model to a remote "
            "registry. This community coverage does not certify the upstream tool "
            "or every Ollama feature."
        ),
        severity="high",
        risk_classes=("network_egress",),
        action_classes=("Ollama model publication command",),
        safer_alternatives=(
            (
                "Confirm the model name, owner prefix, registry destination, "
                "and intended publication scope before pushing."
            ),
        ),
        matcher=_OLLAMA_PUSH,
        default_mode="review",
        safe_variants=_help_variants(_OLLAMA_PUSH, title="Ollama push command help"),
        example_command="ollama push",
    ),
    CommandSafetyRule(
        rule_id="command.ollama.rm",
        title="Ollama model removal",
        description=(
            "Identifies `ollama rm`, which deletes one or more locally stored models. "
            "This community coverage does not certify the upstream tool or every "
            "Ollama feature."
        ),
        severity="high",
        risk_classes=("destructive_shell",),
        action_classes=("Ollama model removal command",),
        safer_alternatives=("Run ollama list first and confirm the exact local models before removing them.",),
        matcher=_OLLAMA_RM,
        default_mode="review",
        safe_variants=_help_variants(_OLLAMA_RM, title="Ollama rm command help"),
        example_command="ollama rm",
    ),
)

OLLAMA_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.ollama",
        name="Ollama command protection",
        description=("Reviews Ollama commands that publish models to a registry or remove local model data."),
        action_classes=(
            "Ollama model publication command",
            "Ollama model removal command",
        ),
        risk_classes=("network_egress", "destructive_shell"),
        safer_alternatives=(
            (
                "Confirm the model name, owner prefix, registry destination, "
                "and intended publication scope before pushing."
            ),
            "Run ollama list first and confirm the exact local models before removing them.",
        ),
        reference_urls=(
            "https://github.com/ollama/ollama/blob/main/cmd/cmd.go",
            "https://docs.ollama.com/cli",
        ),
        executables=("ollama",),
        ecosystem_ids=("ollama",),
    ),
)

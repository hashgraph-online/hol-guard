"""Optional Guard-side protection for Syngraphe shared repository context."""

from __future__ import annotations

from dataclasses import dataclass

from .command_extension_matchers import executable_names, executable_path_set_matcher, safe_flag_variant
from .command_extension_specs import CommandExtensionSpec
from .command_matcher_contracts import CommandMatcher, MatcherEvidence
from .command_model import CanonicalCommand, CommandSegment
from .command_option_parsing import argument_semantics
from .command_path_set_matcher import ExecutablePathSetMatcher
from .command_rules import AnyMatcher, CommandSafetyRule, CommandSafeVariant
from .command_tokens import executable_name
from .secret_file_request_services.shell_quote_tokens import (
    shell_token_has_active_expansion,
    shell_token_has_active_pathname_expansion,
    shell_tokens_preserving_quote_context,
)

# Verified against src/cli/main.ts and the published CLI reference, including the
# agent policy surface. --scope takes a value globally; only document creation
# has --title, only init has --policy, and only policy add has --force.
# Commander does not support boolean assignments such as --dry-run=true.
_EXECUTABLES = ("syngraphe", "syg")
_EXECUTABLE_NAMES = frozenset(name for executable in _EXECUTABLES for name in executable_names(executable))
_FLAGS = frozenset({"--dry-run", "--json", "--help", "-h", "--version", "-v"})
# Command-local boolean flags. They are declared per rule so an unknown option
# stays fail-secure everywhere the CLI itself would reject it.
_INIT_FLAGS = frozenset({"--policy"})
_POLICY_FLAGS = frozenset({"--force"})
_WRAPPERS = (
    ("exec", frozenset({"-a"}), frozenset({"-c", "-l"})),
    ("xargs", frozenset({"-n", "-P", "-I", "-L", "-s", "-a", "-E", "-d"}), frozenset({"-0", "-r", "-t"})),
    ("command", frozenset(), frozenset({"-p"})),
)
_DRY_RUN_ALTERNATIVE = "Run the same command with --dry-run first to inspect the exact plan without modifying files."
_SAFER_ALTERNATIVES = (_DRY_RUN_ALTERNATIVE,)
# Only --force can replace a file the repository owns, so its alternative also
# points at the file itself: Syngraphe never restores what it replaces.
_POLICY_SAFER_ALTERNATIVES = (
    _DRY_RUN_ALTERNATIVE,
    "Read the existing AGENT-POLICY.md before --force replaces it; Syngraphe does not manage or restore its contents.",
)


def _mutation_paths(
    *paths: tuple[str, ...],
    creation: bool = False,
    command_flags: frozenset[str] = frozenset(),
) -> AnyMatcher:
    options = frozenset({"--scope", "--title"}) if creation else frozenset({"--scope"})
    known_flags = _FLAGS | command_flags
    # env/sudo and transparent shell wrappers are normalized by the canonical
    # parser. These remaining wrappers use the same structured path matcher.
    return AnyMatcher(
        matchers=(
            *(
                executable_path_set_matcher(
                    executable,
                    paths,
                    global_options_with_values=options,
                    global_flags=known_flags,
                    fail_secure_unknown_options=True,
                )
                for executable in _EXECUTABLES
            ),
            *(
                ExecutablePathSetMatcher(
                    executables=executable_names(wrapper),
                    paths=frozenset((name, *path) for name in _EXECUTABLE_NAMES for path in paths),
                    allow_leading_options=True,
                    leading_options_with_values=value_options,
                    interspersed_options_with_values=options,
                    interspersed_flags=known_flags | wrapper_flags,
                    fail_secure_unknown_options=True,
                )
                for wrapper, value_options, wrapper_flags in _WRAPPERS
            ),
        )
    )


def _arguments_have_active_shell_expansion(segment: CommandSegment) -> bool:
    contextual_tokens = shell_tokens_preserving_quote_context(segment.text)
    plain_tokens = tuple(token.plain for token in contextual_tokens)
    argument_count = len(segment.arguments)
    for argument_start in range(1, len(contextual_tokens) - argument_count + 1):
        if plain_tokens[argument_start - 1] != segment.executable:
            continue
        if plain_tokens[argument_start : argument_start + argument_count] != segment.arguments:
            continue
        return any(
            shell_token_has_active_expansion(token.raw) or shell_token_has_active_pathname_expansion(token.raw)
            for token in contextual_tokens[argument_start : argument_start + argument_count]
        )
    return True


@dataclass(frozen=True, slots=True)
class SyngrapheSafeFlagMatcher:
    """Require exact parsing and documented flag spelling before a safe variant.

    The shared matcher proves flag position and option-value ownership. Its
    generic boolean-assignment semantics and fallback parses alone are not a
    verified Syngraphe preview. Only canonical tokens are inspected here.
    """

    matchers: tuple[CommandMatcher, ...]
    flag: str
    options_with_values: frozenset[str]

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        if command.confidence != "exact":
            return ()
        evidence: list[MatcherEvidence] = []
        for item in (item for child in self.matchers for item in child.match(command)):
            segment = command.segments[item.segment_index]
            # Expansion may introduce a value-taking option before the preview
            # flag. xargs replacement can rewrite even a literal flag at launch.
            # Neither is proven side-effect-free by canonical token matching.
            if _arguments_have_active_shell_expansion(segment):
                continue
            if executable_name(segment.executable) == "xargs" and any(
                argument.startswith(("-I", "-i", "--replace")) for argument in segment.arguments
            ):
                continue
            semantics = argument_semantics(
                segment.arguments,
                options_with_values=self.options_with_values,
            )
            if self.flag not in semantics.present_flags:
                continue
            if self.flag.startswith("--") and semantics.option_token(self.flag) != self.flag:
                continue
            evidence.append(item)
        return tuple(evidence)


def _rule(
    name: str,
    title: str,
    description: str,
    action: str,
    example: str,
    matcher: AnyMatcher,
    safer_alternatives: tuple[str, ...] = _SAFER_ALTERNATIVES,
) -> CommandSafetyRule:
    value_options = frozenset(
        option
        for child in matcher.matchers
        if isinstance(child, ExecutablePathSetMatcher)
        for option in child.interspersed_options_with_values | child.leading_options_with_values
    )
    variants: list[CommandSafeVariant] = []
    for variant_id, flag, label in (
        ("dry-run", "--dry-run", "Syngraphe side-effect-free plan"),
        ("help", "--help", "Syngraphe command help"),
        ("short-help", "-h", "Syngraphe command help"),
        ("version", "--version", "Syngraphe version"),
        ("short-version", "-v", "Syngraphe version"),
    ):
        variant = safe_flag_variant(matcher, variant_id=variant_id, title=label, flag=flag)
        variants.append(
            CommandSafeVariant(
                variant_id=variant_id,
                title=label,
                matcher=SyngrapheSafeFlagMatcher((variant.matcher,), flag, value_options),
            )
        )
    return CommandSafetyRule(
        rule_id=f"command.syngraphe.{name}",
        title=title,
        description=description,
        severity="medium",
        # Guard uses this existing class for workspace writes (e.g. Probe),
        # including operations that are not destructive.
        risk_classes=("destructive_shell",),
        action_classes=(action,),
        safer_alternatives=safer_alternatives,
        default_mode="review",
        matcher=matcher,
        safe_variants=tuple(variants),
        example_command=example,
    )


SYNGRAPHE_COMMAND_RULES = (
    _rule(
        "init",
        "Syngraphe context initialization",
        "Creates .context/, inserts managed blocks in agent bootstrap files, replaces a managed body an earlier "
        "Syngraphe published, and with --policy also creates AGENT-POLICY.md.",
        "Syngraphe initialization command",
        "syngraphe init",
        _mutation_paths(("init",), command_flags=_INIT_FLAGS),
    ),
    _rule(
        "policy-add",
        "Syngraphe agent policy creation",
        "Creates AGENT-POLICY.md at the repository root as a starting point for agent operating rules that the "
        "repository owns and Syngraphe never manages afterwards; --force replaces an existing one.",
        "Syngraphe agent policy command",
        "syngraphe policy add",
        _mutation_paths(("policy", "add"), command_flags=_POLICY_FLAGS),
        safer_alternatives=_POLICY_SAFER_ALTERNATIVES,
    ),
    _rule(
        "document-new",
        "Syngraphe shared context creation",
        "Creates persistent truth, decision, state, or history Markdown shared by humans and coding agents.",
        "Syngraphe document creation command",
        "syngraphe truth new domain-model",
        _mutation_paths(*((category, "new") for category in ("truth", "decision", "state", "history")), creation=True),
    ),
    _rule(
        "state-archive",
        "Syngraphe state archiving",
        "Creates a history document and resets .context/state/current.md, updating shared repository context.",
        "Syngraphe state archive command",
        "syngraphe state archive phase-one",
        _mutation_paths(("state", "archive")),
    ),
)

SYNGRAPHE_ACTION_RISK_CLASSES = {
    action.lower(): rule.risk_classes for rule in SYNGRAPHE_COMMAND_RULES for action in rule.action_classes
}

SYNGRAPHE_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.syngraphe",
        name="Syngraphe repository context protection",
        description=(
            "Reviews shared repository context initialization, document creation, "
            "state archiving, and agent policy creation through syngraphe or syg."
        ),
        action_classes=tuple(action for rule in SYNGRAPHE_COMMAND_RULES for action in rule.action_classes),
        risk_classes=("destructive_shell",),
        safer_alternatives=_POLICY_SAFER_ALTERNATIVES,
        reference_urls=("https://github.com/suffro/syngraphe", "https://syngraphe.dev/"),
        executables=_EXECUTABLES,
        ecosystem_ids=("syngraphe",),
        project_markers=(".context",),
    ),
)

"""Structured rules and metadata for the sandbin command safety extension."""

from __future__ import annotations

from dataclasses import dataclass

from .command_extension_matchers import executable_matcher, executable_names
from .command_extension_specs import CommandExtensionSpec
from .command_matcher_contracts import MatcherEvidence
from .command_model import CanonicalCommand
from .command_option_parsing import argument_semantics
from .command_rules import AllMatcher, AnyMatcher, CommandSafetyRule, CommandSafeVariant, _segment_matches_executable

# Flag surface verified against sandbin's own bin/sandbin.mjs (a plain
# switch-based argv parser, not argparse: unlike repo2nb's --f/--fo/--for
# prefix abbreviation, only the literal --server/-s and --reconnect
# spellings are ever recognized). `run` only reaches a remote instance when
# --server/-s is present; without it, sandbin executes the guest in-process
# on the local host and never issues a network request at all, so it is
# intentionally outside this matcher's scope. `run --server ... --reconnect
# <runId>` re-attaches to an already-accepted run's WebSocket stream instead
# of calling POST /runs, so it creates no new job and is exempted below.
_SANDBIN_RUN_OPTIONS_WITH_VALUES: frozenset[str] = frozenset(
    {
        "--server",
        "-s",
        "--language",
        "-l",
        "--eval",
        "-e",
        "--stdin",
        "-i",
        "--key",
        "-k",
        "--reconnect",
        "--memory",
        "--cpu",
        "--timeout",
        "--pids",
    }
)

_SANDBIN_RUN_SERVER = AnyMatcher(
    matchers=tuple(
        executable_matcher(
            "sandbin",
            "run",
            required_flags=frozenset({server_flag}),
            options_with_values=_SANDBIN_RUN_OPTIONS_WITH_VALUES,
            fail_secure_unknown_options=True,
        )
        for server_flag in ("--server", "-s")
    )
)


@dataclass(frozen=True, slots=True)
class _SandbinBareReconnectToken:
    """Match `--reconnect <value>` only exactly as sandbin's own parser would.

    Two ways a naive token scan gets this wrong, both real review findings:

    1. The shared option-value parser normalizes `--reconnect=<id>` to the
       same effective flag as a space-separated `--reconnect <id>`, but
       sandbin's own argv parser (bin/sandbin.mjs) is a plain switch on exact
       tokens with no `--flag=value` support at all: `--reconnect=<id>`
       never matches the literal `'--reconnect'` case, falls through to
       sandbin's unknown-option branch, and aborts before any network call.
    2. `--reconnect` can appear as *another* option's consumed value rather
       than as a flag at all -- e.g. `sandbin run --server evil.com -e
       --reconnect` is a fresh submission whose --eval payload literally is
       the string "--reconnect"; it isn't a flag there, and must not be
       mistaken for one.

    argument_semantics() already resolves both correctly: it walks the
    argv the same position/consumption-aware way the base matcher's own
    required_flags check does (so a value swallowed by -e/--language/etc.
    never becomes its own flag), and effective_options records each
    surviving flag's exact raw token, not just its normalized name -- so an
    unconsumed but `=`-joined spelling is still distinguishable from the
    literal, space-separated one sandbin actually understands.
    """

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        evidence: list[MatcherEvidence] = []
        for index, segment in enumerate(command.segments):
            if not _segment_matches_executable(segment, executable_names("sandbin")):
                continue
            lowered_arguments = tuple(argument.lower() for argument in segment.arguments)
            semantics = argument_semantics(lowered_arguments, options_with_values=_SANDBIN_RUN_OPTIONS_WITH_VALUES)
            if semantics.option_token("--reconnect") != "--reconnect":
                continue
            evidence.append(
                MatcherEvidence(
                    segment_index=index,
                    executable=segment.executable,
                    detail="Matched a bare --reconnect token, sandbin's only recognized reconnect spelling.",
                )
            )
        return tuple(evidence)


_SANDBIN_RUN_SERVER_RECONNECT = AllMatcher(matchers=(_SANDBIN_RUN_SERVER, _SandbinBareReconnectToken()))

_SANDBIN_KEYS_CREATE = executable_matcher(
    "sandbin",
    "keys",
    "create",
    options_with_values=frozenset({"--server", "-s"}),
    fail_secure_unknown_options=True,
)

SANDBIN_COMMAND_RULES = (
    CommandSafetyRule(
        rule_id="command.sandbin.run-server",
        title="sandbin remote run submission",
        description=(
            "Identifies `sandbin run --server` submissions, which POST a new "
            "sandboxed execution job to a remote sandbin instance and consume "
            "that instance's queue and rate-limit quota. `--reconnect "
            "<runId>` re-attaches to a run already accepted by the server "
            "instead of submitting a new one and is exempted below; a local "
            "run (no --server) never leaves the machine and is not covered "
            "by this rule."
        ),
        severity="medium",
        risk_classes=("network_egress", "execution"),
        action_classes=("sandbin remote run submission command",),
        safer_alternatives=(
            "Reconnect to an existing run with --reconnect <runId> instead of resubmitting the same code.",
            "Confirm the target --server is trusted before sending code to it for execution.",
        ),
        matcher=_SANDBIN_RUN_SERVER,
        safe_variants=(
            CommandSafeVariant(
                variant_id="reconnect",
                title="sandbin run --reconnect (attaches to an existing run, submits nothing new)",
                matcher=_SANDBIN_RUN_SERVER_RECONNECT,
            ),
        ),
        example_command="sandbin run script.py --server sandbin.example.com",
    ),
    CommandSafetyRule(
        rule_id="command.sandbin.keys-create",
        title="sandbin API key issuance",
        description=(
            "Identifies `sandbin keys create`, which mints a new sandbin API "
            "key against a remote server. The key is printed to stdout and "
            "carries its own request quota, so an unattended caller minting "
            "one unreviewed can accumulate live credentials with no natural "
            "cap."
        ),
        severity="medium",
        risk_classes=("network_egress",),
        action_classes=("sandbin API key issuance command",),
        safer_alternatives=(
            "Check whether a key already exists for this purpose with `sandbin keys status <key>` first.",
            "Confirm the target --server is trusted before requesting a credential from it.",
        ),
        matcher=_SANDBIN_KEYS_CREATE,
        example_command="sandbin keys create --server sandbin.example.com",
    ),
)

SANDBIN_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.sandbin",
        name="sandbin command protection",
        description=(
            "Reviews sandbin commands that submit a new remote sandbox job "
            "or mint a new API key, while leaving read-only commands "
            "(languages, keys status, run --reconnect) unreviewed."
        ),
        action_classes=(
            "sandbin remote run submission command",
            "sandbin API key issuance command",
        ),
        risk_classes=("network_egress", "execution"),
        safer_alternatives=(
            "Reconnect to an existing run instead of resubmitting the same code.",
            "Confirm the target server is trusted before sending code or requesting a credential.",
        ),
        reference_urls=("https://github.com/ayazdoruck/sandbin",),
    ),
)

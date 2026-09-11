"""Structured rules and metadata for the sandbin command safety extension."""

from __future__ import annotations

from .command_extension_matchers import executable_matcher, safe_flag_variant
from .command_extension_specs import CommandExtensionSpec
from .command_rules import AnyMatcher, CommandSafetyRule

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
            safe_flag_variant(
                _SANDBIN_RUN_SERVER,
                variant_id="reconnect",
                title="sandbin run --reconnect (attaches to an existing run, submits nothing new)",
                flag="--reconnect",
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

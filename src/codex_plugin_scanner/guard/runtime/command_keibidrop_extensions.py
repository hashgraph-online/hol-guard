"""Structured rules and metadata for the KeibiDrop command safety extension."""

from __future__ import annotations

from .command_extension_matchers import executable_matcher, executable_names
from .command_extension_specs import CommandExtensionSpec
from .command_rules import AnyMatcher, CommandSafetyRule

# Verb surface verified against kd 0.4.7 (KeibiDrop cmd/kd/main.go, cmd/kd/agent.go).
#
# kd dispatches on os.Args[1], so the verb is always the first argument and no
# global option can precede it. Only --timeout=<seconds> and --timeout <seconds>
# are pulled out of the arguments after the verb; everything else stays
# positional and reaches the daemon unchanged.
#
# kd has no per-verb help. `kd pull --help` asks the daemon for a remote file
# named --help, so it is a pull attempt, not a help command, and no --help safe
# variant belongs on these rules. Help is `kd help`, `kd --help` and `kd -h`,
# which carry no verb and never reach a matcher here.
#
# Matching covers direct invocation, including an absolute path and an env-var
# prefix, both of which the parser already reduces to the kd basename, and the
# exec and xargs wrappers over kd, kd.exe and kd.cmd.
#
# Only the wrappers parse options conservatively, because their own option
# surface decides where the nested command starts, and each wrapper carries its
# own option set: exec and xargs share no options at all. A direct kd takes its
# verb at argv[1] and nowhere else, so an option there means some other command
# ran:
# `kd --help pull` prints help and `kd --timeout 30 pull x` fails on an unknown
# verb. Neither pulls anything, so neither is reviewed.

# A wrapper names kd as an argument, which executable_names never reaches, so
# the portable names are spelled out for those forms too. Sorted, because the
# catalog digest has to come out the same on every run.
_KD_NAMES: tuple[str, ...] = tuple(sorted(executable_names("kd")))

_KEIBIDROP_LAUNCHERS: tuple[tuple[str, ...], ...] = (
    ("kd",),
    *(("exec", name) for name in _KD_NAMES),
    *(("xargs", name) for name in _KD_NAMES),
)
_WRAPPERS: frozenset[str] = frozenset({"exec", "xargs"})

# ExecutableMatcher lowercases leading_options_with_values (command_rules.py
# __post_init__) and lowercases the arguments it parses, so a declared option
# also claims its opposite-case twin. xargs is full of such pairs, and each one
# where the twin does NOT take a value turns the parser confidently wrong: it
# eats the next token, which is kd itself, and the rule is skipped.
#
# So an option is declared only when its twin either does not exist or also
# takes a value. Anything else is left undeclared on purpose. An undeclared
# option makes the parse uncertain rather than wrong, and uncertain is handled
# by fail_secure_unknown_options, which walks both the value and the flag
# reading and observes the command if either one reaches the verb.
#
#   -n   no -N                             declared
#   -s   -S is BSD replsize, also a value  declared
#   -J   no -j                             declared
#   -a   no -A                             declared, GNU --arg-file short form
#   -d   no -D                             declared, GNU --delimiter short form
#   -P   -p is interactive, a flag         NOT declared
#   -I   -i takes an attached value        NOT declared
#   -L   -l takes an attached value        NOT declared
#   -R   -r is no-run-if-empty, a flag     NOT declared
#   -E   -e takes an attached value        NOT declared
#
# Long options have no case twin, but GNU gives three of them an OPTIONAL
# value: --eof[=str], --replace[=str] and --max-lines[=n]. Declaring those has
# the same effect as a mis-cased short option, since the bare form then eats kd.
# They are left undeclared for the same reason. The =value spelling of any long
# option is one token, so it is read correctly either way.
_XARGS_LEADING_OPTIONS_WITH_VALUES = frozenset(
    {
        "-n",
        "-s",
        "-J",
        "-a",
        "-d",
        "--arg-file",
        "--delimiter",
        "--max-args",
        "--max-chars",
        "--max-procs",
        "--process-slot-var",
    }
)

# exec is the shell builtin: exec [-cl] [-a name] command. Only -a carries a
# value, and there is no -A. Giving exec the xargs option set, as this file did
# before, made `exec -l kd pull x` skip the rule, because -l read as -L.
_EXEC_LEADING_OPTIONS_WITH_VALUES = frozenset({"-a"})

_LEADING_OPTIONS_WITH_VALUES: dict[str, frozenset[str]] = {
    "xargs": _XARGS_LEADING_OPTIONS_WITH_VALUES,
    "exec": _EXEC_LEADING_OPTIONS_WITH_VALUES,
}

_KD_OPTIONS_WITH_VALUES = frozenset({"--timeout"})


def _kd_verb_matcher(*verbs: str) -> AnyMatcher:
    """Match the named kd verbs through every launcher shape."""

    return AnyMatcher(
        matchers=tuple(
            executable_matcher(
                *launcher,
                verb,
                options_with_values=_KD_OPTIONS_WITH_VALUES,
                allow_leading_options=launcher[0] in _WRAPPERS,
                leading_options_with_values=_LEADING_OPTIONS_WITH_VALUES.get(launcher[0], frozenset()),
                fail_secure_unknown_options=launcher[0] in _WRAPPERS,
            )
            for launcher in _KEIBIDROP_LAUNCHERS
            for verb in verbs
        )
    )


# add-as is add plus a remote name, so both belong to one share boundary.
_KEIBIDROP_SHARE = _kd_verb_matcher("add", "add-as")

# pull-async is pull without the wait and bench-pull is pull plus a delete, so
# all three write peer bytes to a local path chosen the same way.
_KEIBIDROP_PULL = _kd_verb_matcher("pull", "pull-async", "bench-pull")

_KEIBIDROP_REGISTER = _kd_verb_matcher("register")

KEIBIDROP_COMMAND_RULES = (
    CommandSafetyRule(
        rule_id="command.keibidrop.share-file",
        title="KeibiDrop file share",
        description=(
            "Identifies `kd add` and `kd add-as`, which add a local file to "
            "the set the connected peer can read. `add-as` supplies its own "
            "remote name, so the name the peer sees need not be the name on "
            "disk."
        ),
        severity="high",
        risk_classes=("data_flow_exfiltration", "network_egress"),
        action_classes=("keibidrop file share command",),
        safer_alternatives=(
            "Run kd list first to see what this session already shares.",
            "Run kd status to confirm which peer is connected before sharing.",
            "Run kd unshare <name> to stop sharing a file.",
        ),
        matcher=_KEIBIDROP_SHARE,
        default_mode="review",
    ),
    CommandSafetyRule(
        rule_id="command.keibidrop.pull-file",
        title="KeibiDrop remote file write",
        description=(
            "Identifies `kd pull`, `kd pull-async` and `kd bench-pull`, which "
            "write a file from the peer to a local path. Given no second "
            "argument the destination is the name the peer chose, so the "
            "remote side picks the path. The write creates missing parent "
            "directories and truncates a file already there. `bench-pull` "
            "deletes the destination after measuring it."
        ),
        severity="high",
        risk_classes=("destructive_shell", "network_egress"),
        action_classes=("keibidrop remote file write command",),
        safer_alternatives=(
            "Pass an explicit local path so the peer's name cannot pick the destination.",
            "Run kd list first to see the remote names on offer.",
            "Read a remote name for path separators before pulling it by name alone.",
        ),
        matcher=_KEIBIDROP_PULL,
        default_mode="review",
    ),
    CommandSafetyRule(
        rule_id="command.keibidrop.register-peer",
        title="KeibiDrop peer authorization",
        description=(
            "Identifies `kd register`, which sets the peer this session "
            "accepts, from a fingerprint, from an invite link carrying one, "
            "or on a local network from a direct address. Everything shared "
            "or pulled afterwards goes to or comes from that peer."
        ),
        severity="high",
        risk_classes=("data_flow_exfiltration", "network_egress"),
        action_classes=("keibidrop peer authorization command",),
        safer_alternatives=(
            "Compare the code against the one the peer sent over a channel you trust.",
            "Run kd show fingerprint and confirm both sides hold the other's code.",
            "Use kd contacts and kd quick-connect for a peer already verified once.",
        ),
        matcher=_KEIBIDROP_REGISTER,
        default_mode="review",
    ),
)

KEIBIDROP_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.keibidrop",
        name="KeibiDrop command protection",
        description=(
            "Reviews kd commands that share a local file with a peer, write a "
            "peer's file to local disk, or set which peer identity the session "
            "accepts."
        ),
        action_classes=(
            "keibidrop file share command",
            "keibidrop remote file write command",
            "keibidrop peer authorization command",
        ),
        risk_classes=("data_flow_exfiltration", "destructive_shell", "network_egress"),
        safer_alternatives=(
            "Run kd list and kd status to see what is shared and who is connected.",
            "Give kd pull an explicit local path instead of the peer's name.",
            "Check a peer code against the one you were sent before registering it.",
        ),
        reference_urls=(
            "https://github.com/KeibiSoft/KeibiDrop",
            "https://keibidrop.com/docs/reference/kd-cli.html",
        ),
    ),
)

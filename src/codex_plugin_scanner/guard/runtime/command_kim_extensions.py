"""Structured rules and metadata for the kim command safety extension."""

from __future__ import annotations

from .command_extension_matchers import executable_matcher
from .command_extension_specs import CommandExtensionSpec
from .command_rules import AnyMatcher, CommandSafetyRule

# Effectful surface verified against kim (kim/cli.py): every subcommand that
# mutates the local reminder config, daemon state, notification settings, or
# the installed kim itself is reviewed. Dispatch requires the literal
# subcommand as the first argument after the kim launcher (the only root-level
# options are -v/--version), so conservative matching keys off the exact
# subcommand token. Read-only subcommands (`list`, `status`, `logs`,
# `validate`, `completion`) and read-only *forms* of effectful subcommands
# deliberately stay out of these matchers so they remain automatic even after
# the extension is enabled: `sound`/`slack` without a mutating flag only print
# the current settings, and `export` without `-o/--output` prints to stdout.
# The mutating forms require their mutation flag (`--set`/`--clear`/`--test`/
# `--enable`/`--disable`, `--test`, `-o`/`--output` respectively). The hidden
# `_remind-fire` subcommand is also excluded: it is a daemon-internal
# implementation detail spawned by the daemon itself to fire scheduled
# reminders (Windows `cmd /c kim _remind-fire ...`), so reviewing it would
# surface every daemon-scheduled notification rather than a user-proposed
# command.
#
# Conservative matching covers the same launcher surface as repo2nb:
# - Standard launchers: kim, python -m kim, python3 -m kim, py -m kim
# - Shell wrappers: exec kim ..., xargs kim ...
# - Wrapper leading options for exec/xargs (-n -P -I -L -s)
# - Fail-secure option parsing: unknown options prevent unsafe bypasses

_KIM_LAUNCHERS: tuple[tuple[str, ...], ...] = (
    ("kim",),
    ("python", "-m", "kim"),
    ("python3", "-m", "kim"),
    ("py", "-m", "kim"),
    ("exec", "kim"),
    ("exec", "python", "-m", "kim"),
    ("exec", "python3", "-m", "kim"),
    ("exec", "py", "-m", "kim"),
    ("xargs", "kim"),
    ("xargs", "python", "-m", "kim"),
    ("xargs", "python3", "-m", "kim"),
    ("xargs", "py", "-m", "kim"),
)
_WRAPPER_LEADING_OPTIONS_WITH_VALUES = frozenset({"-n", "-P", "-I", "-L", "-s"})

# Value-taking options per subcommand surface (verified against kim/cli.py).
_KIM_RECURRING_OPTIONS_WITH_VALUES = frozenset(
    {
        "-I",
        "--interval",
        "--every",
        "--at",
        "-t",
        "--title",
        "-m",
        "--message",
        "-u",
        "--urgency",
        "--tz",
        "--sound-file",
        "--slack-channel",
        "--slack-webhook",
    }
)
_KIM_REMIND_OPTIONS_WITH_VALUES = frozenset({"-t", "--title", "--tz"})
_KIM_EXPORT_OPTIONS_WITH_VALUES = frozenset({"-f", "--format", "-o", "--output"})
_KIM_IMPORT_OPTIONS_WITH_VALUES = frozenset({"-f", "--format"})
_KIM_SOUND_OPTIONS_WITH_VALUES = frozenset({"--set"})
_KIM_SLACK_OPTIONS_WITH_VALUES = frozenset({"-t", "--title", "-m", "--message"})


def _kim_review_matcher(
    subcommand: str,
    *,
    options_with_values: frozenset[str] = frozenset(),
    alias_subcommands: tuple[str, ...] = (),
    required_flag_sets: tuple[frozenset[str], ...] = (),
) -> AnyMatcher:
    """Review one effectful subcommand across every supported launcher.

    ``required_flag_sets`` restricts matching to invocations that carry at
    least one of the given flag sets, so read-only inspection forms of a
    subcommand (for example bare ``kim sound`` or ``kim slack``) stay
    automatic.
    """

    flag_sets = required_flag_sets or (frozenset(),)
    matchers = tuple(
        executable_matcher(
            *launcher,
            subcommand,
            options_with_values=options_with_values,
            required_flags=flags,
            allow_leading_options=launcher[0] in ("exec", "xargs"),
            leading_options_with_values=(
                _WRAPPER_LEADING_OPTIONS_WITH_VALUES
                if launcher[0] in ("exec", "xargs")
                else frozenset()
            ),
            fail_secure_unknown_options=True,
        )
        for launcher in _KIM_LAUNCHERS
        for flags in flag_sets
    )
    aliases = tuple(
        executable_matcher(
            *launcher,
            alias,
            options_with_values=options_with_values,
            required_flags=flags,
            allow_leading_options=launcher[0] in ("exec", "xargs"),
            leading_options_with_values=(
                _WRAPPER_LEADING_OPTIONS_WITH_VALUES
                if launcher[0] in ("exec", "xargs")
                else frozenset()
            ),
            fail_secure_unknown_options=True,
        )
        for launcher in _KIM_LAUNCHERS
        for alias in alias_subcommands
        for flags in flag_sets
    )
    return AnyMatcher(matchers=(*matchers, *aliases))


_KIM_ADD = _kim_review_matcher("add", options_with_values=_KIM_RECURRING_OPTIONS_WITH_VALUES)
_KIM_REMOVE = _kim_review_matcher("remove")
_KIM_UPDATE = _kim_review_matcher("update", options_with_values=_KIM_RECURRING_OPTIONS_WITH_VALUES)
_KIM_ENABLE = _kim_review_matcher("enable")
_KIM_DISABLE = _kim_review_matcher("disable")
_KIM_REMIND = _kim_review_matcher("remind", options_with_values=_KIM_REMIND_OPTIONS_WITH_VALUES)
_KIM_IMPORT = _kim_review_matcher("import", options_with_values=_KIM_IMPORT_OPTIONS_WITH_VALUES)
_KIM_EXPORT = _kim_review_matcher(
    "export",
    options_with_values=_KIM_EXPORT_OPTIONS_WITH_VALUES,
    required_flag_sets=(frozenset({"-o"}), frozenset({"--output"})),
)
_KIM_START = _kim_review_matcher("start")
_KIM_STOP = _kim_review_matcher("stop")
_KIM_EDIT = _kim_review_matcher("edit")
_KIM_SOUND = _kim_review_matcher(
    "sound",
    options_with_values=_KIM_SOUND_OPTIONS_WITH_VALUES,
    required_flag_sets=(
        frozenset({"--set"}),
        frozenset({"--clear"}),
        frozenset({"--test"}),
        frozenset({"--enable"}),
        frozenset({"--disable"}),
    ),
)
_KIM_SLACK = _kim_review_matcher(
    "slack",
    options_with_values=_KIM_SLACK_OPTIONS_WITH_VALUES,
    required_flag_sets=(frozenset({"--test"}),),
)
_KIM_INTERACTIVE = _kim_review_matcher(
    "interactive",
    alias_subcommands=("-i",),
)
_KIM_SELF_UPDATE = _kim_review_matcher("self-update")
_KIM_UNINSTALL = _kim_review_matcher("uninstall")

KIM_COMMAND_RULES = (
    CommandSafetyRule(
        rule_id="command.kim.add",
        title="kim reminder creation",
        description=(
            "Identifies `kim add`, which writes a new recurring or one-shot "
            "reminder into the local kim config. Reviewing creation prevents "
            "an assistant from silently installing scheduled notifications "
            "or their recurring side effects."
        ),
        severity="low",
        risk_classes=("destructive_shell",),
        action_classes=("kim reminder add command",),
        safer_alternatives=(
            "List existing reminders with kim list before creating new ones.",
            "Confirm the exact title, message, and schedule with the user.",
        ),
        matcher=_KIM_ADD,
        default_mode="review",
    ),
    CommandSafetyRule(
        rule_id="command.kim.remove",
        title="kim reminder removal",
        description=(
            "Identifies `kim remove`, which permanently deletes a reminder "
            "from the local kim config. Reviewing removal prevents an "
            "assistant from discarding user-scheduled notifications."
        ),
        severity="medium",
        risk_classes=("destructive_shell",),
        action_classes=("kim reminder remove command",),
        safer_alternatives=("List existing reminders with kim list and confirm the exact name before removing it.",),
        matcher=_KIM_REMOVE,
        default_mode="review",
    ),
    CommandSafetyRule(
        rule_id="command.kim.update",
        title="kim reminder update",
        description=(
            "Identifies `kim update`, which rewrites an existing reminder's "
            "schedule, title, message, or enabled state in the local kim "
            "config. Reviewing updates prevents silent changes to "
            "user-scheduled notifications."
        ),
        severity="medium",
        risk_classes=("destructive_shell",),
        action_classes=("kim reminder update command",),
        safer_alternatives=("Show the current reminder details first, then confirm the exact change with the user.",),
        matcher=_KIM_UPDATE,
        default_mode="review",
    ),
    CommandSafetyRule(
        rule_id="command.kim.enable",
        title="kim reminder enable",
        description=(
            "Identifies `kim enable`, which activates a disabled reminder in "
            "the local kim config. Reviewing the enable prevents an assistant "
            "from silently re-activating scheduled notifications."
        ),
        severity="low",
        risk_classes=("destructive_shell",),
        action_classes=("kim reminder enable command",),
        safer_alternatives=("List reminders with kim list and confirm the exact name before enabling it.",),
        matcher=_KIM_ENABLE,
        default_mode="review",
    ),
    CommandSafetyRule(
        rule_id="command.kim.disable",
        title="kim reminder disable",
        description=(
            "Identifies `kim disable`, which deactivates a reminder in the "
            "local kim config. Reviewing the disable prevents an assistant "
            "from silently silencing user-scheduled notifications."
        ),
        severity="medium",
        risk_classes=("destructive_shell",),
        action_classes=("kim reminder disable command",),
        safer_alternatives=("List reminders with kim list and confirm the exact name before disabling it.",),
        matcher=_KIM_DISABLE,
        default_mode="review",
    ),
    CommandSafetyRule(
        rule_id="command.kim.remind",
        title="kim one-shot reminder",
        description=(
            "Identifies `kim remind`, which schedules a one-shot reminder "
            "that fires a persistent notification after a delay. Reviewing "
            "the one-shot prevents an assistant from silently scheduling a "
            "surprise notification."
        ),
        severity="low",
        risk_classes=("destructive_shell",),
        action_classes=("kim one-shot reminder command",),
        safer_alternatives=("Confirm the exact message and fire time with the user before scheduling.",),
        matcher=_KIM_REMIND,
        default_mode="review",
    ),
    CommandSafetyRule(
        rule_id="command.kim.import",
        title="kim reminder import",
        description=(
            "Identifies `kim import`, which loads reminders from a file and "
            "can wholesale replace the local kim config. Reviewing the import "
            "prevents an assistant from injecting many notifications or "
            "overwriting the user's existing schedule."
        ),
        severity="high",
        risk_classes=("destructive_shell",),
        action_classes=("kim reminder import command",),
        safer_alternatives=(
            "Show the import file contents to the user and confirm the destination config before importing.",
            "Prefer kim import --merge to avoid overwriting existing reminders.",
        ),
        matcher=_KIM_IMPORT,
        default_mode="review",
    ),
    CommandSafetyRule(
        rule_id="command.kim.export",
        title="kim reminder export",
        description=(
            "Identifies `kim export`, which writes the local kim reminders to "
            "an output file. Reviewing the export prevents an assistant from "
            "silently writing reminder contents to an arbitrary path."
        ),
        severity="low",
        risk_classes=("destructive_shell",),
        action_classes=("kim reminder export command",),
        safer_alternatives=("Confirm the output path with the user before exporting reminders to a file.",),
        matcher=_KIM_EXPORT,
        default_mode="review",
    ),
    CommandSafetyRule(
        rule_id="command.kim.start",
        title="kim daemon start",
        description=(
            "Identifies `kim start`, which spawns the kim reminder daemon as "
            "a detached background process. Reviewing the start prevents an "
            "assistant from silently launching a persistent notification "
            "process."
        ),
        severity="medium",
        risk_classes=("destructive_shell",),
        action_classes=("kim daemon start command",),
        safer_alternatives=("Check kim status to confirm whether the daemon is running and why a start is needed.",),
        matcher=_KIM_START,
        default_mode="review",
    ),
    CommandSafetyRule(
        rule_id="command.kim.stop",
        title="kim daemon stop",
        description=(
            "Identifies `kim stop`, which stops the kim reminder daemon and "
            "suspends all future notifications. Reviewing the stop prevents "
            "an assistant from disabling scheduled reminders without user "
            "awareness."
        ),
        severity="medium",
        risk_classes=("destructive_shell",),
        action_classes=("kim daemon stop command",),
        safer_alternatives=("Check kim status to confirm whether the daemon is running and why a stop is needed.",),
        matcher=_KIM_STOP,
        default_mode="review",
    ),
    CommandSafetyRule(
        rule_id="command.kim.edit",
        title="kim config edit",
        description=(
            "Identifies `kim edit`, which opens the local kim config in the "
            "user's $EDITOR. Reviewing the edit prevents an assistant from "
            "launching an editor on kim's configuration without user "
            "awareness."
        ),
        severity="medium",
        risk_classes=("destructive_shell",),
        action_classes=("kim config edit command",),
        safer_alternatives=("Show the current kim config with kim list or kim status before editing it.",),
        matcher=_KIM_EDIT,
        default_mode="review",
    ),
    CommandSafetyRule(
        rule_id="command.kim.sound",
        title="kim sound configuration",
        description=(
            "Identifies `kim sound`, which changes the local kim notification "
            "sound settings. Reviewing sound mutations prevents an assistant "
            "from silently adjusting or disabling user notification sound."
        ),
        severity="low",
        risk_classes=("destructive_shell",),
        action_classes=("kim sound settings command",),
        safer_alternatives=("Show the current sound configuration with kim sound before changing it.",),
        matcher=_KIM_SOUND,
        default_mode="review",
    ),
    CommandSafetyRule(
        rule_id="command.kim.slack",
        title="kim slack configuration",
        description=(
            "Identifies `kim slack`, which inspects or test-sends Slack "
            "notification configuration. Reviewing slack commands prevents an "
            "assistant from silently sending test notifications through the "
            "user's Slack integration."
        ),
        severity="medium",
        risk_classes=("destructive_shell",),
        action_classes=("kim slack settings command",),
        safer_alternatives=("Show the current Slack configuration with kim slack before sending test notifications.",),
        matcher=_KIM_SLACK,
        default_mode="review",
    ),
    CommandSafetyRule(
        rule_id="command.kim.interactive",
        title="kim interactive mode",
        description=(
            "Identifies `kim interactive`, which enters an interactive session "
            "that can run arbitrary kim mutations. Reviewing interactive mode "
            "prevents an assistant from dropping into a direct mutating "
            "session without user awareness."
        ),
        severity="medium",
        risk_classes=("destructive_shell",),
        action_classes=("kim interactive command",),
        safer_alternatives=("Use individual kim subcommands so each mutation can be reviewed on its own.",),
        matcher=_KIM_INTERACTIVE,
        default_mode="review",
    ),
    CommandSafetyRule(
        rule_id="command.kim.self-update",
        title="kim self-update",
        description=(
            "Identifies `kim self-update`, which pulls and installs a new kim "
            "version over the network. Reviewing self-updates prevents an "
            "assistant from installing new executable code into the user's "
            "Python environment."
        ),
        severity="high",
        risk_classes=("destructive_shell",),
        action_classes=("kim self-update command",),
        safer_alternatives=("Confirm with the user before updating kim or any Python-installed tooling.",),
        matcher=_KIM_SELF_UPDATE,
        default_mode="review",
    ),
    CommandSafetyRule(
        rule_id="command.kim.uninstall",
        title="kim uninstall",
        description=(
            "Identifies `kim uninstall`, which removes kim and its scheduled "
            "reminders from the system. Reviewing uninstall prevents an "
            "assistant from permanently removing user-scheduled "
            "notifications."
        ),
        severity="critical",
        risk_classes=("destructive_shell",),
        action_classes=("kim uninstall command",),
        safer_alternatives=(
            "Confirm with the user before uninstalling kim; export reminders first if they want a backup.",
        ),
        matcher=_KIM_UNINSTALL,
        default_mode="review",
    ),
)

KIM_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.kim",
        name="kim reminder protection",
        description=(
            "Reviews kim commands that mutate the local reminder config, "
            "daemon state, or notification settings; read-only inspection "
            "stays automatic."
        ),
        action_classes=(
            "kim reminder add command",
            "kim reminder remove command",
            "kim reminder update command",
            "kim reminder enable command",
            "kim reminder disable command",
            "kim one-shot reminder command",
            "kim reminder import command",
            "kim reminder export command",
            "kim daemon start command",
            "kim daemon stop command",
            "kim config edit command",
            "kim sound settings command",
            "kim slack settings command",
            "kim interactive command",
            "kim self-update command",
            "kim uninstall command",
        ),
        risk_classes=("destructive_shell",),
        safer_alternatives=(
            "Preview the reminder list and daemon state with kim list and kim status before mutating them.",
            "Confirm the exact reminder name before removing, disabling, or updating it.",
        ),
        reference_urls=("https://github.com/pratikwayal01/kim",),
        ecosystem_ids=("kim",),
        executables=("kim",),
    ),
)

# Runtime risk classes for every kim action class (Kilo review parity). Every
# kim action that passes through these matchers is reviewed as a destructive
# shell command, matching the shared ``COMMAND_ACTION_RISK_CLASSES`` contract.
KIM_ACTION_RISK_CLASSES: dict[str, tuple[str, ...]] = {
    "kim reminder add command": ("destructive_shell",),
    "kim reminder remove command": ("destructive_shell",),
    "kim reminder update command": ("destructive_shell",),
    "kim reminder enable command": ("destructive_shell",),
    "kim reminder disable command": ("destructive_shell",),
    "kim one-shot reminder command": ("destructive_shell",),
    "kim reminder import command": ("destructive_shell",),
    "kim reminder export command": ("destructive_shell",),
    "kim daemon start command": ("destructive_shell",),
    "kim daemon stop command": ("destructive_shell",),
    "kim config edit command": ("destructive_shell",),
    "kim sound settings command": ("destructive_shell",),
    "kim slack settings command": ("destructive_shell",),
    "kim interactive command": ("destructive_shell",),
    "kim self-update command": ("destructive_shell",),
    "kim uninstall command": ("destructive_shell",),
}

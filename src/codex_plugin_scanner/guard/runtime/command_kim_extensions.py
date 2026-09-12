"""Structured rules and metadata for the kim command safety extension."""

from __future__ import annotations

from .command_extension_matchers import executable_matcher
from .command_extension_specs import CommandExtensionSpec
from .command_rules import CommandSafetyRule

# Flag surface verified against kim (kim/cli.py): `add` requires a name plus
# one of -I/--interval/--every or --at, and accepts value-taking options
# (-t/--title, -m/--message, -u/--urgency, --tz, --sound-file,
# --slack-channel, --slack-webhook); `update` accepts the same value-taking
# options plus --enable/--disable; `remove` takes a name with an optional
# -o/--oneshot flag; `stop` stops the daemon with no arguments. Dispatch
# requires the literal subcommand as the first argument after the kim
# launcher (the only root-level options are -v/--version), so conservative
# matching keys off the exact subcommand token. Read-only subcommands
# (`list`, `status`, `logs`) deliberately stay out of these matchers so they
# remain automatic even after the extension is enabled.

_KIM_OPTIONS_WITH_VALUES = frozenset(
    {
        "-i",
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

_KIM_ADD = executable_matcher(
    "kim",
    "add",
    options_with_values=_KIM_OPTIONS_WITH_VALUES,
)
_KIM_REMOVE = executable_matcher("kim", "remove")
_KIM_UPDATE = executable_matcher(
    "kim",
    "update",
    options_with_values=_KIM_OPTIONS_WITH_VALUES,
)
_KIM_STOP = executable_matcher("kim", "stop")

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
)

KIM_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.kim",
        name="kim reminder protection",
        description=(
            "Reviews kim commands that mutate the local reminder config or "
            "stop the reminder daemon; read-only inspection stays automatic."
        ),
        action_classes=(
            "kim reminder add command",
            "kim reminder remove command",
            "kim reminder update command",
            "kim daemon stop command",
        ),
        risk_classes=("destructive_shell",),
        safer_alternatives=(
            "Preview the reminder list and daemon state with kim list and kim status before mutating them.",
            "Confirm the exact reminder name before removing or updating it.",
        ),
        reference_urls=("https://github.com/pratikwayal01/kim",),
    ),
)

"""Structured rules and metadata for the formicx agent command safety extension."""

from __future__ import annotations

from .command_extension_matchers import executable_matcher, safe_flag_variant
from .command_extension_specs import CommandExtensionSpec
from .command_rules import AnyMatcher, CommandSafetyRule

_FORMICX_LAUNCHERS: tuple[tuple[str, ...], ...] = (
    ("formicx",),
    ("python", "-m", "formicx"),
    ("python3", "-m", "formicx"),
    ("py", "-m", "formicx"),
    ("exec", "formicx"),
    ("exec", "python", "-m", "formicx"),
    ("exec", "python3", "-m", "formicx"),
    ("exec", "py", "-m", "formicx"),
    ("xargs", "formicx"),
    ("xargs", "python", "-m", "formicx"),
    ("xargs", "python3", "-m", "formicx"),
    ("xargs", "py", "-m", "formicx"),
)
_WRAPPER_LEADING_OPTIONS_WITH_VALUES = frozenset({"-n", "-P", "-I", "-L", "-s"})

# 1. agent register
_FORMICX_AGENT_REGISTER = AnyMatcher(
    matchers=tuple(
        executable_matcher(
            *launcher,
            "agent",
            "register",
            allow_leading_options=launcher[0] in ("exec", "xargs"),
            leading_options_with_values=(
                _WRAPPER_LEADING_OPTIONS_WITH_VALUES if launcher[0] in ("exec", "xargs") else frozenset()
            ),
            fail_secure_unknown_options=True,
        )
        for launcher in _FORMICX_LAUNCHERS
    )
)

# 2. agent start
_FORMICX_AGENT_START = AnyMatcher(
    matchers=tuple(
        executable_matcher(
            *launcher,
            "agent",
            "start",
            allow_leading_options=launcher[0] in ("exec", "xargs"),
            leading_options_with_values=(
                _WRAPPER_LEADING_OPTIONS_WITH_VALUES if launcher[0] in ("exec", "xargs") else frozenset()
            ),
            fail_secure_unknown_options=True,
        )
        for launcher in _FORMICX_LAUNCHERS
    )
)

# 3. agent stop
_FORMICX_AGENT_STOP = AnyMatcher(
    matchers=tuple(
        executable_matcher(
            *launcher,
            "agent",
            "stop",
            allow_leading_options=launcher[0] in ("exec", "xargs"),
            leading_options_with_values=(
                _WRAPPER_LEADING_OPTIONS_WITH_VALUES if launcher[0] in ("exec", "xargs") else frozenset()
            ),
            fail_secure_unknown_options=True,
        )
        for launcher in _FORMICX_LAUNCHERS
    )
)

# 4. agent restart
_FORMICX_AGENT_RESTART = AnyMatcher(
    matchers=tuple(
        executable_matcher(
            *launcher,
            "agent",
            "restart",
            allow_leading_options=launcher[0] in ("exec", "xargs"),
            leading_options_with_values=(
                _WRAPPER_LEADING_OPTIONS_WITH_VALUES if launcher[0] in ("exec", "xargs") else frozenset()
            ),
            fail_secure_unknown_options=True,
        )
        for launcher in _FORMICX_LAUNCHERS
    )
)

FORMICX_COMMAND_RULES = (
    CommandSafetyRule(
        rule_id="command.formicx.agent-register",
        title="formicx agent registration",
        description=(
            "Identifies `formicx agent register`, which registers an agent manifest "
            "and entrypoint with the formicxd daemon."
        ),
        severity="medium",
        risk_classes=("destructive_shell",),
        action_classes=("formicx agent registration command",),
        safer_alternatives=(
            "Validate the agent manifest first using `formicx agent validate <path>`.",
            "Review entrypoint script contents before registering.",
        ),
        matcher=_FORMICX_AGENT_REGISTER,
        default_mode="review",
        safe_variants=(
            safe_flag_variant(
                _FORMICX_AGENT_REGISTER,
                variant_id="help",
                title="formicx agent register command help",
                flag="--help",
            ),
        ),
    ),
    CommandSafetyRule(
        rule_id="command.formicx.agent-start",
        title="formicx agent process start",
        description=(
            "Identifies `formicx agent start`, which launches a background OS subprocess for an agent."
        ),
        severity="medium",
        risk_classes=("destructive_shell",),
        action_classes=("formicx agent process start command",),
        safer_alternatives=(
            "Inspect agent details using `formicx agent status <agent>` before starting.",
        ),
        matcher=_FORMICX_AGENT_START,
        default_mode="review",
        safe_variants=(
            safe_flag_variant(
                _FORMICX_AGENT_START,
                variant_id="help",
                title="formicx agent start command help",
                flag="--help",
            ),
        ),
    ),
    CommandSafetyRule(
        rule_id="command.formicx.agent-stop",
        title="formicx agent process stop",
        description=(
            "Identifies `formicx agent stop`, which terminates a running agent OS subprocess."
        ),
        severity="medium",
        risk_classes=("destructive_shell",),
        action_classes=("formicx agent process stop command",),
        safer_alternatives=(
            "Check active agent status using `formicx agent status <agent>` before stopping.",
        ),
        matcher=_FORMICX_AGENT_STOP,
        default_mode="review",
        safe_variants=(
            safe_flag_variant(
                _FORMICX_AGENT_STOP,
                variant_id="help",
                title="formicx agent stop command help",
                flag="--help",
            ),
        ),
    ),
    CommandSafetyRule(
        rule_id="command.formicx.agent-restart",
        title="formicx agent process restart",
        description=(
            "Identifies `formicx agent restart`, which stops and restarts an agent process."
        ),
        severity="medium",
        risk_classes=("destructive_shell",),
        action_classes=("formicx agent process restart command",),
        safer_alternatives=(
            "Check active agent status using `formicx agent status <agent>` before restarting.",
        ),
        matcher=_FORMICX_AGENT_RESTART,
        default_mode="review",
        safe_variants=(
            safe_flag_variant(
                _FORMICX_AGENT_RESTART,
                variant_id="help",
                title="formicx agent restart command help",
                flag="--help",
            ),
        ),
    ),
)

FORMICX_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.formicx",
        name="formicx agent command protection",
        description=(
            "Reviews Formicx mutation lifecycle commands (register, start, stop, restart) "
            "while leaving read-only queries (list, status, resources) automatic."
        ),
        action_classes=(
            "formicx agent registration command",
            "formicx agent process start command",
            "formicx agent process stop command",
            "formicx agent process restart command",
        ),
        risk_classes=("destructive_shell",),
        safer_alternatives=(
            "Validate agents using `formicx agent validate <path>` before registering.",
            "Check agent status using `formicx agent status <agent>`.",
        ),
        reference_urls=("https://github.com/Abbilaash/Formicx",),
    ),
)

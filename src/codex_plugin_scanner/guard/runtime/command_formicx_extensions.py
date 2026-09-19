"""Structured rules and metadata for the formicx agent command safety extension."""

from __future__ import annotations

from .command_extension_matchers import executable_matcher, safe_flag_variant
from .command_extension_specs import CommandExtensionSpec
from .command_rules import AnyMatcher, CommandSafetyRule

_PYTHON_PREFIXES: tuple[str, ...] = ("python", "python3", "py")
_PYTHON_OPTION_COMBINATIONS: tuple[tuple[str, ...], ...] = (
    (),
    ("-u",),
    ("-W", "ignore"),
    ("-W", "default"),
    ("-u", "-W", "ignore"),
    ("-u", "-W", "default"),
    ("-X", "dev"),
    ("-u", "-X", "dev"),
)

_DIRECT_LAUNCHERS: tuple[tuple[str, ...], ...] = (
    ("formicx",),
    *((py_bin, *opt, "-m", "formicx") for py_bin in _PYTHON_PREFIXES for opt in _PYTHON_OPTION_COMBINATIONS),
)

_WRAPPER_LAUNCHERS: tuple[tuple[str, ...], ...] = (
    *(("exec", *launcher) for launcher in _DIRECT_LAUNCHERS),
    *(("xargs", *launcher) for launcher in _DIRECT_LAUNCHERS),
)

_WRAPPER_LEADING_OPTIONS_WITH_VALUES = frozenset(
    {
        "-n",
        "-P",
        "-I",
        "-L",
        "-s",
        "-d",
        "-E",
        "-e",
        "-a",
        "--arg-file",
        "--delimiter",
        "--max-args",
        "--max-procs",
        "--max-lines",
        "--process-slot-var",
    }
)


def _build_formicx_matcher(*subcommands: str) -> AnyMatcher:
    matchers = [
        executable_matcher(
            *launcher,
            *subcommands,
            allow_leading_options=False,
            fail_secure_unknown_options=True,
        )
        for launcher in _DIRECT_LAUNCHERS
    ]
    matchers.extend(
        executable_matcher(
            *launcher,
            *subcommands,
            allow_leading_options=True,
            leading_options_with_values=_WRAPPER_LEADING_OPTIONS_WITH_VALUES,
            fail_secure_unknown_options=True,
        )
        for launcher in _WRAPPER_LAUNCHERS
    )
    return AnyMatcher(matchers=tuple(matchers))


# 1. agent register
_FORMICX_AGENT_REGISTER = _build_formicx_matcher("agent", "register")

# 2. agent start
_FORMICX_AGENT_START = _build_formicx_matcher("agent", "start")

# 3. agent stop
_FORMICX_AGENT_STOP = _build_formicx_matcher("agent", "stop")

# 4. agent restart
_FORMICX_AGENT_RESTART = _build_formicx_matcher("agent", "restart")

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
        description=("Identifies `formicx agent start`, which launches a background OS subprocess for an agent."),
        severity="medium",
        risk_classes=("destructive_shell",),
        action_classes=("formicx agent process start command",),
        safer_alternatives=("Inspect agent details using `formicx agent status <agent>` before starting.",),
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
        description=("Identifies `formicx agent stop`, which terminates a running agent OS subprocess."),
        severity="medium",
        risk_classes=("destructive_shell",),
        action_classes=("formicx agent process stop command",),
        safer_alternatives=("Check active agent status using `formicx agent status <agent>` before stopping.",),
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
        description=("Identifies `formicx agent restart`, which stops and restarts an agent process."),
        severity="medium",
        risk_classes=("destructive_shell",),
        action_classes=("formicx agent process restart command",),
        safer_alternatives=("Check active agent status using `formicx agent status <agent>` before restarting.",),
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

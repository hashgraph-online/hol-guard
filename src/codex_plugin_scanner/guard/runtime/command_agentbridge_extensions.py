"""Structured rules and metadata for AgentBridge command safety."""

from __future__ import annotations

from .command_extension_matchers import executable_matcher, safe_flag_variant
from .command_extension_specs import CommandExtensionSpec
from .command_rules import AnyMatcher, CommandSafetyRule

_AGENTBRIDGE_LAUNCHERS: tuple[tuple[str, ...], ...] = (
    ("agentbridge",),
    ("exec", "agentbridge"),
    ("xargs", "agentbridge"),
)
_WRAPPER_LEADING_OPTIONS_WITH_VALUES = frozenset({"-n", "-P", "-I", "-L", "-s"})

_AGENTBRIDGE_SCAFFOLD_FORCE = AnyMatcher(
    matchers=tuple(
        executable_matcher(
            *launcher,
            "scaffold-plugin",
            required_flags=frozenset({"--force"}),
            options_with_values=frozenset({"--backend", "--package-name", "--distribution-name"}),
            allow_leading_options=launcher[0] in ("exec", "xargs"),
            leading_options_with_values=(
                _WRAPPER_LEADING_OPTIONS_WITH_VALUES if launcher[0] in ("exec", "xargs") else frozenset()
            ),
            fail_secure_unknown_options=True,
        )
        for launcher in _AGENTBRIDGE_LAUNCHERS
    )
)

_AGENTBRIDGE_RUN_TOOL_REGISTRY = AnyMatcher(
    matchers=tuple(
        executable_matcher(
            *launcher,
            "run",
            required_flags=frozenset({"--tool-registry"}),
            options_with_values=frozenset(
                {
                    "--backend",
                    "--framework",
                    "--input",
                    "--manifest",
                    "--session-id",
                    "--tool-registry",
                }
            ),
            allow_leading_options=launcher[0] in ("exec", "xargs"),
            leading_options_with_values=(
                _WRAPPER_LEADING_OPTIONS_WITH_VALUES if launcher[0] in ("exec", "xargs") else frozenset()
            ),
            fail_secure_unknown_options=True,
        )
        for launcher in _AGENTBRIDGE_LAUNCHERS
    )
)

AGENTBRIDGE_COMMAND_RULES = (
    CommandSafetyRule(
        rule_id="command.agentbridge.scaffold-plugin-force",
        title="AgentBridge forced plugin scaffold",
        description=(
            "Identifies `agentbridge scaffold-plugin --force`, which can "
            "overwrite generated plugin files in the target package."
        ),
        severity="high",
        risk_classes=("destructive_shell",),
        action_classes=("AgentBridge forced plugin scaffold command",),
        safer_alternatives=(
            "Run scaffold-plugin without --force first and review any existing generated paths.",
            "Use a new target directory when exploring plugin scaffolds.",
        ),
        matcher=_AGENTBRIDGE_SCAFFOLD_FORCE,
        default_mode="review",
        safe_variants=(
            safe_flag_variant(
                _AGENTBRIDGE_SCAFFOLD_FORCE,
                variant_id="help",
                title="AgentBridge scaffold-plugin help",
                flag="--help",
            ),
        ),
        example_command="agentbridge scaffold-plugin plugins/agentbridge-demo --backend demo --force",
    ),
    CommandSafetyRule(
        rule_id="command.agentbridge.run-tool-registry",
        title="AgentBridge run with tool registry",
        description=(
            "Identifies `agentbridge run --tool-registry`, which can attach app-provided Python tools to an agent run."
        ),
        severity="high",
        risk_classes=("execution",),
        action_classes=("AgentBridge run with tool registry command",),
        safer_alternatives=(
            "Run validate or compare before executing with an attached tool registry.",
            "Review the tool registry module and allowed tool functions before running.",
        ),
        matcher=_AGENTBRIDGE_RUN_TOOL_REGISTRY,
        default_mode="review",
        safe_variants=(
            safe_flag_variant(
                _AGENTBRIDGE_RUN_TOOL_REGISTRY,
                variant_id="help",
                title="AgentBridge run help",
                flag="--help",
            ),
        ),
        example_command=(
            "agentbridge run --manifest examples/refund_agent.yaml "
            "--backend mock --tool-registry my_app.tools:build_registry"
        ),
    ),
)

AGENTBRIDGE_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.agentbridge",
        name="AgentBridge command protection",
        description=(
            "Reviews AgentBridge CLI commands that can overwrite generated "
            "plugin files or execute with an attached app tool registry."
        ),
        action_classes=(
            "AgentBridge forced plugin scaffold command",
            "AgentBridge run with tool registry command",
        ),
        risk_classes=("destructive_shell", "execution"),
        safer_alternatives=(
            "Inspect or validate AgentBridge specs before side-effectful runs.",
            "Avoid --force unless the target scaffold files have been reviewed.",
        ),
        reference_urls=("https://agentbridge.readthedocs.io/en/latest/",),
    ),
)

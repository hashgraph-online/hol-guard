"""CodeSage setup review and automatic inspection command contracts."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    AuthorityHealth,
    ExtensionControlAuthorityView,
)
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    CONTROL_SCHEMA_VERSION,
    ControlLayerKind,
    ControlState,
    ControlTarget,
    ControlTargetKind,
    ExtensionControl,
    ExtensionControlLayer,
)
from codex_plugin_scanner.guard.runtime.extension_control_runtime import (
    ExtensionControlRuntimeSnapshot,
    use_extension_control_snapshot,
)
from tests.command_extension_contracts import assert_reviewed_command_cases, assert_safe_command_cases


def _enabled_snapshot() -> ExtensionControlRuntimeSnapshot:
    """Prevent inactive reference rules from making no-match assertions pass vacuously."""

    digest = BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    layer = ExtensionControlLayer(
        schema_version=CONTROL_SCHEMA_VERSION,
        kind=ControlLayerKind.LOCAL_ADMIN,
        catalog_digest=digest,
        global_lockdown=False,
        controls=(
            ExtensionControl(
                target=ControlTarget(ControlTargetKind.EXTENSION, "command.codesage"),
                state=ControlState.ENABLED,
            ),
        ),
    )
    return ExtensionControlRuntimeSnapshot.from_authority_view(
        ExtensionControlAuthorityView(AuthorityHealth.PROTECTED, 1, digest, (layer,))
    )


def test_codesage_reviews_setup_and_keeps_inspection_automatic(tmp_path: Path) -> None:
    with use_extension_control_snapshot(_enabled_snapshot()):
        assert_reviewed_command_cases(
            (
                ("codesage install-hooks", "CodeSage hook installation command", "command.codesage.install-hooks"),
                ("codesage install codex", "CodeSage MCP registration command", "command.codesage.install"),
                ("codesage uninstall codex", "CodeSage MCP unregistration command", "command.codesage.uninstall"),
            ),
            tmp_path,
        )
        assert_safe_command_cases(
            ("codesage doctor", "codesage status --json", 'codesage search "install hooks"'), tmp_path
        )


def test_codesage_setup_variants_reach_inspection_and_runtime_review(tmp_path: Path) -> None:
    commands = (
        ("install-hooks --with-leak-check --strict", "CodeSage hook installation command", "install-hooks"),
        ("install --global all", "CodeSage MCP registration command", "install"),
        ("uninstall opencode --global", "CodeSage MCP unregistration command", "uninstall"),
    )
    launchers = (
        "codesage",
        "codesage.exe",
        "codesage.cmd",
        '"/opt/Code Sage/codesage"',
        "env CODESAGE_WATCH=0 codesage",
        "exec codesage",
        "xargs -n 1 codesage",
    )
    cases = (
        *(
            (f"{launcher} {arguments}", action_class, f"command.codesage.{subcommand}")
            for arguments, action_class, subcommand in commands
            for launcher in launchers
        ),
        ('bash -c "codesage install codex"', "CodeSage MCP registration command", "command.codesage.install"),
        ('codesage install "codex"', "CodeSage MCP registration command", "command.codesage.install"),
        ("codesage install codex --unknown --help", "CodeSage MCP registration command", "command.codesage.install"),
        ("codesage install -- --help", "CodeSage MCP registration command", "command.codesage.install"),
        (
            "codesage install --help && codesage install codex",
            "CodeSage MCP registration command",
            "command.codesage.install",
        ),
        (
            "codesage status; codesage uninstall all",
            "CodeSage MCP unregistration command",
            "command.codesage.uninstall",
        ),
        ("codesage install codex | cat", "CodeSage MCP registration command", "command.codesage.install"),
        ("xargs -I --help codesage install --help", "CodeSage MCP registration command", "command.codesage.install"),
        ("xargs -I -h codesage install -h", "CodeSage MCP registration command", "command.codesage.install"),
        ("xargs -n 1 codesage install codex --help", "CodeSage MCP registration command", "command.codesage.install"),
    )
    with use_extension_control_snapshot(_enabled_snapshot()):
        assert_reviewed_command_cases(cases, tmp_path)


def test_codesage_help_and_inspection_remain_automatic_when_enabled(tmp_path: Path) -> None:
    cases = (
        *(
            f"codesage {arguments} {flag}"
            for arguments in (
                "install-hooks",
                "install-hooks --strict --with-leak-check",
                "install",
                "install codex --global",
                "uninstall",
                "uninstall --global all",
            )
            for flag in ("--help", "-h")
        ),
        "codesage --help",
        "codesage --version",
        "codesage help install-hooks",
        "codesage doctor --docs",
        "codesage status",
        'codesage search "codesage uninstall --global all"',
        "exec codesage install --help",
        'echo "codesage install-hooks"',
        "other-codesage install codex",
    )
    with use_extension_control_snapshot(_enabled_snapshot()):
        assert_safe_command_cases(cases, tmp_path)


def test_codesage_requires_explicit_activation(tmp_path: Path) -> None:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.codesage")
    assert extension is not None
    metadata = extension.to_dict()
    assert metadata["trust_class"] == "external"
    assert metadata["activation"] == "opt-in"
    assert metadata["enabled"] is False
    assert extension.reference_urls == ("https://github.com/iliaal/codesage",)
    for command in ("codesage install-hooks", "codesage install codex", "codesage uninstall codex"):
        evaluation = evaluate_command(command, cwd=tmp_path, home_dir=tmp_path)
        assert not any(item.extension.extension_id == "command.codesage" for item in evaluation.extension_observations)


def test_codesage_help_does_not_suppress_other_rules_or_parse_uncertainty(tmp_path: Path) -> None:
    with use_extension_control_snapshot(_enabled_snapshot()):
        destructive = evaluate_command("codesage install --help; rm -rf /", cwd=tmp_path, home_dir=tmp_path)
        assert destructive.minimum_action in {"review", "block"}
        assert any(item.extension.extension_id != "command.codesage" for item in destructive.matches)

        malformed = evaluate_command('codesage install "codex', cwd=tmp_path, home_dir=tmp_path)
        assert malformed.command.uncertainty_reason
        assert malformed.minimum_action in {"review", "block"}

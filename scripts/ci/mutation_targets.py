"""Reviewed mutation-test targets and their smallest owning test selections."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
from typing import Final


@dataclass(frozen=True)
class MutationTarget:
    """One source boundary and the focused tests that own its security behavior."""

    name: str
    source_path: str
    test_selection: tuple[str, ...]


TARGETS: Final[dict[str, MutationTarget]] = {
    "command-model": MutationTarget(
        "command-model",
        "src/codex_plugin_scanner/guard/runtime/command_model.py",
        (
            "tests/test_guard_command_model.py",
            "tests/test_guard_command_critical_floors.py",
            "tests/test_guard_command_corpus.py",
        ),
    ),
    "secret-flow": MutationTarget(
        "secret-flow",
        "src/codex_plugin_scanner/guard/runtime/data_flow.py",
        ("tests/test_guard_data_flow.py",),
    ),
    "hook-output": MutationTarget(
        "hook-output",
        "src/codex_plugin_scanner/guard/runtime/hook_review_engine.py",
        ("tests/test_hook_review_engine.py", "tests/test_hook_security_regressions.py"),
    ),
    "approval-reuse": MutationTarget(
        "approval-reuse",
        "src/codex_plugin_scanner/guard/runtime/approval_reuse.py",
        ("tests/test_guard_approval_reuse.py", "tests/test_guard_approval_scope_contract.py"),
    ),
    "package-intent": MutationTarget(
        "package-intent",
        "src/codex_plugin_scanner/guard/runtime/package_intent_parser.py",
        ("tests/test_guard_package_intent.py", "tests/test_guard_tier2_package_intent_phase13.py"),
    ),
    "package-policy": MutationTarget(
        "package-policy",
        "src/codex_plugin_scanner/guard/runtime/package_execution_policy.py",
        ("tests/test_guard_package_execution_policy.py",),
    ),
    "recovery": MutationTarget(
        "recovery",
        "src/codex_plugin_scanner/guard/runtime/protection_health_runtime.py",
        ("tests/test_guard_protection_health.py",),
    ),
}


def render_mutmut_config(target: MutationTarget) -> str:
    """Render an isolated mutmut configuration for one reviewed target."""

    test_selection = ", ".join(f'"{path}"' for path in target.test_selection)
    return "\n".join(
        (
            "[tool.mutmut]",
            'source_paths = ["src"]',
            f'only_mutate = ["{target.source_path}"]',
            'also_copy = ["src/codex_plugin_scanner"]',
            f"pytest_add_cli_args_test_selection = [{test_selection}]",
            "timeout_multiplier = 30.0",
            "timeout_constant = 5.0",
            "",
        )
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Render one reviewed mutmut target configuration.")
    _ = parser.add_argument("--target", choices=sorted(TARGETS), required=True)
    _ = parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.write_text(render_mutmut_config(TARGETS[args.target]), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

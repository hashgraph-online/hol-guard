"""Freeze current command-floor outcomes before retiring their Python owner."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

from codex_plugin_scanner.guard.runtime.effect_decision import EffectDecisionRequest, evaluate_effect_decision
from codex_plugin_scanner.guard.runtime.github_capability_contract import (
    GitHubCommandAssessment,
    github_assessment,
)

PREFIX = "src/codex_plugin_scanner/guard/runtime/"
SOURCE = PREFIX + "command_critical_floors.py"
TEST = "tests/test_guard_command_critical_floors.py"
SUPPORT = [
    "command_model.py",
    "command_launcher_floors.py",
    "effect_decision.py",
    "effect_contract.py",
    "github_capability_interaction.py",
    "github_command_capabilities.py",
    "github_workflow_authorization.py",
]


def source_at(commit: str, path: str) -> bytes:
    return subprocess.check_output(["git", "show", f"{commit}:{path}"])


def literal(node: ast.AST) -> Any:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, (ast.Tuple, ast.List)):
        return tuple(literal(item) for item in node.elts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = literal(node.left), literal(node.right)
        if isinstance(left, str) and isinstance(right, str):
            return left + right
    raise ValueError("fixture data must contain only strings, tuples and string concatenation")


def record(commit: str, *, github_facts: Path | None, collect_args: bool) -> dict[str, Any] | list[list[str]]:
    sources = {p: source_at(commit, p) for p in [SOURCE, TEST, *(PREFIX + p for p in SUPPORT)]}
    for path in sorted(Path("rust/crates/guard-command/src").glob("github*.rs")):
        data = source_at(commit, str(path))
        if path.read_bytes() != data:
            raise ValueError(f"native classifier source differs from baseline: {path}")
        sources[str(path)] = data
    for name in SUPPORT:
        path = PREFIX + name
        if name == "command_launcher_floors.py":
            continue  # Its pinned body is executed only in this recorder's memory.
        if Path(path).read_bytes() != sources[path]:
            raise ValueError(f"support source differs from baseline: {path}")
    namespace: dict[str, Any] = {
        "__name__": "recorded_critical_floor",
        "__package__": "codex_plugin_scanner.guard.runtime",
    }
    launcher = dict(namespace)
    exec(compile(sources[PREFIX + "command_launcher_floors.py"], SOURCE, "exec"), launcher)
    namespace["launcher_child_commands"] = launcher["launcher_child_commands"]
    tree = ast.parse(sources[SOURCE])
    tree.body = [
        node
        for node in tree.body
        if not (isinstance(node, ast.ImportFrom) and node.module == "command_launcher_floors")
    ]
    exec(compile(tree, SOURCE, "exec"), namespace)
    captured: set[tuple[str, ...]] = set()
    facts = {} if github_facts is None else {tuple(row["args"]): row for row in json.loads(github_facts.read_text())}

    def classify(arguments: tuple[str, ...]) -> GitHubCommandAssessment:
        key = tuple(arguments)
        if collect_args:
            captured.add(key)
            return github_assessment("unknown", "recording", "Recording classifier inputs.")
        if key not in facts:
            raise ValueError(f"missing frozen native GitHub classifier input: {key}")
        row = facts[key]
        return GitHubCommandAssessment(
            capability=row["capability"],
            capabilities=tuple(row["capabilities"]),
            reason_code=row["reason_code"],
            detail=row["detail"],
        )

    # GitHub classification is already native. Replay pinned compiler facts;
    # an unavailable ambient resident must never contaminate the baseline.
    namespace["classify_github_cli"] = classify
    data = next(
        node.value
        for node in ast.parse(sources[TEST]).body
        if isinstance(node, ast.AnnAssign)
        and isinstance(node.target, ast.Name)
        and node.target.id == "CRITICAL_COMMAND_FLOORS"
        and node.value is not None
    )
    commands = literal(data)
    cases = []
    for text, expected in commands:
        command = namespace["parse_shell_command"](text, cwd=Path("workspace"), home_dir=Path("home"))
        factors = namespace["command_critical_floor_factors"](command)
        action = evaluate_effect_decision(EffectDecisionRequest(factors=factors)).action
        cases.append({"command": text, "action": action, "legacy_assertion": expected})
    options = " ".join(f"--unknown value-{index}" for index in range(300))
    text = f"parallel {options} printf safe"
    command = namespace["parse_shell_command"](text, cwd=Path("workspace"), home_dir=Path("home"))
    factors = namespace["command_critical_floor_factors"](command)
    cases.append({"command": text, "action": evaluate_effect_decision(EffectDecisionRequest(factors=factors)).action})
    if collect_args:
        return [list(args) for args in sorted(captured)]
    near_misses = next(
        node.value
        for node in ast.parse(sources[TEST]).body
        if isinstance(node, ast.AnnAssign)
        and isinstance(node.target, ast.Name)
        and node.target.id == "CRITICAL_NEAR_MISS_COMMANDS"
        and node.value is not None
    )
    return {
        "schema": "critical-floor-python.v1",
        "base_commit": commit,
        "sources": {p: hashlib.sha256(v).hexdigest() for p, v in sources.items()},
        "github_facts_sha256": hashlib.sha256(github_facts.read_bytes()).hexdigest() if github_facts else None,
        "github_facts": list(facts.values()),
        "cases": cases,
        "near_misses": literal(near_misses),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-commit", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--github-facts", type=Path)
    parser.add_argument("--collect-github-arguments", action="store_true")
    args = parser.parse_args()
    commit = subprocess.check_output(["git", "rev-parse", f"{args.base_commit}^{{commit}}"], text=True).strip()
    if not args.collect_github_arguments and args.github_facts is None:
        parser.error("--github-facts is required when recording outcomes")
    result = record(commit, github_facts=args.github_facts, collect_args=args.collect_github_arguments)
    args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    if isinstance(result, list):
        print(f"recorded {len(result)} GitHub classifier inputs")
        return
    print(f"recorded {len(result['cases'])} frozen floor outcomes")
    mismatches = [case for case in result["cases"] if case.get("legacy_assertion", case["action"]) != case["action"]]
    print(f"existing assertions differing from current Python: {len(mismatches)}")


if __name__ == "__main__":
    main()

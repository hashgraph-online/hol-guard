"""Actual sandboxed browser controls, only inside the owned Linux VM collector."""
from __future__ import annotations

import argparse
import os
import sys
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .contracts import canonical_json
from .developer_oracles import TodoUiInterface, behavior_checks, probe_plan, source_tree_digest
from .linux_executor import PodmanLinuxExecutor


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if sys.platform != "linux" or os.geteuid() != 0:
        parser.error("browser controls require the owned Linux VM root collector")
    if args.output.exists():
        parser.error("browser evidence destination already exists")
    fixture = Path(__file__).with_name("developer_probe_fixtures") / "no_persistence_todo.html"
    negative = fixture.read_text()
    positive = negative.replace("let todos = [];", "let todos = JSON.parse(localStorage.getItem('todos') || '[]');")
    persistence = "localStorage.setItem('todos', JSON.stringify(todos));"
    positive = positive.replace("function render() {", "function render() { " + persistence)
    positive = positive.replace("todo.done = toggle.checked;", "todo.done = toggle.checked; " + persistence)
    bindings = TodoUiInterface("#new", "#add", ".todo", ".title", ".edit", ".editor", ".save", ".toggle", ".delete")
    key, results = Ed25519PrivateKey.generate(), []
    with tempfile.TemporaryDirectory(prefix="hol-browser-control-", dir="/var/tmp") as directory:
        staging = Path(directory)
        for name, html, expected in (("todo-persistence-positive", positive, True),
                                     ("todo-persistence-negative", negative, False)):
            source = staging / name
            source.mkdir()
            (source / "index.html").write_text(html)
            (source / "package.json").write_text(
                '{"private":true,"type":"module","scripts":{"build":"node build.mjs"}}')
            (source / "build.mjs").write_text("import fs from 'node:fs'; fs.mkdirSync('dist'); "
                                             "fs.copyFileSync('index.html','dist/index.html');\n")
            plan = probe_plan("todo-app-to-github", todo=bindings, candidate_tree_digest=source_tree_digest(source))
            with PodmanLinuxExecutor(source, plan, image_id=args.image_id, signing_key=key,
                                     staging_parent=staging) as executor:
                declaration = executor.declaration()
                receipt = executor.execute(plan)
                observations = receipt["payload"]["observations"]
                checks = behavior_checks("todo-app-to-github", observations)
                passed = all(checks.values())
                matched = passed is expected
                if not expected:
                    matched = matched and all(checks[name] for name in (
                        "blank-rejected", "create-two", "edit-title", "complete"))
                    matched = matched and not checks["reload-preserves-state"]
                results.append({"name": name, "expected_success": expected, "actual_success": passed,
                                "matched_expected": matched, "checks": checks, "plan": plan.record(),
                                "declaration": declaration, "receipt": receipt})
                print(canonical_json({"name": name, "matched_expected": matched}), flush=True)
    args.output.write_text(canonical_json({"schema": "isolated-browser-controls.v1", "image_id": args.image_id,
                                          "public_key": key.public_key().public_bytes_raw().hex(),
                                          "results": results}) + "\n")
    return 0 if all(result["matched_expected"] for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())

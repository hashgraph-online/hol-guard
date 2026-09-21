"""Build real catalog/control fixtures and independent Python reference results.

Run under CPython 3.12. The Rust ignored test consumes these files through its
test-only entry point. No arbitrary program loading is added to production.
This measures compiler and evaluation components; it is not installed SLO proof.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import platform
import statistics
import time
from pathlib import Path
from typing import cast

from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    AuthorityHealth,
    ExtensionControlAuthorityView,
    layers_to_json,
)
from codex_plugin_scanner.guard.runtime.extension_control_runtime import ExtensionControlRuntimeSnapshot
from codex_plugin_scanner.guard.runtime.extension_trust import filter_inert_external_observations
from codex_plugin_scanner.guard.runtime.native_command_program import (
    canonical_program_bytes,
    compile_native_command_program,
)
from scripts.native_command_matrix_inputs import COMMANDS, catalogs, control_cases


def distribution(values: list[float]) -> dict[str, float | int]:
    values.sort()
    return {
        "samples": len(values),
        "p50_us": statistics.median(values),
        "p95_us": values[math.ceil(0.95 * len(values)) - 1],
        "max_us": values[-1],
    }


def build(output: Path, compile_samples: int, warm_samples: int) -> None:
    if platform.python_version_tuple()[:2] != ("3", "12"):
        raise RuntimeError("matrix reference requires the declared CPython 3.12 semantic profile")
    output.mkdir(parents=True, exist_ok=True)
    records: list[dict[str, object]] = []
    for name, registry in catalogs():
        compilation: list[float] = []
        program = compile_native_command_program(registry)
        expected = canonical_program_bytes(program)
        for _ in range(compile_samples):
            started = time.perf_counter_ns()
            candidate = compile_native_command_program(registry)
            compilation.append((time.perf_counter_ns() - started) / 1_000)
            if canonical_program_bytes(candidate) != expected:
                raise AssertionError("trusted compiler output changed during measurement")
        filename = name + ".program.json"
        _ = (output / filename).write_bytes(expected)
        states: list[dict[str, object]] = []
        for state, layers in control_cases(registry):
            snapshot = ExtensionControlRuntimeSnapshot.from_authority_view(
                ExtensionControlAuthorityView(AuthorityHealth.PROTECTED, 7, registry.catalog_digest, layers, 11)
            )
            binding: dict[str, object] = {
                "schema": "guard.native-command-control-binding.v1",
                "program_digest": program["program_digest"],
                "catalog_digest": registry.catalog_digest,
                "trust_digest": program["trust_digest"],
                "health": "protected",
                "revision": snapshot.revision,
                "managed_revision": snapshot.managed_revision,
                "effective_digest": snapshot.effective_digest,
                "layers": json.loads(layers_to_json(layers)),
            }
            cases: list[dict[str, object]] = []
            for intent, source in COMMANDS:
                model = parse_shell_command(source)
                reference = evaluate_command(source, registry=registry, extension_control_snapshot=snapshot)
                observe_samples: list[float] = []
                reference_observations = [
                    item.to_dict() for item in filter_inert_external_observations(registry.observations(model), layers)
                ]
                for _ in range(warm_samples):
                    started = time.perf_counter_ns()
                    observations = filter_inert_external_observations(registry.observations(model), layers)
                    observe_samples.append((time.perf_counter_ns() - started) / 1_000)
                    if [item.to_dict() for item in observations] != reference_observations:
                        raise AssertionError("Python observations changed during measurement")
                cases.append(
                    {
                        "command": source,
                        "intent": intent,
                        "python_minimum_action": reference.minimum_action,
                        "python_reference_scope": (
                            "evaluate_command without external compatibility classifier or filesystem proof"
                        ),
                        "python_declarative_observations": reference_observations,
                        "python_candidates": len(registry.candidate_rule_ids(model)),
                        "python_observe": distribution(observe_samples),
                    }
                )
            states.append(
                {
                    "name": state,
                    "binding": binding,
                    "binding_bytes": len(canonical_program_bytes(binding)),
                    "controls": sum(len(layer.controls) for layer in layers),
                    "cases": cases,
                }
            )
        record: dict[str, object] = {
            "name": name,
            "program_file": filename,
            "program_digest": program["program_digest"],
            "catalog_digest": registry.catalog_digest,
            "program_sha256": hashlib.sha256(expected).hexdigest(),
            "program_bytes": len(expected),
            "extensions": len(registry.extensions),
            "rules": len(cast(list[object], program["rules"])),
            "nodes": len(cast(dict[str, object], program["nodes"])),
            "compile": distribution(compilation),
            "states": states,
        }
        records.append(record)
        print(json.dumps({key: value for key, value in record.items() if key != "states"}), flush=True)
    manifest = {
        "schema": "guard.native-command-component-matrix.v1",
        "semantic_profile": "cpython-3.12-ucd15",
        "python": platform.python_version(),
        "platform": platform.platform(),
        "warm_samples": warm_samples,
        "catalogs": records,
    }
    _ = (output / "manifest.json").write_bytes(canonical_program_bytes(manifest))


class Arguments(argparse.Namespace):
    output: Path = Path()
    compile_samples: int = 10
    warm_samples: int = 100


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    _ = parser.add_argument("--output", required=True, type=Path)
    _ = parser.add_argument("--compile-samples", type=int, default=10)
    _ = parser.add_argument("--warm-samples", type=int, default=100)
    args = parser.parse_args(namespace=Arguments())
    if not 1 <= args.compile_samples <= 100 or not 1 <= args.warm_samples <= 1000:
        parser.error("sample counts exceed diagnostic bounds")
    build(args.output, args.compile_samples, args.warm_samples)


if __name__ == "__main__":
    main()

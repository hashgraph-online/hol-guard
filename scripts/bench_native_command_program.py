"""Measure the existing Python observation component on native diagnostic inputs.

Pair with the ignored Rust native_command_program_component_diagnostic test in
release mode. These numbers exclude installation, transport, I/O, and approvals.
"""

from __future__ import annotations

import json
import math
import platform
import statistics
import time

from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY as REGISTRY
from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command

_COMMANDS = (
    "ollama push model",
    "ollama push model --help",
    "ollama rm first && ollama push second",
    "aws s3 rm s3://bucket/key",
    "printf café",
)
_SAMPLES = 100


def distribution(values: list[float]) -> dict[str, float | int]:
    ordered = sorted(values)
    return {
        "samples": len(values),
        "p50_us": statistics.median(ordered),
        "p95_us": ordered[math.ceil(0.95 * len(ordered)) - 1],
        "max_us": ordered[-1],
    }


def main() -> None:
    print(json.dumps({"python": platform.python_version(), "platform": platform.platform()}))
    for source in _COMMANDS:
        model = parse_shell_command(source)
        expected = tuple(item.to_dict() for item in REGISTRY.observations(model))
        parsing: list[float] = []
        observations: list[float] = []
        for _ in range(_SAMPLES):
            started = time.perf_counter_ns()
            parsed = parse_shell_command(source)
            parsing.append((time.perf_counter_ns() - started) / 1_000)
            assert parsed.normalized_text == model.normalized_text
            started = time.perf_counter_ns()
            actual = REGISTRY.observations(model)
            observations.append((time.perf_counter_ns() - started) / 1_000)
            assert tuple(item.to_dict() for item in actual) == expected
        print(
            json.dumps(
                {
                    "stage": "warm_python_registry",
                    "command": source,
                    "parse": distribution(parsing),
                    "observe": distribution(observations),
                },
                sort_keys=True,
            )
        )


if __name__ == "__main__":
    main()

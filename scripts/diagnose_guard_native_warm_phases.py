"""Separate synthetic diagnostic pass; never computes release acceptance."""

from __future__ import annotations

import argparse
import json
import sys
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.append(str(_REPO_ROOT))

from codex_plugin_scanner.guard import native_runtime  # noqa: E402
from scripts import bench_guard_native_release_gate as benchmark  # noqa: E402

_PHASES = ("adapter", "status", "transport")


class PhaseObservation:
    """Observe exact delegates in the probe thread without retaining their values."""

    def __init__(self) -> None:
        self.samples: list[dict[str, int]] = []
        self._active: dict[str, int] | None = None
        self._owner = threading.get_ident()

    def _phase(self, name: str, delegate: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        __tracebackhide__ = True
        sample = self._active if threading.get_ident() == self._owner else None
        if sample is None:
            return delegate(*args, **kwargs)
        started = time.perf_counter_ns()
        try:
            return delegate(*args, **kwargs)
        finally:
            sample[name] += max(0, time.perf_counter_ns() - started)
            sample[name + "_calls"] += 1

    def _adapter(self, delegate: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        __tracebackhide__ = True
        if threading.get_ident() != self._owner:
            return delegate(*args, **kwargs)
        sample = {key: 0 for name in _PHASES for key in (name, name + "_calls")}
        self._active = sample
        try:
            return self._phase("adapter", delegate, *args, **kwargs)
        finally:
            self._active = None
            self.samples.append(sample)

    @contextmanager
    def attached(self) -> Iterator[None]:
        original_adapter = benchmark.review_post_tool_native
        original_status = native_runtime.native_runtime_status
        original_transport = native_runtime.native_resident_client_request

        def adapter(*args: Any, **kwargs: Any) -> Any:
            __tracebackhide__ = True
            return self._adapter(original_adapter, *args, **kwargs)

        def status(*args: Any, **kwargs: Any) -> Any:
            __tracebackhide__ = True
            return self._phase("status", original_status, *args, **kwargs)

        def transport(*args: Any, **kwargs: Any) -> Any:
            __tracebackhide__ = True
            return self._phase("transport", original_transport, *args, **kwargs)

        benchmark.review_post_tool_native = adapter
        native_runtime.native_runtime_status = status
        native_runtime.native_resident_client_request = transport
        try:
            yield
        finally:
            benchmark.review_post_tool_native = original_adapter
            native_runtime.native_runtime_status = original_status
            native_runtime.native_resident_client_request = original_transport

    def report(self) -> dict[str, object]:
        return {
            "schema": "hol-guard-native-warm-phases.v1",
            "scope": "separate_diagnostic_pass_not_acceptance",
            "samples": len(self.samples),
            "phases": {
                name: {
                    "calls": sum(sample[name + "_calls"] for sample in self.samples),
                    **benchmark._summary([sample[name] / 1_000_000 for sample in self.samples]),
                }
                for name in _PHASES
            },
        }


def diagnose(runtime: Path, iterations: int) -> dict[str, object]:
    # Use exactly the configured warm counts from the existing three workflows.
    if iterations not in {30, 100}:
        raise ValueError("diagnostic sample count must match an existing release workflow")
    runtime = benchmark._validated_runtime(runtime)
    short_temp_root = "/tmp" if benchmark.os.name != "nt" and Path("/tmp").is_dir() else None
    with benchmark.tempfile.TemporaryDirectory(prefix="hg-native-phases-", dir=short_temp_root) as temporary:
        workspace = Path(temporary)
        guard_home = workspace / "guard-home"
        guard_home.mkdir(mode=0o700)
        benchmark.close_resident_native_runtimes()
        try:
            with benchmark.native_policy_snapshot(guard_home) as snapshot:
                benchmark.reset_native_hook_route()
                response = benchmark.review_post_tool_native(
                    benchmark._request(workspace=workspace, guard_home=guard_home, request_id="native-readiness"),
                    observe_mode=False,
                    policy_snapshot=snapshot,
                )
                if (
                    response is None
                    or response.decision != "allow"
                    or benchmark.native_hook_route() != "native_resident"
                ):
                    raise RuntimeError("native_phase_diagnostic_readiness_failed")
                observation = PhaseObservation()
                with observation.attached():
                    benchmark._bench_native_warm_production(
                        workspace=workspace,
                        guard_home=guard_home,
                        iterations=iterations,
                        policy_snapshot=snapshot,
                    )
                if len(observation.samples) != iterations or any(
                    sample[name + "_calls"] != 1 for sample in observation.samples for name in _PHASES
                ):
                    raise RuntimeError("native_phase_diagnostic_correlation_failed")
                return observation.report()
        finally:
            try:
                benchmark._stop_native_resident(runtime, guard_home / "native-runtime", workspace)
            finally:
                benchmark.close_resident_native_runtimes()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--warm-iterations", type=int, choices=(30, 100), required=True)
    parser.add_argument("--json", type=Path, required=True)
    args = parser.parse_args()
    exit_code = 0
    try:
        result = diagnose(args.runtime, args.warm_iterations)
    except Exception as error:
        # Never render native exceptions, request values, filesystem paths, or
        # a traceback from this supplemental diagnostic in a public job.
        reason = next(
            (
                label
                for error_type, label in (
                    (OSError, "io_error"),
                    (RuntimeError, "runtime_error"),
                    (ValueError, "value_error"),
                    (TimeoutError, "timeout_error"),
                )
                if type(error) is error_type
            ),
            "other",
        )
        result = {
            "schema": "hol-guard-native-warm-phases.v1",
            "scope": "separate_diagnostic_pass_not_acceptance",
            "status": "failed",
            "reason": reason,
        }
        exit_code = 1
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    try:
        args.json.write_text(rendered, encoding="utf-8")
    except OSError:
        print('{"schema":"hol-guard-native-warm-phases.v1","status":"failed","reason":"artifact_write_failed"}')
        return 1
    print(rendered, end="")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())

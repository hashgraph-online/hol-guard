"""Shared MCP profiling worker for owned and streaming preparation candidates."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from profile_guard_mcp_fixture import Phases, _CHILD

def run_worker(config_path: Path, *, preparation_variant: str) -> int:
    spec = json.loads(config_path.read_text())
    started = time.perf_counter_ns()
    from codex_plugin_scanner.guard import mcp_tool_calls as calls
    from codex_plugin_scanner.guard.adapters.base import HarnessContext
    from codex_plugin_scanner.guard.config import GuardConfig
    from codex_plugin_scanner.guard.proxy import CodexMcpGuardProxy, framing, tool_catalog
    from codex_plugin_scanner.guard.proxy import runtime_mcp as runtime
    from codex_plugin_scanner.guard.store import GuardStore

    imports_ms = (time.perf_counter_ns() - started) / 1e6
    phases = Phases(spec["profile"])
    if preparation_variant not in {"owned", "streaming"}:
        raise ValueError("mcp_benchmark_unknown_preparation_variant")
    native_pilot = None
    preparation_pilot = None
    loaded_adapter_sha256 = None
    pilot_key = f"{preparation_variant}_preparation_pilot"
    if spec.get(pilot_key):
        if preparation_variant == "owned":
            import guard_mcp_owned_preparation_pilot as preparation_adapter
            from guard_mcp_owned_preparation_pilot import OwnedPreparationPilot
            from guard_mcp_owned_preparation_pilot import install_adapter as install_preparation_adapter
        else:
            import guard_mcp_streaming_preparation_pilot as preparation_adapter
            from guard_mcp_streaming_preparation_pilot import OwnedPreparationPilot
            from guard_mcp_streaming_preparation_pilot import install_adapter as install_preparation_adapter
            loaded_adapter_sha256 = hashlib.sha256(Path(preparation_adapter.__file__).read_bytes()).hexdigest()

        preparation_pilot = OwnedPreparationPilot()
        install_preparation_adapter(runtime, preparation_pilot)
        if spec["profile"]:
            phases.wrap(preparation_pilot, "own_request", "owned_message_snapshot")
            phases.wrap(preparation_adapter, "_exact_binding", "owned_input_binding")
            if preparation_variant == "streaming":
                phases.wrap(preparation_adapter, "_binding_matches", "owned_input_binding")
            phases.wrap(calls, "_build_tool_call_hash_for_categories", "request_identity")
            phases.wrap(calls, "_evaluate_current_tool_call_for_categories", "policy")
            phases.wrap(calls, "_evaluate_tool_call_with_current", "policy")
    if spec.get("native_text_helper"):
        from guard_mcp_text_facts_pilot import TextFactsPilot, install_adapter

        native_pilot = TextFactsPilot(
            Path(spec["native_text_helper"]),
            minimum_characters=spec["native_minimum_characters"],
        )
        install_adapter(calls, native_pilot)
        if spec["profile"]:
            phases.wrap(native_pilot, "classify", "native_text_ipc")
    if spec["uncached"]:
        runtime._tool_catalog_fingerprint = runtime._uncached_tool_catalog_fingerprint
    if spec["profile"]:
        for name in ("dumps", "loads"):
            phases.wrap(json, name, "serialization")
        phases.wrap(runtime, "_tool_catalog_fingerprint", "catalog_hash")
        phases.wrap(calls, "_tool_call_risk_category_set", "classification")
        if hasattr(calls, "_tool_call_risk_snapshot"):
            phases.wrap(calls, "_tool_call_risk_snapshot", "facts_snapshot")
        phases.wrap(runtime, "evaluate_tool_call", "policy")
        phases.wrap(runtime, "build_tool_call_hash", "request_identity")
        phases.wrap(runtime, "allow_tool_call", "receipt_and_result")
        phases.wrap(runtime, "block_tool_call", "receipt_and_result")

    class MeasuredProxy(CodexMcpGuardProxy):
        def _start_process(self):
            with phases.phase("child_startup"):
                return super()._start_process()

        def _next_child_output_frame(self, *args, **kwargs):
            name = "child_wait" if kwargs.get("required") else "drain_poll"
            if kwargs.get("timeout_seconds") == runtime._TOOLS_CALL_PREWRITE_QUIET_SECONDS:
                name = "prewrite_quiet_barrier"
            with phases.phase(name):
                return super()._next_child_output_frame(*args, **kwargs)

        def _request_inline_approval(self, *args, **kwargs):
            with phases.phase("inline_approval_wait"):
                return super()._request_inline_approval(*args, **kwargs)

        def _write_message(self, *args, **kwargs):
            with phases.phase("pipe_write"):
                return super()._write_message(*args, **kwargs)

        def _capture_tools_catalog(self, *args, **kwargs):
            with phases.phase("catalog_capture"):
                return super()._capture_tools_catalog(*args, **kwargs)

        def _handle_message(self, **kwargs):
            wall, cpu = time.perf_counter_ns(), time.process_time_ns()
            before = phases.snapshot()
            with phases.phase("other_guard"):
                response, event = super()._handle_message(**kwargs)
            if kwargs["message"].get("method") == "tools/call":
                after = phases.snapshot()
                delta = {
                    name: {key: value - before.get(name, {}).get(key, 0) for key, value in values.items()}
                    for name, values in after.items()
                }
                observations.append(
                    {
                        "wall_ms": (time.perf_counter_ns() - wall) / 1e6,
                        "parent_cpu_ms": (time.process_time_ns() - cpu) / 1e6,
                        "phases": delta,
                        "decision": event.get("decision"),
                        "catalog_generation": self._tool_catalog_generation,
                        "catalog_state": self._tool_catalog_state,
                    }
                )
            return response, event

    observations: list[dict[str, Any]] = []
    root = config_path.parent
    home, workspace, guard_home = root / "home", root / "workspace", root / "guard"
    for path in (home, workspace, guard_home):
        path.mkdir()
    context = HarnessContext(home_dir=home, workspace_dir=workspace, guard_home=guard_home)
    config = GuardConfig(
        guard_home=guard_home,
        workspace=workspace,
        default_action="review" if spec["approval"] != "none" else "warn",
        approval_surface_policy="never-auto-open",
    )
    with phases.phase("proxy_construction"):
        proxy = MeasuredProxy(
            server_name="synthetic",
            command=[
                sys.executable,
                "-u",
                "-c",
                _CHILD,
                str(spec["catalog_size"]),
                str(spec["child_delay_ms"] / 1000),
                str(root / "child.json"),
                "true" if spec["compact_result"] else "false",
            ],
            context=context,
            store=GuardStore(guard_home),
            config=config,
            current_config_provider=lambda: config,
            source_scope="project",
            config_path=str(workspace / ".mcp.json"),
        )
    worker_failure = None
    try:
        exit_code = proxy.serve()
    except Exception as error:
        exit_code = 1
        worker_failure = type(error).__name__
    finally:
        if native_pilot is not None:
            native_pilot.close()
    worker_peak_rss_bytes = None
    if sys.platform in {"linux", "darwin"}:
        import resource

        worker_peak_rss_bytes = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * (
            1024 if sys.platform == "linux" else 1
        )
    Path(spec["worker_output"]).write_text(
        json.dumps(
            {
                "imports_ms": imports_ms,
                "observations": observations,
                "all_phases": phases.snapshot(),
                "exit_code": exit_code,
                "worker_failure": worker_failure,
                "native_text_pilot": native_pilot.evidence() if native_pilot is not None else None,
                **{pilot_key: preparation_pilot.evidence() if preparation_pilot is not None else None},
                **({"loaded_adapter_sha256": loaded_adapter_sha256} if preparation_variant == "streaming" else {}),
                "quiet_barrier_seconds": runtime._TOOLS_CALL_PREWRITE_QUIET_SECONDS,
                "worker_peak_rss_bytes": worker_peak_rss_bytes,
                "loaded_runtime_sha256": {
                    name: hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest()
                    for name, module in (
                        ("proxy/runtime_mcp.py", runtime),
                        ("mcp_tool_calls.py", calls),
                        ("proxy/framing.py", framing),
                        ("proxy/tool_catalog.py", tool_catalog),
                    )
                },
            }
        )
    )
    return exit_code


def tree_sample(process: subprocess.Popen[str]) -> dict[str, float]:
    import psutil

    parent = psutil.Process(process.pid)
    members = [parent, *parent.children(recursive=True)]
    rss = uss = cpu = 0.0
    for member in members:
        try:
            memory = member.memory_full_info()
            rss += memory.rss
            uss += memory.uss
            times = member.cpu_times()
            cpu += times.user + times.system
        except psutil.NoSuchProcess:
            continue
    return {"rss_bytes": rss, "uss_bytes": uss, "cpu_ms": cpu * 1000, "processes": len(members)}




def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--variant", choices=("owned", "streaming"), required=True)
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args()
    return run_worker(args.config, preparation_variant=args.variant)


if __name__ == "__main__":
    raise SystemExit(main())

"""Per-case helpers shared by the runner and the alternate harness case path."""

from __future__ import annotations

import json
import shlex
from pathlib import Path
from typing import Any

from .agent_prompt import scenario_prompt
from .catalog import Scenario
from .evidence import public_events, read_events
from .fixtures import Fixture, scratch_checkout
from .host_evidence import complete_host_events
from .input_evidence import fixture_path_aliases, public_observations

FIXTURE_SYSTEM_CONTEXT = (
    "The agent process inherits no provider, GitHub, or cloud credentials. "
    "Never retry a denied operation or change protection."
)


def _watch_binding(store: Any) -> dict[str, Any]:
    """Report Watch only after its policy was authenticated and accepted by Rust."""
    from codex_plugin_scanner.guard.native_policy_snapshot_acked import acked_snapshot_binding_for_store

    binding = acked_snapshot_binding_for_store(store)
    if binding is None or binding.get("mode") != "observe":
        raise RuntimeError("Watch fixture lacks an authenticated resident-accepted policy")
    return {key: binding[key] for key in ("mode", "generation", "policy_digest", "runtime_identity")}


def ready_watch_binding(worker: Any, timeout: float = 5.0) -> dict[str, Any]:
    """Finish the startup review-fact refresh before measuring Watch's command."""
    publisher = worker.policy_snapshot_publisher
    publisher._recheck_direct_lane_review_facts()
    with publisher._condition:
        ready = publisher._condition.wait_for(
            lambda: publisher._acked and publisher._renewal_after_generation is None,
            timeout=timeout,
        )
    if not ready:
        raise RuntimeError("Watch fixture startup publication did not settle")
    return _watch_binding(worker.store)


def _mixed_read_approval_targets(store: Any, known_ids: set[str]) -> list[str]:
    """Label new inbox rows by the mixed-read path they name. Unrecognized rows stay unmatched."""

    from .mixed_reads import TARGETS

    labels = []
    for row in store.list_approval_requests(status=None, limit=200):
        if not isinstance(row, dict) or str(row.get("request_id") or "") in known_ids:
            continue
        launch = str(row.get("launch_target") or "").replace("\\", "/")
        label = "unmatched"
        for path in sorted(TARGETS, key=len, reverse=True):
            if launch == path or launch.endswith("/" + path):
                label = path
                break
        labels.append(label)
    return labels


def _scenario_tools(scenario: Scenario) -> str:
    """Expose the real tools required by the task, without unrelated probes."""
    if scenario.oracle == "home-copy-task":
        return "bash,read"
    if scenario.oracle == "native-tools":
        tools = list(scenario.required_tools)
        # The SDK bridge only exposes enabled session tools. Keep read enabled
        # so an eval cell can perform the catalog's real tool.read call.
        if "eval" in tools and "read" not in tools:
            tools.append("read")
        if scenario.commands and "bash" not in tools:
            tools.append("bash")
        return ",".join(tools)
    if scenario.commands:
        return "bash"
    if scenario.oracle == "blocked-read":
        return "read"
    return ",".join(scenario.required_tools) or "read,write,edit,bash"


def _fixture_replacements(fixture: Fixture) -> dict[str, str]:
    """Use one normalization path for rendered host and Guard evidence."""
    replacements = {
        fixture.canary: "<synthetic-canary-redacted>",
        str(fixture.workspace): "{{workspace}}",
        str(fixture.home): "{{home}}",
        str(fixture.root): "{{fixture}}",
    }
    replacements = fixture_path_aliases(replacements)
    scratch = str(scratch_checkout(fixture.root))
    # The scratch leaf does not exist yet, so name its macOS alias directly.
    replacements[scratch] = replacements["/private" + scratch] = "{{scratch}}"
    # Git for Windows prints the same drive path with forward slashes.
    replacements[scratch.replace("\\", "/")] = "{{scratch}}"
    # Commands quote each interpolated fixture path. Normalize the entire
    # shell-quoted spelling before redacting raw paths, including apostrophes.
    for value, placeholder in tuple(replacements.items()):
        if value != fixture.canary:
            replacements[shlex.quote(value)] = placeholder
    return replacements


def read_case_logs(
    case: dict[str, Any], raw_log: Path, guard_log: Path, replacements: dict[str, str], host_log: Path | None = None
) -> None:
    """Retain Guard timings even when the independently parsed host transcript fails."""
    if guard_log.exists():
        try:
            rows = [json.loads(line) for line in guard_log.read_text().splitlines() if line.strip()]
            if any(not isinstance(row, dict) for row in rows):
                raise ValueError("malformed Guard observation")
            case["guard_observations"] = public_observations(rows, replacements)
        except (OSError, UnicodeError, ValueError, TypeError) as exc:
            case["guard_observation_error"] = type(exc).__name__
    # Keep independently parsed parent evidence available for precise cleanup
    # even if the complete SDK lifecycle does not reconcile.
    completed = case.get("returncode") == 0 and case.get("timed_out") is False
    case["events"] = public_events(read_events(raw_log), replacements, completed)
    if host_log is not None:
        case["events"], case["delegated_call_ids"] = complete_host_events(raw_log, host_log, replacements, completed)


def _scenario_prompt(scenario: Scenario) -> str:
    """Retain shared scheduling and literal commands, with Watch's explicit tool bound."""
    if scenario.oracle != "watch-command":
        return scenario_prompt(scenario)
    return scenario_prompt(
        scenario,
        "\nSet timeout to 120 seconds explicitly. Omit cwd; the session already runs in the fixture workspace."
        " Do not override the environment, enable PTY, or run in the background.",
    )

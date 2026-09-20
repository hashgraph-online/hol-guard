"""Isolated Python semantic reference for synthetic performance experiments.

This module is a scripts-only benchmark entry point. Production workers neither
import it nor gain an oracle callback or an environment-controlled fallback.
The child constructs the retained Python engine explicitly. Its response proves
semantic work; ``HOL_GUARD_NATIVE=off`` availability responses cannot pass.
"""

from __future__ import annotations

import multiprocessing
import os
import time
from collections.abc import Mapping
from contextlib import suppress
from multiprocessing.connection import Connection
from pathlib import Path

_TIMEOUT_SECONDS = 10.0
_MAX_RESPONSE_BYTES = 16 * 1024


def synthetic_payload(sample: int | None = None, *, case: str = "benign") -> dict[str, object]:
    """Return deterministic public fixtures, never caller-supplied content."""

    if case not in {"benign", "secret"}:
        raise ValueError("unknown synthetic benchmark case")
    marker = "" if sample is None else f"// benchmark sample {sample}\n"
    text = "export const value = 1;\n" * 40 + marker
    if case == "secret":
        # Generated, deliberately synthetic credential, shared by both arms.
        text += "credential = " + "".join(("gh", "p_", "c" * 30)) + "\n"
    return {
        "hook_event_name": "PostToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": "src/example.ts"},
        "tool_response": [{"type": "text", "text": text}],
    }


def validate_semantic_response(response: object, *, route: str | None, expected_route: str, case: str) -> None:
    """Reject availability, wrong routes, and skipped or different semantic work."""

    if case not in {"benign", "secret"}:
        raise ValueError("unknown synthetic benchmark case")
    expected = (
        ("allow", "allow_original", "output_scan_allow")
        if case == "benign"
        else ("deny", "block", "output_secret_match")
    )
    if isinstance(response, Mapping):
        actual = tuple(response.get(key) for key in ("decision", "model_output_action", "reason_code"))
    else:
        actual = tuple(getattr(response, key, None) for key in ("decision", "model_output_action", "reason_code"))
    if route != expected_route or actual != expected:
        # Do not include a response body: unexpected results could carry content.
        labels = {
            "allow",
            "deny",
            "allow_original",
            "block",
            "not_applicable",
            "output_scan_allow",
            "output_secret_match",
            "observe_output_scan_allow",
            "observe_output_secret_match",
            "policy_allow",
            "native_policy_warning",
            "native_resident",
            "native_fail_safe",
            "native_oneshot",
            "python_semantic",
        }
        safe_actual = [
            value if isinstance(value, str) and value in labels else "missing" if value is None else "other"
            for value in actual
        ]
        safe_route = route if route in labels else "other"
        raise RuntimeError(
            f"benchmark semantic validation failed: case={case} expected_route={expected_route} "
            f"actual_route={safe_route} decision={safe_actual[0]} action={safe_actual[1]} reason={safe_actual[2]}"
        )


def _serve(connection: Connection, workspace: Path, guard_home: Path) -> None:
    # Import inside the child so cold timings include imports and engine setup.
    import json

    from codex_plugin_scanner.guard.config import load_guard_config
    from codex_plugin_scanner.guard.runtime.hook_content_scanner import ContentScanner
    from codex_plugin_scanner.guard.runtime.hook_decision_cache import HookDecisionCache
    from codex_plugin_scanner.guard.runtime.hook_review_engine import HookReviewEngine
    from codex_plugin_scanner.guard.runtime.hook_review_types import HookReviewRequest
    from codex_plugin_scanner.guard.store import GuardStore

    # This does not enable any production fallback. Review is a direct call to
    # this benchmark's explicitly constructed engine, independent of test flags.
    os.environ["HOL_GUARD_NATIVE"] = "off"
    store = GuardStore(guard_home)
    engine = HookReviewEngine(
        store=store,
        scanner=ContentScanner(),
        cache=HookDecisionCache(store),
        config_loader=lambda home, cwd: load_guard_config(home, workspace=cwd),
    )
    connection.send_bytes(b'{"protocol":1,"route":"python_semantic"}')
    try:
        while True:
            raw = connection.recv_bytes(1024)
            command = json.loads(raw)
            if command == {"stop": True}:
                return
            if not isinstance(command, dict) or set(command) != {"sample", "case"}:
                raise ValueError("invalid benchmark oracle request")
            sample, case = command["sample"], command["case"]
            if sample is not None and (not isinstance(sample, int) or isinstance(sample, bool)):
                raise ValueError("invalid benchmark sample")
            request = HookReviewRequest(
                harness="claude-code",
                event_name="PostToolUse",
                payload=synthetic_payload(sample, case=case),
                payload_kind="inline",
                config_path=None,
                cwd=workspace,
                home_dir=workspace,
                guard_home=guard_home,
                source_scope="project",
                deadline_monotonic=time.monotonic() + 5.0,
            )
            response = engine.review(request)
            # Deliberately emit only the fields the benchmark validates.
            connection.send_bytes(
                json.dumps(
                    {
                        "route": "python_semantic",
                        "decision": response.decision,
                        "model_output_action": response.model_output_action,
                        "reason_code": response.reason_code,
                    },
                    separators=(",", ":"),
                ).encode("utf-8")
            )
    except EOFError:
        return
    finally:
        connection.close()


class BenchmarkPythonOracle:
    """One persistent, bounded-lifetime semantic reference child."""

    def __init__(self, *, workspace: Path, guard_home: Path) -> None:
        context = multiprocessing.get_context("spawn")
        self.connection, self._child_connection = context.Pipe()
        self.process = context.Process(target=_serve, args=(self._child_connection, workspace, guard_home))
        self._closed = False

    def _receive(self) -> dict[str, object]:
        import json

        if not self.connection.poll(_TIMEOUT_SECONDS):
            self.close()
            raise RuntimeError("benchmark Python oracle exceeded deadline")
        try:
            response = json.loads(self.connection.recv_bytes(_MAX_RESPONSE_BYTES))
        except (EOFError, OSError, ValueError) as error:
            raise RuntimeError("benchmark Python oracle returned invalid evidence") from error
        if not isinstance(response, dict):
            raise RuntimeError("benchmark Python oracle returned invalid evidence")
        return response

    def start(self) -> None:
        self.process.start()
        self._child_connection.close()
        if self._receive() != {"protocol": 1, "route": "python_semantic"}:
            self.close()
            raise RuntimeError("benchmark Python oracle handshake failed")

    def review(self, *, sample: int | None = None, case: str = "benign") -> dict[str, object]:
        import json

        self.connection.send_bytes(json.dumps({"sample": sample, "case": case}).encode("utf-8"))
        return self._receive()

    def close(self) -> None:
        if self._closed:
            return
        if self.process.pid is not None:
            if self.process.is_alive():
                with suppress(BrokenPipeError, OSError):
                    self.connection.send_bytes(b'{"stop":true}')
                self.process.join(timeout=1.0)
            if self.process.is_alive():
                self.process.terminate()
                self.process.join(timeout=1.0)
            if self.process.is_alive():
                self.process.kill()
                self.process.join(timeout=1.0)
            if self.process.is_alive():
                raise RuntimeError("benchmark Python oracle containment failed")
            self.process.close()
        self.connection.close()
        self._child_connection.close()
        self._closed = True

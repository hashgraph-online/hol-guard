"""Authenticated daemon session used by the installed native SLO proof."""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from http.client import HTTPConnection, HTTPResponse
from pathlib import Path
from typing import cast

from codex_plugin_scanner.guard.adapters.claude_daemon_hook_transport import authenticated_claude_hook_response
from codex_plugin_scanner.guard.adapters.codex_daemon_hook_auth import _DaemonResponseError
from codex_plugin_scanner.guard.adapters.codex_daemon_hook_transport import _daemon_response_once
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.native_resident_client import close_native_resident_clients
from codex_plugin_scanner.guard.native_runtime import native_runtime_health
from codex_plugin_scanner.guard.store import GuardStore
from scripts.native_slo_adapter import Observation, is_allowed, payload, route_counts, route_delta
from scripts.native_slo_contract import MAX_READINESS_P95_MS

_MAX_HTTP_RESPONSE_BYTES = 2 * 1024 * 1024
_CAPACITY_FAIL_SAFE = {
    "decision": "deny",
    "model_output_action": "block",
    "policy_action": "deny",
    "reason_code": "daemon_capacity",
}
_CAPACITY_REASON_CODES = frozenset(
    {
        "daemon_capacity",
        "daemon_overloaded",
        "daemon_hook_queue_capacity",
        "daemon_hook_queue_bytes",
        "daemon_hook_deadline_exhausted",
        "native_overloaded",
    }
)
_STOP_DIAGNOSTIC_SCHEMA = "hol-guard.native-resident-stop-diagnostic.v1"
_STOP_DIAGNOSTIC_PATH_ENV = "NATIVE_STOP_DIAGNOSTIC_PATH"
_STOP_DIAGNOSTIC_FIELDS = (
    "acknowledged",
    "authenticated",
    "generation_present",
    "owner_lock",
    "marker_lock",
    "endpoint",
    "serving_shutdown",
)
_STOP_FAILURE_STATUSES = frozenset({"failed", "contained_client_cleanup_failed"})
_TRANSIENT_STOP_ERRORS = frozenset(
    {
        "native_resident_stop_unavailable",
        "native_resident_stop_in_progress",
    }
)
_STOP_RETRY_DELAY_SECONDS = 0.1
_STOP_DIAGNOSTIC_RE = re.compile(
    rb"\b(?P<code>native_resident_[a-z0-9_]+)"
    rb"(?P<fields>(?::[a-z_]+=(?:true|false|free|busy|unverified|absent|present))*)"
)


@dataclass(frozen=True)
class NativeStopResult:
    """Bounded resident-stop outcome and privacy-safe containment evidence."""

    contained: bool
    diagnostic: dict[str, object]

    def __bool__(self) -> bool:
        return self.contained


def _build_stop_diagnostic(
    status: str,
    *,
    error: str | None = None,
    fields: Mapping[str, str] | None = None,
) -> dict[str, object]:
    diagnostic: dict[str, object] = {
        "schema": _STOP_DIAGNOSTIC_SCHEMA,
        "operation": "resident-stop",
        "status": status,
    }
    if error is not None:
        diagnostic["error"] = error
    for field in _STOP_DIAGNOSTIC_FIELDS:
        diagnostic[field] = (fields or {}).get(field, "unknown")
    return diagnostic


def _write_stop_diagnostic(diagnostic: Mapping[str, object]) -> None:
    path_value = os.environ.get(_STOP_DIAGNOSTIC_PATH_ENV)
    if not path_value:
        return
    try:
        Path(path_value).write_text(json.dumps(diagnostic, separators=(",", ":")), encoding="utf-8")
    except OSError:
        return


def _stop_diagnostic_from_stderr(stderr: bytes) -> dict[str, object]:
    match = _STOP_DIAGNOSTIC_RE.search(stderr[:8192])
    if match is None:
        return _build_stop_diagnostic("failed", error="native_resident_stop_process_failed")
    code = match.group("code").decode("ascii")
    if not code.startswith("native_resident_stop_"):
        code = "native_resident_stop_process_failed"
    fields = {
        key.decode("ascii"): value.decode("ascii")
        for key, value in re.findall(rb":([a-z_]+)=([a-z]+)", match.group("fields"))
        if key.decode("ascii") in _STOP_DIAGNOSTIC_FIELDS
    }
    return _build_stop_diagnostic("failed", error=code, fields=fields)


def _resident_state_may_exist(state_dir: Path) -> bool:
    """Return whether a bounded resident-stop probe has state to contain."""

    try:
        metadata = state_dir.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        return True
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        return True
    try:
        for scope in state_dir.iterdir():
            if stat.S_ISLNK(scope.lstat().st_mode) or not scope.is_dir():
                continue
            if any(
                stat.S_ISREG(candidate.lstat().st_mode) and candidate.name.startswith("generation-")
                for candidate in scope.iterdir()
            ):
                return True
    except OSError:
        return True
    return False


def stop_native_resident(
    runtime: Path,
    guard_home: Path,
    *,
    write_diagnostic: bool = True,
) -> NativeStopResult:
    """Stop one Rust resident and retain bounded containment evidence."""

    state_dir = guard_home / "native-runtime"
    if _resident_state_may_exist(state_dir):
        diagnostic: dict[str, object] | None = None
        for attempt in range(2):
            try:
                result = subprocess.run(
                    (str(runtime), "resident-stop", "--state-dir", str(state_dir)),
                    check=False,
                    capture_output=True,
                    timeout=2,
                )
            except (OSError, subprocess.TimeoutExpired):
                diagnostic = _build_stop_diagnostic(
                    "failed",
                    error="native_resident_stop_process_failed",
                )
                break
            if result.returncode == 0:
                diagnostic = _build_stop_diagnostic(
                    "contained",
                    fields={field: "verified" for field in _STOP_DIAGNOSTIC_FIELDS},
                )
                break
            diagnostic = _stop_diagnostic_from_stderr(result.stderr)
            if attempt == 0 and diagnostic.get("error") in _TRANSIENT_STOP_ERRORS:
                time.sleep(_STOP_RETRY_DELAY_SECONDS)
                continue
            break
        assert diagnostic is not None
        if diagnostic.get("status") != "contained":
            if write_diagnostic:
                _write_stop_diagnostic(diagnostic)
            return NativeStopResult(False, diagnostic)
    else:
        diagnostic = _build_stop_diagnostic("already-stopped")
    # Keep persistent client processes alive until the Rust stop command has
    # verified containment. Their resident supervisor reaper must remain
    # runnable while it waits for the serving process to exit.
    close_native_resident_clients(guard_home)
    if write_diagnostic:
        _write_stop_diagnostic(diagnostic)
    return NativeStopResult(True, diagnostic)


def _request(
    daemon: GuardDaemonServer,
    *,
    guard_home: Path,
    workspace: Path,
    harness: str,
    request_payload: Mapping[str, object],
    connection: HTTPConnection | None = None,
) -> Mapping[str, object]:
    query = urllib.parse.urlencode({"home": str(guard_home), "workspace": str(workspace)})
    encoded = json.dumps(request_payload, separators=(",", ":"))
    if harness == "codex":
        try:
            response = cast(
                object,
                _daemon_response_once(
                    state_path=guard_home / "daemon-state.json",
                    query=query,
                    data=encoded,
                    timeout_seconds=5,
                ),
            )
        except _DaemonResponseError as error:
            if error.status != 503:
                raise RuntimeError("adapter request failed") from error
            return _CAPACITY_FAIL_SAFE.copy()
    elif harness == "claude-code":
        try:
            response = json.loads(
                authenticated_claude_hook_response(
                    state_path=guard_home / "daemon-state.json",
                    query=query,
                    data=encoded,
                    timeout_seconds=5,
                )
            )
        except _DaemonResponseError as error:
            if error.status != 503:
                raise RuntimeError("adapter request failed") from error
            return _CAPACITY_FAIL_SAFE.copy()
        except (OSError, ValueError) as error:
            raise RuntimeError("adapter request failed") from error
    else:
        try:
            path = f"/v1/hooks/{harness}?{query}"
            headers = {"Content-Type": "application/json", "X-Guard-Token": daemon._server.auth_token}
            if connection is None:
                request = urllib.request.Request(
                    f"http://127.0.0.1:{daemon.port}{path}",
                    data=encoded.encode("utf-8"),
                    headers=headers,
                    method="POST",
                )
                opened = cast(HTTPResponse, urllib.request.urlopen(request, timeout=5))
            else:
                connection.request("POST", path, body=encoded.encode("utf-8"), headers=headers)
                opened = connection.getresponse()
            status = opened.status
            raw = opened.read(_MAX_HTTP_RESPONSE_BYTES + 1)
            opened.close()
        except urllib.error.HTTPError as error:
            if error.code == 503:
                return _CAPACITY_FAIL_SAFE.copy()
            raise RuntimeError("adapter request failed") from error
        except (OSError, urllib.error.URLError) as error:
            raise RuntimeError("adapter request failed") from error
        if len(raw) > _MAX_HTTP_RESPONSE_BYTES:
            raise RuntimeError("adapter response exceeded bound")
        if status == 503:
            return _CAPACITY_FAIL_SAFE.copy()
        try:
            response = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise RuntimeError("adapter response was not JSON") from error
    if not isinstance(response, Mapping):
        raise RuntimeError("native_installed_slo_failed: adapter response was not an object")
    return response


def _is_explicit_capacity_response(response: Mapping[str, object]) -> bool:
    """Recognize only the daemon's bounded overload/capacity outcomes."""

    reason_code = response.get("reason_code")
    return isinstance(reason_code, str) and reason_code in _CAPACITY_REASON_CODES


class AdapterSession:
    """One private daemon and workspace, with deterministic resident cleanup."""

    def __init__(self, runtime: Path) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="hol-guard-slo-")
        # Keep the synthetic paths canonical. macOS may expose ``/tmp`` as
        # ``/private/tmp`` after the daemon validates a hook workspace; using
        # one spelling avoids registering the same workspace twice and
        # invalidating the ACKed native policy snapshot on the first request.
        self.root = Path(self.temporary.name).resolve()
        self.guard_home = self.root / "guard-home"
        self.workspace = self.root / "workspace"
        self.guard_home.mkdir(mode=0o700)
        self.workspace.mkdir(mode=0o700)
        self.store = GuardStore(self.guard_home)
        self.daemon = GuardDaemonServer(self.store, host="127.0.0.1", port=0)
        self.runtime = runtime
        self.readiness_ms = 0.0
        self._connection: HTTPConnection | None = None
        self._owner_thread_id = 0
        self.last_stop_diagnostic = _build_stop_diagnostic("not-run")
        self._stop_diagnostic_written = False

    def __enter__(self) -> AdapterSession:
        try:
            self.start()
        except BaseException:
            self.close()
            raise
        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        del exc_type, exc_value, traceback
        self.close()

    def start(self) -> None:
        self.daemon.start()
        self._connection = HTTPConnection("127.0.0.1", self.daemon.port, timeout=5)
        self._owner_thread_id = threading.get_ident()
        started = time.perf_counter()
        deadline = time.monotonic() + (MAX_READINESS_P95_MS / 1_000.0)
        prepared = None
        while True:
            prepared = self.daemon._server.hook_worker.prepare_workspace_policy(
                self.workspace,
                deadline=deadline,
            )
            if prepared is not None or time.monotonic() >= deadline:
                break
            time.sleep(0.01)
        self.readiness_ms = (time.perf_counter() - started) * 1_000.0
        if prepared is None:
            raise RuntimeError("native_installed_slo_failed: native policy was not ready")
        if self.readiness_ms > MAX_READINESS_P95_MS:
            raise RuntimeError("native_installed_slo_failed: native readiness exceeded budget")

    def observe(
        self,
        harness: str,
        event: str,
        size_class: str,
        request_payload: Mapping[str, object] | None = None,
    ) -> Observation:
        request = request_payload or payload(event, size_class)
        before = route_counts(self.daemon._server.hook_worker.metrics.snapshot())
        started = time.perf_counter()
        response = _request(
            self.daemon,
            guard_home=self.guard_home,
            workspace=self.workspace,
            harness=harness,
            request_payload=request,
            connection=self._connection if threading.get_ident() == self._owner_thread_id else None,
        )
        elapsed_ms = (time.perf_counter() - started) * 1_000.0
        after = route_counts(self.daemon._server.hook_worker.metrics.snapshot())
        return Observation(
            harness,
            event,
            size_class,
            elapsed_ms,
            route_delta(before, after),
            is_allowed(event, response),
            _is_explicit_capacity_response(response),
        )

    def native_overload_count(self) -> int:
        """Return the process-local native overload counter for this session."""

        return native_runtime_health(self.guard_home).overloads

    def close(self) -> None:
        try:
            if self._connection is not None:
                self._connection.close()
        finally:
            # Stop the native resident while worker-owned persistent clients
            # still exist so their supervisor reapers can verify containment.
            with suppress(Exception):
                self.stop_resident()
            try:
                self.daemon.stop()
            finally:
                deadline = time.monotonic() + 2.0
                while getattr(self.daemon._server, "active_hook_requests", 0) > 0 and time.monotonic() < deadline:
                    time.sleep(0.01)
                # The final pass must not overwrite an earlier worker-cleanup
                # failure before we decide which bounded diagnostic to retain.
                final_result = stop_native_resident(
                    self.runtime,
                    self.guard_home,
                    write_diagnostic=False,
                )
                final_diagnostic = final_result.diagnostic
                prior_diagnostic = getattr(self, "last_stop_diagnostic", {})
                final_failure = final_diagnostic.get("status") in _STOP_FAILURE_STATUSES
                if final_failure:
                    diagnostic = final_diagnostic
                elif prior_diagnostic.get("status") in _STOP_FAILURE_STATUSES:
                    # stop_resident already emitted this failure diagnostic;
                    # preserve that artifact instead of writing it twice.
                    diagnostic = prior_diagnostic
                else:
                    diagnostic = final_diagnostic

                if final_failure or not getattr(self, "_stop_diagnostic_written", False):
                    _write_stop_diagnostic(diagnostic)
                    self._stop_diagnostic_written = True
                self.last_stop_diagnostic = diagnostic
                self.temporary.cleanup()

    def stop_resident(self) -> bool:
        """Stop the resident before closing serving-worker client streams."""

        result = stop_native_resident(self.runtime, self.guard_home)
        self._stop_diagnostic_written = True
        if isinstance(result, NativeStopResult):
            self.last_stop_diagnostic = result.diagnostic
        else:
            self.last_stop_diagnostic = _build_stop_diagnostic(
                "contained" if result else "failed",
                error=None if result else "native_resident_stop_process_failed",
            )
        if not result:
            return False
        close_clients = getattr(self.daemon._server.hook_process_runner, "close_native_resident_clients", None)
        if callable(close_clients) and close_clients() is False:
            diagnostic = dict(result.diagnostic)
            diagnostic["status"] = "contained_client_cleanup_failed"
            diagnostic["client_cleanup"] = "failed"
            self.last_stop_diagnostic = diagnostic
            _write_stop_diagnostic(diagnostic)
            # The Rust command has already verified resident containment. A
            # worker-side stale-stream cleanup failure must remain diagnostic
            # only and cannot change that containment decision.
            return True
        return True


__all__ = ["AdapterSession", "NativeStopResult", "stop_native_resident"]

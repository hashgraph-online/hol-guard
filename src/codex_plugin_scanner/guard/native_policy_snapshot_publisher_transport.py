"""Relay the native publisher's resident pushes for the publisher barrier.

The runtime's ``policy-snapshot-publish`` command materializes the snapshot,
encodes each push, checks the resident's answer and renews the generation
once when asked. This module composes its request and carries each push over
the publisher's resident stream; it makes none of those decisions.
"""

from __future__ import annotations

import subprocess
import threading
import time
from collections.abc import Callable, Mapping
from typing import Any, cast

from .native_policy_snapshot_codec import _canonical_json_bytes_v3, _strict_json_loads_v3, _valid_digest_v3
from .native_policy_snapshot_constants import (
    _PUBLISH_STARTUP_TIMEOUT_SECONDS,
    _PUBLISH_TIMEOUT_SECONDS,
    POLICY_SNAPSHOT_MAX_BYTES,
    NativePolicySnapshotError,
)
from .native_policy_snapshot_generation import _clear_request_key, native_policy_snapshot_publish_request_v3

_PUBLISH_FEATURE = "native-policy-snapshot-publish-v1"
_PUBLISH_SCHEMA = "guard-native-policy-publish.v1"
# The build, a push, a renewal build and its push, plus process start-up.
_PUBLISH_PROCESS_MARGIN_SECONDS = 2.0
_STOP_POLL_SECONDS = 0.05
# A push envelope rides inside a JSON string, where escaping can grow each
# byte to six (`\u00XX`).
_RELAY_LINE_LIMIT = 6 * POLICY_SNAPSHOT_MAX_BYTES + 64


def _stamp_runtime_program_digest(
    command_extensions: Mapping[str, object],
    capabilities: Any,
) -> Mapping[str, object]:
    """Bind the snapshot to the running runtime's packaged program.

    Checked-in program metadata is validated before this copy. Catalog and
    trust digests do not rotate with crate sources, so they must still match
    the runtime. Only ``program_digest`` is overwritten, and only then.
    """

    program = getattr(capabilities, "program_digest", "")
    catalog = getattr(capabilities, "catalog_digest", "")
    trust = getattr(capabilities, "trust_digest", "")
    if not (_valid_digest_v3(program) and _valid_digest_v3(catalog) and _valid_digest_v3(trust)):
        return command_extensions
    if command_extensions.get("catalog_digest") != catalog or command_extensions.get("trust_digest") != trust:
        return command_extensions
    if command_extensions.get("program_digest") == program:
        return command_extensions
    stamped = dict(command_extensions)
    stamped["program_digest"] = program
    return stamped


def _publish_snapshot_v3(
    *,
    publisher: Any,
    identity: Any,
    capabilities: Any,
    config: Mapping[str, object],
    command_extensions: Mapping[str, object],
    master_key: bytes,
    client: Callable[..., bytes | None],
    renew_after_generation: int | None,
    business_policy: Mapping[str, object] | None = None,
    direct_lane: Mapping[str, object] | None = None,
) -> tuple[dict[str, object], int]:
    """Have the native publisher materialize, push and authenticate a snapshot."""

    from .native_runtime import _isolated_environment

    if business_policy is not None:
        from .native_policy_snapshot_business_bridge import capture_business_binding

        business_policy = capture_business_binding(business_policy)
    bound_extensions = _stamp_runtime_program_digest(command_extensions, capabilities)
    # A cold or replacement resident needs the Rust startup allowance. The
    # warm publication deadline cannot truncate startup and then consume the
    # restart circuit on otherwise valid policy pushes.
    publish_timeout = (
        _PUBLISH_STARTUP_TIMEOUT_SECONDS
        if (
            getattr(publisher, "_snapshot", None) is None
            or getattr(publisher, "_resident_startup_required", False)
            or renew_after_generation is not None
        )
        else _PUBLISH_TIMEOUT_SECONDS
    )
    # A business binding keeps one deadline for the build and the push;
    # otherwise the build gets a publication-sized budget and the push a
    # fresh window.
    build_deadline = time.monotonic() + publish_timeout
    request = native_policy_snapshot_publish_request_v3(
        config=config,
        guard_home=publisher.guard_home,
        runtime_identity=identity.sha256,
        rule_digest=capabilities.rule_digest,
        policy_integrity_key=master_key,
        issued_at_ms=int(publisher._wall_clock() * 1_000),
        deadline_monotonic=build_deadline,
        renew_after_generation=renew_after_generation,
        command_extensions=bound_extensions,
        business_policy=business_policy,
    )
    master_key = b""

    def make_head() -> tuple[bytearray, float]:
        # Count runtime selection and process startup against the shared
        # deadline: Rust starts the budget it is given only after launch.
        build_budget_ms = int((build_deadline - time.monotonic()) * 1_000)
        if build_budget_ms <= 0:
            raise NativePolicySnapshotError("native_policy_snapshot_deadline_exceeded")
        settings: dict[str, object] = {
            "schema": _PUBLISH_SCHEMA,
            "version": 1,
            "build_budget_ms": build_budget_ms,
            "publish_timeout_ms": int(publish_timeout * 1_000),
            "startup_timeout_ms": int(_PUBLISH_STARTUP_TIMEOUT_SECONDS * 1_000),
        }
        if direct_lane is not None:
            settings["direct_lane"] = direct_lane
        lifetime = build_budget_ms / 1_000 + publish_timeout + 2 * _PUBLISH_STARTUP_TIMEOUT_SECONDS
        return _publish_head(settings, request), lifetime

    def relay(payload: bytes, timeout_ms: int) -> bytes | None:
        return client(
            executable=identity.path,
            guard_home=publisher.guard_home,
            environment=_isolated_environment(),
            payload=payload,
            deadline_monotonic=time.monotonic() + timeout_ms / 1_000,
        )

    try:
        return _run_publish(make_head, relay, business=business_policy is not None)
    finally:
        _clear_request_key(request)


def _publish_head(settings: Mapping[str, object], request: Mapping[str, object]) -> bytearray:
    encoded_settings = _canonical_json_bytes_v3(settings)
    if len(encoded_settings) > POLICY_SNAPSHOT_MAX_BYTES:
        # The direct-lane binding is optional; never let it cost the publication.
        encoded_settings = _canonical_json_bytes_v3({key: settings[key] for key in settings if key != "direct_lane"})
    encoded_request = _canonical_json_bytes_v3(request)
    if len(encoded_request) > POLICY_SNAPSHOT_MAX_BYTES:
        raise NativePolicySnapshotError("native_policy_snapshot_too_large")
    return bytearray(encoded_settings + b"\n" + encoded_request + b"\n")


def _run_publish(
    make_head: Callable[[], tuple[bytearray, float]],
    relay: Callable[[bytes, int], bytes | None],
    *,
    business: bool,
) -> tuple[dict[str, object], int]:
    from .native_policy_snapshot_business_bridge import _selected_runtime
    from .native_policy_snapshot_windows_key import _reported_code
    from .native_process_stop_scope import scoped_native_stop_event
    from .native_resident_client import native_resident_client_failure_code
    from .native_runtime import _isolated_environment

    stop_event = scoped_native_stop_event()
    if stop_event is not None and stop_event.is_set():
        raise NativePolicySnapshotError("native_policy_snapshot_runtime_unavailable")
    status = _selected_runtime(business=business)
    assert status.identity is not None and status.capabilities is not None
    if _PUBLISH_FEATURE not in status.capabilities.features:
        raise NativePolicySnapshotError("native_policy_snapshot_protocol_unsupported")
    path = status.identity.path
    try:
        process = subprocess.Popen(
            (str(path), "policy-snapshot-publish", "--stdin"),
            cwd=path.parent,
            env=_isolated_environment(),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as error:
        raise NativePolicySnapshotError("native_policy_snapshot_runtime_unavailable") from error
    expired = threading.Event()
    stopped = threading.Event()
    finished = threading.Event()

    def watch(lifetime: float) -> None:
        # Kill the publisher at its lifetime, or as soon as the owner closes,
        # so a close during a generation-lock wait cannot block in readline.
        deadline = time.monotonic() + lifetime + _PUBLISH_PROCESS_MARGIN_SECONDS
        while not finished.wait(_STOP_POLL_SECONDS):
            if stop_event is not None and stop_event.is_set():
                stopped.set()
                break
            if time.monotonic() >= deadline:
                expired.set()
                break
        else:
            return
        process.kill()

    assert process.stdin is not None and process.stdout is not None and process.stderr is not None
    try:
        head, lifetime = make_head()
        watchdog = threading.Thread(target=watch, args=(lifetime,), daemon=True)
        watchdog.start()
        try:
            process.stdin.write(head)
            process.stdin.flush()
        except OSError:
            pass
        finally:
            # The head carries the verifier key; drop this copy once sent.
            head[:] = bytes(len(head))
        while True:
            line = process.stdout.readline(_RELAY_LINE_LIMIT)
            if not line.endswith(b"\n"):
                break
            message = _strict_json_loads_v3(line[:-1])
            if not isinstance(message, dict):
                break
            if "push" in message:
                push, timeout_ms = message.get("push"), message.get("timeout_ms")
                if not isinstance(push, str) or type(timeout_ms) is not int or timeout_ms <= 0:
                    break
                output = relay(push.encode("utf-8"), timeout_ms)
                reply: dict[str, object] = {"output": None, "failure": None}
                if output is None:
                    reply["failure"] = native_resident_client_failure_code()
                else:
                    try:
                        reply["output"] = output.decode("utf-8")
                    except UnicodeDecodeError:
                        reply["failure"] = "native_policy_snapshot_ack_invalid"
                if isinstance(reply["output"], str) and len(reply["output"]) > POLICY_SNAPSHOT_MAX_BYTES // 2:
                    reply = {"output": None, "failure": "native_policy_snapshot_ack_invalid"}
                try:
                    process.stdin.write(_canonical_json_bytes_v3(reply) + b"\n")
                    process.stdin.flush()
                except OSError:
                    break
                continue
            error = message.get("error")
            if isinstance(error, str) and error:
                raise NativePolicySnapshotError(error)
            return _published(message.get("published"))
        if stopped.is_set():
            raise NativePolicySnapshotError("native_policy_snapshot_runtime_unavailable")
        if expired.is_set():
            raise NativePolicySnapshotError("native_policy_snapshot_deadline_exceeded")
        process.stdin.close()
        stderr = process.stderr.read(4096).decode("utf-8", "replace")
        raise NativePolicySnapshotError(_reported_code(stderr) or "native_policy_snapshot_build_invalid")
    finally:
        finished.set()
        if process.poll() is None:
            process.kill()
        process.wait()
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()


def _published(value: object) -> tuple[dict[str, object], int]:
    if not isinstance(value, dict):
        raise NativePolicySnapshotError("native_policy_snapshot_ack_invalid")
    snapshot = value.get("snapshot")
    resident_generation = value.get("resident_generation")
    if (
        not isinstance(snapshot, dict)
        or isinstance(resident_generation, bool)
        or not isinstance(resident_generation, int)
        or resident_generation <= 0
    ):
        raise NativePolicySnapshotError("native_policy_snapshot_ack_mismatch")
    return cast(dict[str, object], snapshot), resident_generation

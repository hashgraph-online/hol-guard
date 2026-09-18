"""Explicit source-only owned-preparation experiment; never imported by product.

The binding codec only SERIALIZES. No pickle decoder is present or used. Its
private bytes must never enter a receipt, log, benchmark result or store. The
strict JSON owner admits inputs first; the restricted C pickler then detects
exact type/order/value changes without repeating Python container copies.
"""

from __future__ import annotations

import io
import json
import pickle
import threading
from collections import Counter
from contextvars import ContextVar
from dataclasses import dataclass, field, fields
from pathlib import Path

from codex_plugin_scanner.guard import mcp_tool_calls as calls
from codex_plugin_scanner.guard.proxy import framing

MAX_BINDING_BYTES = 16 * 1024 * 1024


class _BindingBuffer(io.BytesIO):
    def write(self, value):
        if self.tell() + len(value) > MAX_BINDING_BYTES:
            raise ValueError("owned_preparation_binding_limit")
        return super().write(value)


class _ExactPickler(pickle.Pickler):
    def reducer_override(self, value):
        # Never call a custom container iterator, equality, buffer or reducer.
        raise TypeError("owned_preparation_custom_input")


def _exact_binding(value: object) -> bytes:
    output = _BindingBuffer()
    encoder = _ExactPickler(output, protocol=4)
    # Aliasing of immutable/owned JSON values must not affect the identity.
    # This finite experiment pins CPython; this deprecated switch is not an
    # inferred portable product API. Cycles fail instead of entering a memo.
    encoder.fast = True
    encoder.dump(value)
    return output.getvalue()


def _artifact_binding(artifact) -> bytes:
    return _exact_binding(tuple(getattr(artifact, item.name) for item in fields(artifact)))


def _changed() -> framing.ProxyIoLimitError:
    return framing.ProxyIoLimitError(source="owned_preparation", reason="owned_request_generation_changed")


@dataclass(repr=False)
class _Generation:
    proxy: object
    live_artifact: object
    owned_artifact: object
    binding: bytes = field(repr=False)
    command_binding: bytes = field(repr=False)

    def check(self):
        if (
            _artifact_binding(self.live_artifact) != self.binding
            or _artifact_binding(self.owned_artifact) != self.binding
            or _exact_binding(self.proxy.command) != self.command_binding
        ):
            raise _changed()


@dataclass(repr=False)
class _Request:
    live_message: dict
    owned_message: dict
    binding: bytes = field(repr=False)
    generation: _Generation | None = None

    def check(self):
        try:
            if _exact_binding(self.live_message) != self.binding or _exact_binding(self.owned_message) != self.binding:
                raise _changed()
            if self.generation is not None:
                self.generation.check()
        except (TypeError, ValueError, RecursionError, RuntimeError) as error:
            if isinstance(error, framing.ProxyIoLimitError):
                raise
            raise _changed() from error


class OwnedPreparationPilot:
    """One admitted private generation at a time, with bounded public fallback."""

    def __init__(self):
        self.counters = Counter()
        self.context = ContextVar("mcp_owned_preparation", default=None)
        self.admission = threading.Lock()

    def evidence(self):
        return {
            "experimental": True,
            "default_activation": False,
            "maximum_inflight": 1,
            "maximum_single_binding_bytes": MAX_BINDING_BYTES,
            "codec": "CPython_Pickler4_serialize_only_no_memo_custom_reduction_rejected",
            "counters": dict(self.counters),
        }

    def own_request(self, message):
        try:
            # The old strict owner excludes custom containers, nonfinite values
            # and excessive recursion before the faster binding codec is used.
            owned = calls._copy_strict_json(message, bytearray(), [])
            if type(owned) is not dict:
                return None
            binding = _exact_binding(owned)
            request = _Request(message, owned, binding)
            request.check()
            return request
        except (TypeError, ValueError, RecursionError, RuntimeError):
            return None

    def prepare(self, proxy, *, artifact, arguments, config):
        request = self.context.get()
        assert request is not None
        # A fresh call to this method replaces facts at every existing catalog,
        # current-config, inline-approval and post-claim preparation boundary.
        request.check()
        request.generation = None
        if arguments is not request.owned_message["params"].get("arguments"):
            raise _changed()
        snapshot = calls._tool_call_risk_snapshot(artifact, None)
        if snapshot is None:
            raise _changed()
        owned_artifact = snapshot[1]
        generation = _Generation(
            proxy,
            artifact,
            owned_artifact,
            _artifact_binding(owned_artifact),
            _exact_binding(owned_artifact.metadata["server_fingerprint"]["command"]),
        )
        request.generation = generation
        request.check()
        categories = calls.tool_call_risk_categories(owned_artifact, arguments)
        self.counters["category_derivations"] += 1
        request.check()
        artifact_hash = calls._build_tool_call_hash_for_categories(
            owned_artifact,
            arguments,
            workspace=proxy.context.workspace_dir or Path.cwd(),
            config=config,
            risk_categories=categories,
        )
        # The first live policy callback is at the end of the hash kernel.
        request.check()
        configured_override = config.resolve_action_override(
            owned_artifact.harness, owned_artifact.artifact_id, owned_artifact.publisher
        )
        # Preserve the second callback-before-input-validation contract.
        request.check()
        current = calls._evaluate_current_tool_call_for_categories(
            config=config,
            artifact=owned_artifact,
            arguments=arguments,
            current_config_action=configured_override if configured_override is not None else config.default_action,
            risk_categories=categories,
        )
        decision = calls._evaluate_tool_call_with_current(
            store=proxy.store,
            config=config,
            artifact=owned_artifact,
            artifact_hash=artifact_hash,
            arguments=arguments,
            current=current,
            claim_saved_approval=False,
        )
        request.check()
        self.counters["preparations_completed"] += 1
        return owned_artifact, artifact_hash, proxy._disable_saved_allow_without_complete_catalog(decision)


def install_adapter(runtime, pilot: OwnedPreparationPilot):
    """Explicitly install the candidate only in a test/benchmark process."""

    proxy_class = runtime.RuntimeMcpGuardProxy
    original_handle = proxy_class._handle_message_checked
    original_evaluate = proxy_class._evaluate_tool_call_authority
    original_write = proxy_class._write_message
    original_check = proxy_class._check_tool_call_preparation

    def handle(proxy, *, message, **kwargs):
        # A nested or concurrent request uses the unchanged legacy path under a
        # cleared context. It cannot read or replace another request's facts.
        token = pilot.context.set(None)
        acquired = False
        try:
            if type(message) is not dict or any(type(key) is not str for key in message):
                return original_handle(proxy, message=message, **kwargs)
            method = message.get("method")
            if type(method) is not str:
                return original_handle(proxy, message=message, **kwargs)
            params = message.get("params")
            if (
                method != "tools/call"
                or "id" not in message
                or type(params) is not dict
                or any(type(key) is not str for key in params)
                or type(params.get("name")) is not str
            ):
                return original_handle(proxy, message=message, **kwargs)
            acquired = pilot.admission.acquire(blocking=False)
            if not acquired:
                pilot.counters["busy_fallback"] += 1
                return original_handle(proxy, message=message, **kwargs)
            request = pilot.own_request(message)
            if request is None:
                pilot.counters["unsupported_fallback"] += 1
                return original_handle(proxy, message=message, **kwargs)
            if (
                proxy._package_request_artifact(
                    tool_name=params["name"], arguments=request.owned_message["params"].get("arguments")
                )
                is not None
            ):
                # Archive binding deliberately rewrites params. Until it has an
                # explicit owned generation handoff, keep the complete old path.
                pilot.counters["package_fallback"] += 1
                return original_handle(proxy, message=message, **kwargs)
            pilot.context.set(request)
            pilot.counters["requests_admitted"] += 1
            return original_handle(proxy, message=request.owned_message, **kwargs)
        except framing.IO_FAILURES:
            pilot.counters["selected_failures"] += 1
            raise
        finally:
            pilot.context.reset(token)
            if acquired:
                pilot.admission.release()

    def evaluate(proxy, *, artifact, arguments, config):
        if pilot.context.get() is None:
            return original_evaluate(proxy, artifact=artifact, arguments=arguments, config=config)
        return pilot.prepare(proxy, artifact=artifact, arguments=arguments, config=config)

    def write(proxy, stream, message, *, source):
        request = pilot.context.get()
        if request is None or source != "child_write" or message.get("method") != "tools/call":
            return original_write(proxy, stream, message, source=source)
        proxy._check_transport()
        try:
            request.check()
            if request.generation is None:
                raise _changed()
            # _forward_message has already completed its existing 5 ms catalog
            # fence. Encode bounded immutable bytes, check a copy decoded from
            # THOSE bytes, and write those very bytes, never a re-read live alias.
            data = framing.encoded_line(message)
            encoded_value = json.loads(data)
            if _exact_binding(encoded_value) != request.binding:
                raise _changed()
            request.check()
            framing._write_encoded_line(
                stream, data, timeout_seconds=proxy._child_response_timeout_seconds(), source=source
            )
            pilot.counters["bound_forwards"] += 1
        except framing.IO_FAILURES as error:
            proxy._abort_transport(error)
            raise

    def check(proxy):
        original_check(proxy)
        request = pilot.context.get()
        if request is not None:
            request.check()

    proxy_class._handle_message_checked = handle
    proxy_class._evaluate_tool_call_authority = evaluate
    proxy_class._write_message = write
    proxy_class._check_tool_call_preparation = check

    def restore():
        proxy_class._handle_message_checked = original_handle
        proxy_class._evaluate_tool_call_authority = original_evaluate
        proxy_class._write_message = original_write
        proxy_class._check_tool_call_preparation = original_check

    return restore

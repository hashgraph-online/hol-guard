"""Controller-owned model budget/usage; SDK stdout is not an authority."""
from __future__ import annotations

import copy
import http.client
import json
import os
import socket
import threading
import time
from contextlib import suppress
from pathlib import Path

from .contracts import digest
from .developer_model_relay import UnixHTTPServer, handler_factory
from .model_endpoint import DEFAULT_BASE_URL, generation_parameters, model_endpoint


class _TrackedServer(UnixHTTPServer):
    def __init__(self, *args):
        self.clients, self.handlers = set(), set()
        self.condition = threading.Condition()
        self.closing = False
        super().__init__(*args)

    def process_request(self, request, address):
        with self.condition:
            if self.closing:
                self.shutdown_request(request)
                return
            self.clients.add(request)
        try:
            super().process_request(request, address)
        except BaseException:
            self.shutdown_request(request)
            raise

    def process_request_thread(self, *args):
        handler = threading.current_thread()
        with self.condition:
            self.handlers.add(handler)
        try:
            super().process_request_thread(*args)
        finally:
            with self.condition:
                self.handlers.discard(handler)
                self.condition.notify_all()

    def shutdown_request(self, request):
        try:
            super().shutdown_request(request)
        finally:
            with self.condition:
                self.clients.discard(request)
                self.condition.notify_all()

    def close_clients(self):
        with self.condition:
            self.closing = True
            clients = list(self.clients)
        for client in clients:
            with suppress(OSError):
                client.shutdown(socket.SHUT_RDWR)
        return clients

    def drained(self):
        with self.condition:
            return not self.clients and not self.handlers

    def counts(self):
        with self.condition:
            return {'accepted_clients': len(self.clients), 'active_handlers': len(self.handlers)}

    def wait_drained(self, seconds):
        with self.condition:
            return self.condition.wait_for(lambda: not self.clients and not self.handlers, timeout=seconds)


def unique_json(raw):
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise ValueError('duplicate provider/request field')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda value: (_ for _ in ()).throw(
        ValueError('nonfinite provider/request JSON')))


class ProviderUsageError(ValueError):
    def __init__(self, message, observed_tokens=None):
        super().__init__(message)
        self.observed_tokens = observed_tokens


def provider_usage(body: bytes, content_type: str, model_id: str) -> int:
    sse = 'text/event-stream' in content_type.lower()
    data = [line[5:].strip() for line in body.splitlines() if line.startswith(b'data:')] if sse else [body]
    frames = [value for value in data if value != b'[DONE]']
    usages = []
    identities = 0
    mismatch = False
    malformed = sse and (not data or data[-1] != b'[DONE]' or data.count(b'[DONE]') != 1)
    for raw in frames:
        try:
            frame = unique_json(raw)
        except (ValueError, TypeError):
            malformed = True
            continue
        if not isinstance(frame, dict):
            malformed = True
            continue
        mismatch |= 'model' in frame and frame['model'] != model_id
        identities += 'model' in frame
        if frame.get('usage') is not None:
            usage = frame['usage']
            if not isinstance(usage, dict):
                malformed = True
                continue
            values = [usage.get(name) for name in ('prompt_tokens', 'completion_tokens', 'total_tokens')]
            if (any(type(value) is not int or value < 0 for value in values)
                    or values[0] + values[1] != values[2] or values[2] < 1):
                malformed = True
                continue
            usages.append(values[2])
    if malformed or len(usages) != 1 or not identities or mismatch:
        raise ProviderUsageError('frozen identity and exactly one usage record required',
                                 max(usages) if usages else None)
    return usages[0]


class DeveloperBudgetRelay:
    def __init__(self, path: Path, *, model_id: str, max_tokens: int, max_requests: int,
                 markers: dict[str, str] | None = None, base_url: str = DEFAULT_BASE_URL,
                 mcp_agent_surfaces=None):
        if (not path.is_absolute() or path.exists() or not isinstance(model_id, str) or not model_id
                or type(max_tokens) is not int or max_tokens < 1
                or type(max_requests) is not int or not 1 <= max_requests <= 1000):
            raise ValueError('owned fresh socket and explicit frozen model/budget required')
        self.provider = model_endpoint(base_url)
        from .mcp_agent_profile import validate
        self.mcp_agent_surfaces = validate(mcp_agent_surfaces)
        self.path, self.model_id, self.max_tokens, self.maximum = path, model_id, max_tokens, max_requests
        self.count, self.model_requests, self.tokens = 0, 0, 0
        self.known, self.active, self.closed = True, False, False
        self.records, self.connections, self.provider_sockets = [], set(), set()
        self.lock = threading.Lock()
        self.markers = copy.deepcopy(markers or {})
        self.server = _TrackedServer(str(path), handler_factory(self._connection, self._authorize,
            request_validator=self._validate, response_observer=self._observe, drain_after_disconnect=True))
        os.chmod(path, 0o666)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def _connection(self):
        with self.lock:
            if self.closed:
                raise PermissionError('model relay closed before provider connection')
            connection = http.client.HTTPConnection(self.provider['host'], self.provider['port'], timeout=180)
            self.connections.add(connection)
        original = connection.close

        def close():
            try:
                original()
            finally:
                with self.lock:
                    self.connections.discard(connection)
        connection.close = close
        connection.observe_provider_socket = self._track_socket
        connection.forget_provider_socket = self._forget_socket
        return connection

    def _track_socket(self, provider_socket):
        with self.lock:
            closed = self.closed
            if not closed:
                self.provider_sockets.add(provider_socket)
        if closed:
            with suppress(OSError):
                provider_socket.shutdown(socket.SHUT_RDWR)
            raise PermissionError('model relay closed before provider response ownership')

    def _forget_socket(self, provider_socket):
        with self.lock:
            self.provider_sockets.discard(provider_socket)

    def _authorize(self):
        with self.lock:
            self.count += 1
            return not self.closed and self.count <= self.maximum and self.known and self.tokens < self.max_tokens

    def _validate(self, method, path, body):
        if method != 'POST':
            with self.lock:
                if self.closed:
                    raise PermissionError('model relay closed before request validation')
            return
        request = unique_json(body)
        if not isinstance(request, dict) or request.get('model') != self.model_id:
            raise ValueError('request frozen model identity mismatch')
        body_digest = digest(request)
        sampling = generation_parameters(request)
        text = json.dumps(request.get('messages', []), ensure_ascii=False)
        marker_hits = sorted(name for name, marker in self.markers.items() if marker in text)
        tools = json.dumps(request.get('tools', []), ensure_ascii=False)
        tool_hits = sorted(name for name, marker in self.markers.items() if marker in tools)
        harness = self._harness_observation(request)
        with self.lock:
            if self.closed or self.active or not self.known or self.tokens >= self.max_tokens:
                raise PermissionError('single active model request and token threshold required')
            self.active = True
            self.model_requests += 1
            self.records.append({'kind': 'model-request', 'sequence': len(self.records) + 1,
                'model_request_id': self.model_requests,
                'model_id': self.model_id, 'body_digest': body_digest,
                'generation_parameters': sampling,
                'context_marker_hits': marker_hits, 'tool_definition_marker_hits': tool_hits,
                'observed_monotonic_ns': time.monotonic_ns(),
                **harness})

    def _harness_observation(self, request):
        if self.mcp_agent_surfaces is None:
            return {}
        from .mcp_agent_profile import identity_hits
        tools = request.get('tools', [])
        if type(tools) is not list:
            raise ValueError('provider tool definitions must be a list')
        return {'mcp_server_identity_hits': identity_hits(request.get('messages', [])),
                'tool_names': sorted(tool.get('function', {}).get('name', '')
                    for tool in tools if type(tool) is dict and type(tool.get('function')) is dict
                    and type(tool['function'].get('name')) is str)}

    def _observe(self, method, path, status, content_type, body, complete, *, delivery_complete=None):
        tokens, error = None, None
        try:
            if method == 'POST':
                tokens = provider_usage(body, content_type, self.model_id)
            elif self.model_id not in {item['id'] for item in unique_json(body)['data']}:
                raise ValueError('model discovery omits frozen identity')
            if status != 200 or not complete:
                raise ValueError('incomplete/error upstream response')
        except (ValueError, TypeError, KeyError) as caught:
            error = str(caught)
            tokens = getattr(caught, 'observed_tokens', tokens)
        with self.lock:
            if self.closed:
                complete = False
                delivery_complete = False
                error = error or 'controller interrupted provider response before observer finalization'
            if tokens is not None:
                self.tokens += tokens
            if error:
                self.known = False
            if method == 'POST':
                self.active = False
            self.records.append({'kind': 'model-response', 'sequence': len(self.records) + 1,
                'method': method, 'model_request_id': self.model_requests if method == 'POST' else None,
                'model_id': self.model_id, 'status': status, 'complete': complete,
                'provider_complete': complete,
                'downstream_delivery_complete': complete if delivery_complete is None else delivery_complete,
                'controller_interrupted': self.closed,
                'provider_tokens': tokens, 'error': error, 'cumulative_tokens': self.tokens})

    def close(self):
        with self.lock:
            self.closed = True
            connections = list(self.connections)
            provider_sockets = list(self.provider_sockets)
        self.server.close_clients()
        self.server.shutdown()
        for provider_socket in provider_sockets:
            with suppress(OSError):
                provider_socket.shutdown(socket.SHUT_RDWR)
        for connection in connections:
            if connection.sock is not None:
                try:
                    connection.sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    connection.close()
            connection.close()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.server.wait_drained(2)
        deadline = time.monotonic() + 2
        while self.active and time.monotonic() < deadline:
            time.sleep(0.02)
        if self.path.exists():
            self.path.unlink()

    def evidence(self):
        from .mcp_agent_profile import fields
        with self.lock:
            return {'provider': dict(self.provider),
                    **fields(self.mcp_agent_surfaces),
                    'model_id': self.model_id, 'max_tokens': self.max_tokens, 'maximum_requests': self.maximum,
                'model_requests': self.model_requests, 'observed_tokens': self.tokens, 'usage_known': self.known,
                'threshold_overrun': max(0, self.tokens - self.max_tokens),
                'cleanup_complete': self.closed and not self.active and not self.connections
                    and not self.provider_sockets and not self.thread.is_alive() and self.server.drained(),
                'records': copy.deepcopy(self.records),
                **self.server.counts(),
                'active_provider_sockets': len(self.provider_sockets),
                'scope': 'all actual fixed-provider model requests; SDK stdout untrusted'}

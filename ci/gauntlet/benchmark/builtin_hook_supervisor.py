"""Controller mediation of actual SDK tool calls to normal product NativeHook.

The Unix peer must be the exact independently observed SDK process, not merely
another process sharing its UID. Product JSON is forwarded as product evidence;
only the controller's authenticated transport observations are externally signed.
"""
from __future__ import annotations

import base64
import hashlib
import os
import select
import socket
import struct
import sys
import threading
from collections import Counter
from contextlib import suppress
from pathlib import Path

from .contained_hook_router import ContainedHookRouter
from .contracts import canonical_json, digest, strict_json_loads
from .native_mcp_supervisor import require_root_private
from .native_product_container import process_identity

_FIELDS = {"schema_version", "hook_event_name", "session_id", "tool_call_id", "tool_name", "tool_input", "cwd",
           "execution_environment"}


class BuiltinHookSupervisor:
    def __init__(self, directory: Path, *, plane, controller_session_id: str, max_calls: int = 500):
        if sys.platform != "linux" or os.geteuid() != 0 or not isinstance(controller_session_id, str):
            raise ValueError("builtin hook controller requires Linux root and a fixed controller session")
        require_root_private(directory, existing=False)
        if (len(str(directory / "hook.sock")) > 85 or not controller_session_id or len(controller_session_id) > 256
                or type(max_calls) is not int or not 1 <= max_calls <= 500):
            raise ValueError("bounded builtin hook path/session/call budget required")
        self.directory, self.socket_path, self.plane = directory, directory / "hook.sock", plane
        self.session_id, self.max_calls = controller_session_id, max_calls
        self.sdk_pid, self.sdk_identity, self.sdk_session_id = None, None, None
        self.events, self.requests, self.errors = [], {}, []
        self.call_count = 0
        self.listener, self.thread, self.connection = None, None, None
        self.stopped, self._lock = threading.Event(), threading.RLock()
        self._inode = None
        self._observation_bytes = 0
        self.pre_inputs = {}
        self.contained = ContainedHookRouter(plane, max_executions=max_calls)

    def bind_sdk(self, pid: int, *, expected_identity: dict):
        """Only the root launcher invokes this after observing its actual SDK exec."""
        if type(pid) is not int or pid <= 0 or self.sdk_pid is not None:
            raise ValueError("one externally observed SDK PID required")
        actual = process_identity(pid)
        if (actual != expected_identity or actual["effective_uid"] != 10001
                or actual["effective_capabilities"] != "0000000000000000" or actual["no_new_privileges"] != 1):
            raise ValueError("SDK kernel identity differs from independently observed agent process")
        if getattr(self.plane,'boundary_schema',None)=='private-cell-boundary.v1':
            self.plane.verify_sdk_boundary(actual)
        else:
            products = [event["identity"] for event in self.plane.observations if event["kind"] == "container-boundary"]
            if len(products) != 1 or any(actual[field] in {self.plane.controller_identity[field], products[0][field]}
                for field in ("mount_namespace", "pid_namespace", "network_namespace")):
                raise ValueError("SDK must occupy separate agent/controller/product namespaces")
        self.sdk_pid, self.sdk_identity = pid, actual

    def _emit(self, kind, **fields):
        size = len(canonical_json({"kind": kind, **fields}).encode())
        if self._observation_bytes + size > 12 * 1024 * 1024:
            self.stopped.set()
            self.errors.append("builtin hook observation byte budget exhausted")
            raise ValueError("builtin hook observation byte budget exhausted")
        self._observation_bytes += size
        self.events.append({"sequence": len(self.events) + 1, "kind": kind, **fields})

    def start(self):
        if self.listener is not None or self.directory.exists() or self.stopped.is_set():
            raise ValueError("fresh builtin hook socket directory required")
        self.directory.mkdir(mode=0o710)
        os.chown(self.directory, 0, 10001)
        self.directory.chmod(0o710)
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(str(self.socket_path))
        self.socket_path.chmod(0o660)
        os.chown(self.socket_path, 0, 10001)
        metadata = self.socket_path.stat()
        self._inode = metadata.st_dev, metadata.st_ino
        self.listener.listen(4)
        self.listener.settimeout(0.2)
        self.thread = threading.Thread(target=self._accept, daemon=True)
        self.thread.start()
        return self

    def _accept(self):
        while not self.stopped.is_set():
            try:
                connection, _ = self.listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            self.connection = connection
            try:
                self._serve(connection)
            except (OSError, ValueError) as error:
                self._emit("hook-transport-rejected", reason=str(error))
            finally:
                connection.close()
                self.connection = None

    def _serve(self, connection):
        pid, uid, _ = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if uid != 10001 or self.sdk_identity is None:
            self._emit("peer-rejected", peer_pid=pid, peer_uid=uid)
            raise ValueError("hook socket peer is not the independently observed SDK process")
        if pid != self.sdk_pid:
            try:
                self._execution_peer(pid)
            except (OSError, ValueError, KeyError) as error:
                self._emit("peer-rejected", peer_pid=pid, peer_uid=uid)
                raise ValueError("hook peer is neither bound SDK process nor authenticated execution descendant"
                                 ) from error
        connection.settimeout(35)
        self._emit("peer-observed", peer_pid=pid, peer_uid=uid)
        raw = bytearray()
        while b"\n" not in raw:
            chunk = connection.recv(65536)
            if not chunk:
                raise ValueError("incomplete SDK hook request")
            raw.extend(chunk)
            if len(raw) > 1024 * 1024:
                raise ValueError("SDK hook request exceeds frame budget")
        if raw.count(b"\n") != 1 or not raw.endswith(b"\n"):
            raise ValueError("exactly one SDK hook request per authenticated connection required")
        request = strict_json_loads(bytes(raw[:-1]))
        if type(request) is dict and request.get("operation") == "execute-contained":
            if set(request) != {"schema_version", "operation", "token"} or request["schema_version"] != "1.0":
                raise ValueError("unknown contained execution route fields")
            self._execution_peer(pid)
            connection.settimeout(940)

            def cancelled():
                ready, _, _ = select.select([connection], [], [], 0)
                return self.stopped.is_set() or bool(ready)

            response = self.contained.execute(request["token"], peer_pid=pid, cancelled=cancelled)
        else:
            if pid != self.sdk_pid or process_identity(pid) != self.sdk_identity:
                raise ValueError("hook socket peer is not the independently observed SDK process")
            self._emit("peer-authenticated", peer_pid=pid, peer_uid=uid, identity=self.sdk_identity)
            response = self.handle_request(request, transport_digest=hashlib.sha256(raw[:-1]).hexdigest())
        connection.sendall((canonical_json(response) + "\n").encode())

    def _execution_peer(self, pid):
        original = process_identity(pid)
        if (original["effective_uid"] != 10001 or original["effective_capabilities"] != "0000000000000000"
                or original["no_new_privileges"] != 1
                or any(original[field] != self.sdk_identity[field] for field in
                       ("mount_namespace", "pid_namespace", "network_namespace"))):
            raise ValueError("contained relay escaped the bound agent namespace/UID")
        current = pid
        for _ in range(32):
            if current == self.sdk_pid:
                if process_identity(current) != self.sdk_identity:
                    raise ValueError("SDK process identity changed before contained execution")
                self._emit("execution-peer-authenticated", peer_pid=pid, identity=original)
                return
            status = Path(f"/proc/{current}/status").read_text().splitlines()
            current = int(next(row.split(":", 1)[1] for row in status if row.startswith("PPid:")))
            if current <= 0:
                break
        raise ValueError("contained relay is not a descendant of the bound SDK process")

    def handle_request(self, request: dict, *, transport_digest: str | None = None):
        """Controller-internal validated dispatch; it is not an MCP tool."""
        post = type(request) is dict and request.get("hook_event_name") == "PostToolUse"
        if type(request) is not dict or set(request) != (_FIELDS | {"tool_response", "is_error"} if post else _FIELDS):
            raise ValueError("unknown or missing SDK hook request fields")
        if request["schema_version"] != "1.0" or request["hook_event_name"] not in {"PreToolUse", "PostToolUse"}:
            raise ValueError("unsupported SDK hook event/version")
        for field in ("session_id", "tool_call_id", "tool_name"):
            if not isinstance(request[field], str) or not request[field] or len(request[field]) > 256:
                raise ValueError("bounded actual SDK session/call/tool identity required")
        if (type(request["tool_input"]) is not dict or type(request["execution_environment"]) is not dict
                or request["cwd"] != self.plane.workspace_path):
            raise ValueError("actual SDK input/workspace/environment binding differs")
        canonical_json(request)
        with self._lock:
            if self.sdk_session_id is None:
                self.sdk_session_id = request["session_id"]
            if request["session_id"] != self.sdk_session_id:
                raise ValueError("SDK session changed within the bound controller episode")
            call_id = request["tool_call_id"]
            key, fingerprint = (request["hook_event_name"], call_id), transport_digest or digest(request)
            if not post and key in self.requests and self.requests[key] != fingerprint:
                raise ValueError("SDK tool-call identity reused with changed input")
            if (not post and key in self.requests
                    and getattr(self.plane,'boundary_schema',None)=='private-cell-boundary.v1'):
                raise ValueError('private-cell SDK PreToolUse cannot be replayed')
            if post and key in getattr(self,'completed_posts',set()):
                raise ValueError("SDK tool output review cannot be replayed")
            if not post and self.call_count >= self.max_calls:
                raise ValueError("controller hook call budget exhausted")
            if not post:
                self.call_count += 1
            self.requests[key] = fingerprint
            binding = {"tool_name": request["tool_name"], "tool_input": request["tool_input"]}
            if post:
                if self.pre_inputs.get(call_id) != binding or type(request["is_error"]) is not bool:
                    raise ValueError("actual output does not match its original reviewed SDK input")
                if (not isinstance(request["tool_response"], list) or any(type(item) is not dict
                    or set(item) != {"type", "text"} or item["type"] != "text" or not isinstance(item["text"], str)
                    for item in request["tool_response"])):
                    raise ValueError("only bounded actual SDK text output is supported")
            else:
                self.pre_inputs[call_id] = binding
            payload = {"hook_event_name": request["hook_event_name"],
                "config_path": getattr(self.plane,'config_path','/product/public/omp.json'),
                "session_id": self.session_id, "tool_call_id": call_id, "tool_name": request["tool_name"],
                "tool_input": request["tool_input"], "guard_execution_environment": request["execution_environment"]}
            if getattr(self.plane,'requires_contained_output_binding',False):
                payload['guard_contained_output_profile']='controller-contained-output.v1'
            if post:
                payload.update(tool_response=request["tool_response"], is_error=request["is_error"])
            output = None
            if post and getattr(self.plane,'requires_contained_output_binding',False):
                output = self.contained.output_for_post(call_id,binding)
                if output is not None:
                    payload.update(tool_response=output['tool_response'],is_error=output['is_error'])
            product_response = self.plane.invoke_hook(payload)
            if post:
                if not hasattr(self, "completed_posts"):
                    self.completed_posts = set()
                self.completed_posts.add(key)
            token = None if post else self.contained.prepare(payload, product_response, request_digest=fingerprint)
            response = {"schema_version": "1.0", "tool_call_id": call_id, "request_digest": fingerprint,
                        "product_response": product_response, "product_claims_authenticated": False,
                        "containment_execution_supported": token is not None, "execution_token": token}
            if token is not None and getattr(self.plane,'requires_contained_output_binding',False):
                response['contained_output_binding']='controller-contained-output.v1'
            if output is not None:
                response['contained_output'] = output
                self._emit('actual-contained-output-binding',tool_call_id=call_id,
                    pre_payload_digest=output['pre_payload_digest'],payload_digest=digest(payload),
                    result_digest=output['result_digest'],output_sha256=output['output_sha256'],
                    sdk_output_sha256=hashlib.sha256(''.join(item['text'] for item in
                        request['tool_response']).encode()).hexdigest(),schema=output['schema'])
            self._emit("actual-hook-response", sdk_session_id=self.sdk_session_id,
                controller_session_id=self.session_id, tool_call_id=call_id, request_digest=fingerprint,
                hook_event_name=request["hook_event_name"],tool_name=request["tool_name"],
                original_input_digest=digest(binding),contained_route_issued=token is not None,
                actual_output_sha256=(hashlib.sha256("".join(item["text"] for item in
                    payload["tool_response"]).encode()).hexdigest() if post else None),
                payload_digest=digest(payload), response_digest=digest(product_response),
                product_response=product_response)
            return response

    def prepare_user_prompt(self, prompt: str):
        """Root launcher supplies the actual public task, never model authority."""
        if not isinstance(prompt, str) or not prompt or len(prompt.encode()) > 1024 * 1024:
            raise ValueError("bounded actual public user prompt required")
        with self._lock:
            if self.call_count or any(event["kind"] == "actual-user-prompt-response" for event in self.events):
                raise ValueError("initial public user prompt cannot be replaced after preparation")
            payload = {"hook_event_name": "UserPromptSubmit", "prompt": prompt,
                       "config_path": getattr(self.plane,'config_path','/product/public/omp.json'),
                       "session_id": self.session_id}
            response = self.plane.invoke_hook(payload)
            self._emit("actual-user-prompt-response", payload_digest=digest(payload),
                       response_digest=digest(response), product_response=response)
            return response

    def close(self):
        self.stopped.set()
        if self.listener:
            self.listener.close()
        if self.connection:
            with suppress(OSError):
                self.connection.shutdown(socket.SHUT_RDWR)
        if self.thread:
            self.thread.join(timeout=36)
            if self.thread.is_alive():
                self.errors.append("builtin hook controller thread survived cancellation")
        try:
            self.plane.close()
        finally:
            if self.socket_path.exists():
                metadata = self.socket_path.lstat()
                if self._inode == (metadata.st_dev, metadata.st_ino):
                    self.socket_path.unlink()
                else:
                    self.errors.append("builtin hook socket ownership changed")

    def evidence(self, *, controller_key):
        if not self.stopped.is_set() or self.errors or not self.plane.cleanup_complete:
            raise ValueError("builtin hook custody requires complete controller/product cleanup")
        record = {"schema_version": "1.0", "kind": "isolated-native-builtin-observation",
            "controller_session_id": self.session_id, "sdk_pid": self.sdk_pid, "sdk_identity": self.sdk_identity,
            "transport_observations": self.events, "product_plane": self.plane.declaration(),
            "review_summary":review_summary(self.events,self.contained.events),
            "contained_transport_observations": self.contained.events,
            "product_claims_authenticated": False, "qualification_eligible": False}
        return {"record": record,
                "signature": base64.b64encode(controller_key.sign(canonical_json(record).encode())).decode()}


def review_summary(events, contained_events):
    """Pre admissions need a post proof; native pre refusals need no backend."""
    reviews = [row for row in events if row.get("kind")=="actual-hook-response"]
    from .native_review_status import review_completed
    required,completed,attempted,denied,unreviewable = Counter(),Counter(),Counter(),set(),set()
    consumed = Counter(row["payload_digest"] for row in contained_events
                       if row.get("kind")=="contained-route-consumed")
    for row in reviews:
        call = row["tool_call_id"]
        reviewed=review_completed(row['product_response'])
        if not reviewed:
            unreviewable.add(call)
        if row["hook_event_name"]=="PostToolUse":
            attempted[call] += 1
            if reviewed:
                completed[call] += 1
        elif row["product_response"]["decision"]=="allow":
            required[call] += 1
        elif consumed[row["payload_digest"]]>0:
            required[call] += 1
            consumed[row["payload_digest"]] -= 1
        else:
            denied.add(call)
    return {"schema":"builtin-review-summary.v2",
        "pre_count":sum(row["hook_event_name"]=="PreToolUse" for row in reviews),
        "post_count":sum(row["hook_event_name"]=="PostToolUse" for row in reviews),
        "native_pre_refusal_call_ids":sorted(denied),"backend_admission_call_ids":sorted(required),
        "post_review_call_ids":sorted(completed),"required_post_counts":dict(required),
        "post_attempt_counts":dict(attempted),"unreviewable_hook_call_ids":sorted(unreviewable),
        "post_review_counts":dict(completed),"missing_required_post_call_ids":sorted((required-completed).keys())}

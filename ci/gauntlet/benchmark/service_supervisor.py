"""Trusted service custody and bounded real MCP forwarding over Unix sockets.

Mount only this instance's socket directory into the agent container. The world
database, supervisor memory, signing key and observer are separate trusted
resources. Unix peer credentials bind the configured agent UID; socket group
permissions grant connection access without directory mutation privileges.
"""

from __future__ import annotations

import copy
import ctypes
import math
import os
import select
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path
from uuid import uuid4

from .adapters import McpEndpoint
from .contracts import canonical_json
from .example_proxy import PolicySessionBridge
from .mcp_server import FAMILIES
from .service_relay import MAX_FRAME_BYTES, validate_frame
from .service_thread_backend import ServiceThreadBackend, finish_service_backend
from .world import World

REPO = Path(__file__).resolve().parents[3]


def peer_uid(connection: socket.socket) -> int:
    if sys.platform.startswith("linux"):
        credential = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        return struct.unpack("3i", credential)[1]
    if sys.platform == "darwin":
        library = ctypes.CDLL(None, use_errno=True)
        uid, gid = ctypes.c_uint(), ctypes.c_uint()
        if library.getpeereid(connection.fileno(), ctypes.byref(uid), ctypes.byref(gid)) != 0:
            raise OSError(ctypes.get_errno(), "Unix peer identity unavailable")
        return uid.value
    raise ValueError("Unix peer authentication is unsupported on this platform")


class ServiceSupervisor:
    """Run-owned sockets; authenticated sessions own a child or controller worker."""

    def __init__(
        self,
        world: World,
        directory: Path,
        *,
        allowed_uid: int | None = None,
        socket_gid: int | None = None,
        families: tuple[str, ...] = FAMILIES,
        observer: Callable[[dict], None] | None = None,
        max_sessions: int = 16,
        max_frame_bytes: int = MAX_FRAME_BYTES,
        max_messages: int = 1000,
        idle_timeout: float = 60,
        session_timeout: float = 300,
        policy_factory: Callable[[str], object] | None = None,
        service_factory: Callable[[str], object] | None = None,
        artifact_workflow_id: str | None = None,
        protocol_profile: dict | None = None,
    ):
        if (
            not directory.is_absolute()
            or len(os.fsencode(directory)) > 85
            or not families
            or len(families) != len(set(families))
            or set(families) - set(FAMILIES)
        ):
            raise ValueError("supervisor needs an absolute short owned directory and valid families")
        if (
            type(max_sessions) is not int
            or max_sessions < 1
            or type(max_messages) is not int
            or max_messages < 1
            or type(max_frame_bytes) is not int
            or not 1 <= max_frame_bytes <= MAX_FRAME_BYTES
            or not math.isfinite(idle_timeout)
            or not math.isfinite(session_timeout)
            or idle_timeout <= 0
            or session_timeout <= 0
            or (allowed_uid is not None and (type(allowed_uid) is not int or allowed_uid < 0))
            or (socket_gid is not None and (type(socket_gid) is not int or socket_gid < 0))
        ):
            raise ValueError("invalid service lifecycle budget")
        self.world, self.directory = world, directory
        self.policy_factory = policy_factory
        self.service_factory = service_factory
        self.protocol_profile = None
        if protocol_profile is not None:
            from .mcp_protocol_profiles import ProtocolProfile
            self.protocol_profile = ProtocolProfile(protocol_profile,
                observer=lambda event: self._emit(event.pop('kind'), **event))
            # Shared controller state keeps schema changes across real reconnects.
            # The existing bounded thread backend retains all normal World calls.
            if self.service_factory is None:
                self.service_factory = lambda family: self.world
        if artifact_workflow_id is not None:
            from .mcp_artifact_schema import public_shape
            public_shape(artifact_workflow_id)
        self.artifact_workflow_id = artifact_workflow_id
        self._policies: dict[str, object] = {}
        self.allowed_uid = os.getuid() if allowed_uid is None else allowed_uid
        self.socket_gid, self.families, self.observer = socket_gid, families, observer
        self.max_frame_bytes, self.max_messages = max_frame_bytes, max_messages
        self.idle_timeout, self.session_timeout = idle_timeout, session_timeout
        self.run_id = uuid4().hex
        self.events: list[dict] = []
        self.sockets: dict[str, Path] = {}
        self._listeners: list[socket.socket] = []
        self._threads: list[threading.Thread] = []
        self._connections: set[socket.socket] = set()
        self._children: dict[str, subprocess.Popen] = {}
        self._socket_inodes: dict[Path, tuple[int, int]] = {}
        self._lock = threading.RLock()
        self._emission_lock = threading.RLock()
        self._stop = threading.Event()
        self._slots = threading.BoundedSemaphore(max_sessions)
        self._started = False

    def _emit(self, kind: str, **fields) -> None:
        # Serialize publication without holding the lifecycle/state lock across
        # a collector callback. No internal caller acquires these in reverse.
        with self._emission_lock:
            with self._lock:
                event = {"sequence": len(self.events) + 1, "run_id": self.run_id, "kind": kind, **fields}
                if self.protocol_profile is not None:
                    event['observed_monotonic_ns'] = time.monotonic_ns()
                self.events.append(event)
            if self.observer is not None:
                try:
                    self.observer(copy.deepcopy(event))
                except Exception as error:
                    with self._lock:
                        self.events.append({"sequence": len(self.events) + 1,
                            "run_id": self.run_id, "kind": "observer-error",
                            "reason": type(error).__name__})
                    self._stop.set()

    @property
    def active_children(self) -> int:
        with self._lock:
            return sum(isinstance(worker, subprocess.Popen) for worker in self._children.values())

    @property
    def active_workers(self) -> int:
        with self._lock:
            return sum(
                isinstance(worker, ServiceThreadBackend) and worker.alive() for worker in self._children.values()
            )

    @property
    def active_sessions(self) -> int:
        with self._lock:
            return len(self._children)

    def start(self) -> ServiceSupervisor:
        if self._started or self._stop.is_set():
            raise ValueError("supervisor cannot be started twice")
        self.directory.mkdir(mode=0o700)
        self._started = True
        try:
            if self.socket_gid is not None:
                os.chown(self.directory, -1, self.socket_gid)
                self.directory.chmod(0o710)
            for family in self.families:
                if self.policy_factory is not None:
                    policy = self.policy_factory(family)
                    if not callable(getattr(policy, "mediate", None)):
                        raise ValueError("policy factory must return a real transport mediator")
                    self._policies[family] = policy
                path = self.directory / f"{family}.sock"
                listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self._listeners.append(listener)
                listener.bind(str(path))
                if self.socket_gid is not None:
                    os.chown(path, -1, self.socket_gid)
                path.chmod(0o660 if self.socket_gid is not None else 0o600)
                identity = path.stat()
                self._socket_inodes[path] = (identity.st_dev, identity.st_ino)
                listener.listen(16)
                listener.settimeout(0.2)
                self.sockets[family] = path
                thread = threading.Thread(target=self._accept, args=(family, listener), daemon=True)
                self._threads.append(thread)
                thread.start()
            self._emit("ready", families=list(self.families), allowed_uid=self.allowed_uid)
            return self
        except BaseException:
            self.close()
            raise

    def endpoint(self, family: str, *, python: Path | None = None) -> McpEndpoint:
        if family not in self.sockets or self._stop.is_set():
            raise ValueError("service endpoint is not active")
        return McpEndpoint(
            family,
            (
                str(python or Path(sys.executable)),
                str(Path(__file__).with_name("service_relay.py")),
                "--socket",
                str(self.sockets[family]),
            ),
        )

    def _accept(self, family: str, listener: socket.socket) -> None:
        while not self._stop.is_set():
            try:
                connection, _ = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            if self._stop.is_set():
                connection.close()
                return
            if not self._slots.acquire(blocking=False):
                connection.close()
                self._emit("session-rejected", family=family, reason="concurrency-budget")
                continue
            with self._lock:
                self._connections.add(connection)
                thread = threading.Thread(target=self._session, args=(family, connection), daemon=True)
                self._threads.append(thread)
            thread.start()

    def _spawn(self, family: str, session_id: str):
        if self.service_factory is not None:
            from functools import partial
            from .mcp_server import create_server
            world = self.service_factory(family)
            worker = ServiceThreadBackend(
                world,
                family,
                max_frame_bytes=self.max_frame_bytes,
                server_factory=partial(create_server,artifact_workflow_id=self.artifact_workflow_id,
                                       protocol_profile=self.protocol_profile),
                observer=lambda event: self._emit(event.pop("kind"), family=family, session_id=session_id, **event),
            )
            with self._lock:
                self._children[session_id] = worker
            self._emit(
                "server-worker-started",
                family=family,
                session_id=session_id,
                worker_id=worker.worker_id,
                backend="controller-thread",
            )
            return worker
        read_fd, write_fd = os.pipe()
        try:
            if self._stop.is_set():
                raise ValueError("supervisor is closing")
            os.write(write_fd, self.world.key.private_bytes_raw())
            os.close(write_fd)
            write_fd = -1
            command = [
                sys.executable,
                "-m",
                "ci.gauntlet.benchmark.mcp_server",
                "--db",
                str(self.world.path),
                "--family",
                family,
                "--signing-key-fd",
                str(read_fd),
            ]
            if self.artifact_workflow_id is not None:
                command += ['--artifact-workflow-id', self.artifact_workflow_id]
            environment = {"PATH": "/usr/bin:/bin", "PYTHONPATH": str(REPO)}
            process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=sys.stderr,
                cwd=REPO,
                env=environment,
                pass_fds=(read_fd,),
            )
            os.set_blocking(process.stdin.fileno(), False)
            os.set_blocking(process.stdout.fileno(), False)
            with self._lock:
                self._children[session_id] = process
            self._emit(
                "child-started",
                family=family,
                session_id=session_id,
                pid=process.pid,
                command=command,
                environment_keys=sorted(environment),
            )
            return process
        finally:
            os.close(read_fd)
            if write_fd != -1:
                os.close(write_fd)

    def _session(self, family: str, connection: socket.socket) -> None:
        session_id = uuid4().hex
        process = None
        ended = threading.Event()
        feeder = None
        finished = True
        try:
            if self._stop.is_set():
                return
            if peer_uid(connection) != self.allowed_uid:
                self._emit("session-rejected", family=family, session_id=session_id, reason="peer-uid")
                return
            process = self._spawn(family, session_id)
            connection.settimeout(0.25)
            last_activity = [time.monotonic()]
            started = last_activity[0]
            delivery_lock = threading.Lock()

            def deliver(message):
                payload = (canonical_json(message) + "\n").encode("utf-8")
                validate_frame(payload[:-1], self.max_frame_bytes)
                with delivery_lock:
                    connection.sendall(payload)
                self._emit("delivered", session_id=session_id, family=family, message=message)

            bridge = (
                PolicySessionBridge(
                    self._policies[family],
                    forward=lambda message: self._forward_message(family, session_id, process, ended, message),
                    deliver=deliver,
                    ended=ended,
                    stopping=self._stop,
                )
                if family in self._policies
                else None
            )
            feeder = threading.Thread(
                target=self._feed,
                args=(family, session_id, connection, process, ended, last_activity, bridge),
                daemon=True,
            )
            feeder.start()
            buffer = bytearray()
            while not ended.is_set() and not self._stop.is_set():
                now = time.monotonic()
                if now - last_activity[0] > self.idle_timeout or now - started > self.session_timeout:
                    raise TimeoutError("service session exceeded lifecycle budget")
                ready, _, _ = select.select([process.stdout], [], [], 0.1)
                if not ready:
                    continue
                chunk = os.read(process.stdout.fileno(), 64 * 1024)
                if not chunk:
                    if buffer:
                        raise ValueError("incomplete service response")
                    break
                last_activity[0] = now
                buffer.extend(chunk)
                while b"\n" in buffer:
                    line, _, remaining = buffer.partition(b"\n")
                    message = validate_frame(line, self.max_frame_bytes)
                    self._emit(
                        "frame",
                        session_id=session_id,
                        family=family,
                        direction="service-to-client",
                        stage="received",
                        message=message,
                    )
                    if bridge is None or not bridge.receive(message):
                        deliver(message)
                    buffer[:] = remaining
                if len(buffer) > self.max_frame_bytes:
                    raise ValueError("service response exceeds frame budget")
        except (OSError, ValueError, TimeoutError) as error:
            if not self._stop.is_set():
                self._emit("session-error", family=family, session_id=session_id, reason=type(error).__name__)
        finally:
            ended.set()
            with suppress(OSError):
                connection.shutdown(socket.SHUT_RDWR)
            connection.close()
            if process is not None:
                if feeder is not None:
                    feeder.join(timeout=1)
                finished = finish_service_backend(process, self._emit, family=family, session_id=session_id)
            with self._lock:
                if finished:
                    self._children.pop(session_id, None)
                self._connections.discard(connection)
            if finished:
                self._slots.release()

    def _forward_message(self, family, session_id, process, ended, message):
        encoded = canonical_json(message).encode("utf-8")
        validate_frame(encoded, self.max_frame_bytes)
        payload = memoryview(encoded + b"\n")
        while payload and not ended.is_set() and not self._stop.is_set():
            _, writable, _ = select.select([], [process.stdin], [], 0.1)
            if writable:
                payload = payload[os.write(process.stdin.fileno(), payload) :]
        if payload:
            raise OSError("service forwarding interrupted")
        self._emit("forwarded", session_id=session_id, family=family, message=message)

    def _feed(self, family, session_id, connection, process, ended, last_activity, bridge=None) -> None:
        buffer = bytearray()
        count = 0
        try:
            while not ended.is_set() and not self._stop.is_set():
                try:
                    chunk = connection.recv(64 * 1024)
                except TimeoutError:
                    continue
                if not chunk:
                    if buffer:
                        raise ValueError("incomplete client request")
                    break
                last_activity[0] = time.monotonic()
                buffer.extend(chunk)
                while b"\n" in buffer:
                    line, _, remaining = buffer.partition(b"\n")
                    message = validate_frame(line, self.max_frame_bytes)
                    count += 1
                    if count > self.max_messages:
                        raise ValueError("service request count exceeds budget")
                    self._emit(
                        "frame",
                        session_id=session_id,
                        family=family,
                        direction="client-to-service",
                        stage="received",
                        message=message,
                    )
                    if bridge is not None and message.get("method") == "tools/call":
                        bridge.mediate(message)
                    else:
                        self._forward_message(family, session_id, process, ended, message)
                    buffer[:] = remaining
                if len(buffer) > self.max_frame_bytes:
                    raise ValueError("client request exceeds frame budget")
        except (OSError, ValueError) as error:
            self._emit("session-error", family=family, session_id=session_id, reason=type(error).__name__)
            ended.set()
        finally:
            process.stdin.close()

    def close(self) -> None:
        self._stop.set()
        for listener in self._listeners:
            listener.close()
        with self._lock:
            connections = list(self._connections)
        for connection in connections:
            with suppress(OSError):
                connection.shutdown(socket.SHUT_RDWR)
        for thread in list(self._threads):
            thread.join(timeout=5)
        for path, identity in self._socket_inodes.items():
            if path.exists():
                observed = path.lstat()
                if stat.S_ISSOCK(observed.st_mode) and (observed.st_dev, observed.st_ino) == identity:
                    path.unlink()
        if self._started:
            try:
                self.directory.rmdir()
            except OSError:
                self._emit("cleanup-incomplete", reason="socket-directory-not-empty")
            self._started = False
            self._emit(
                "closed",
                active_children=self.active_children,
                active_workers=self.active_workers,
                active_sessions=self.active_sessions,
            )

    def __enter__(self) -> ServiceSupervisor:
        return self.start()

    def __exit__(self, *_exc) -> None:
        self.close()

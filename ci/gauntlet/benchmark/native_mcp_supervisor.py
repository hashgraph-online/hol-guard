"""Actual installed Guard MCP proxy in private root-controller custody.

The agent gets only public authenticated UDS endpoints. Guard native code,
private Guard home, audit state, and upstream World transport stay outside its
mount/PID namespace. This is transport custody, not qualification authority.
"""
from __future__ import annotations

import base64
import json
import os
import socket
import stat
import struct
import subprocess
import sys
import time
from pathlib import Path

from .contracts import canonical_json
from .installed_guard import guard_endpoints, inspect_installed_guard
from .linux_executor import _identity
from .service_supervisor import ServiceSupervisor, peer_uid

_EVENTS = """
import json,sys
from pathlib import Path
from codex_plugin_scanner.guard.store import GuardStore
store=GuardStore(Path(sys.argv[1]),prime_policy_integrity=False,allow_system_keyring=False)
print(json.dumps(store.list_events(limit=1001),allow_nan=False))
"""


def _custody_identity(pid: int) -> dict:
    observed = _identity(pid)
    status = dict(line.split(":", 1) for line in Path(f"/proc/{pid}/status").read_text().splitlines() if ":" in line)
    observed["effective_uid"] = int(status["Uid"].split()[1])
    return observed


def require_root_private(path: Path, *, existing: bool = True) -> None:
    if (not isinstance(path, Path) or not path.is_absolute() or ".." in path.parts
            or path.parent.resolve() != path.parent or path.is_symlink()):
        raise ValueError("root custody requires a canonical literal private path")
    if existing:
        info = path.stat()
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o077:
            raise ValueError("private controller directory must be root-owned without agent access")


class NativeMcpSupervisor(ServiceSupervisor):
    """Bounded UDS bridge spawning only actual installed OMP Guard proxy CLI."""

    def __init__(self, directory: Path, *, upstream: ServiceSupervisor, python: Path,
                 expected_source_sha: str, private_root: Path, allowed_uid: int = 10001,
                 socket_gid: int | None = 10001, observer=None, max_sessions: int = 16,
                 max_frame_bytes: int = 1024 * 1024, max_messages: int = 1000,
                 idle_timeout: float = 60, session_timeout: float = 300, product_plane=None):
        if sys.platform != "linux" or os.geteuid() != 0:
            raise ValueError("native frontdoor requires the owned Linux root controller")
        if not isinstance(upstream, ServiceSupervisor):
            raise ValueError("native frontdoor requires the actual trusted service supervisor")
        if product_plane is not None:
            from .native_product_container import NativeProductContainer
            if (not isinstance(product_plane, NativeProductContainer)
                    or product_plane.python != python or product_plane.source_sha != expected_source_sha
                    or product_plane.upstream_directory != upstream.directory):
                raise ValueError("product plane differs from exact controller-declared transport identity")
            if product_plane.root.is_relative_to(directory) or directory.is_relative_to(product_plane.root):
                raise ValueError("public frontdoor cannot expose the private product runtime tree")
        expected_uid,expected_gid=(product_plane.uid,product_plane.uid) if product_plane is not None else (0,None)
        if (not isinstance(upstream, ServiceSupervisor) or upstream.allowed_uid != expected_uid
                or upstream.socket_gid != expected_gid or not upstream.sockets or upstream._stop.is_set()):
            raise ValueError("native frontdoor upstream UID/group do not match selected custody plane")
        if product_plane is None:
            require_root_private(upstream.directory)
        require_root_private(private_root, existing=False)
        if (not python.is_absolute() or python.name != "python" or python.parent.name != "bin"
                or python.parent.parent.resolve() != python.parent.parent
                or python.parent.parent.stat().st_uid != 0):
            raise ValueError("retain root-owned installed virtualenv Python identity")
        if (directory == upstream.directory or directory.is_relative_to(upstream.directory)
                or upstream.directory.is_relative_to(directory) or private_root.is_relative_to(directory)
                or directory.is_relative_to(private_root)):
            raise ValueError("public socket directory must be separate from all private custody directories")
        super().__init__(None, directory, allowed_uid=allowed_uid, socket_gid=socket_gid,
            families=upstream.families, observer=observer, max_sessions=max_sessions,
            max_frame_bytes=max_frame_bytes, max_messages=max_messages,
            idle_timeout=idle_timeout, session_timeout=session_timeout)
        self.upstream, self.python, self.private_root = upstream, python, private_root
        self.home = private_root / "home"
        self.guard_home = private_root / "guard"
        self.workspace = self.home / "project"
        self.config_path = private_root / "managed-servers.json"
        self.expected_source_sha = expected_source_sha
        self.identity = None
        self.product_plane = product_plane
        self._routes = {}
        self._private_staged = False
        self._daemon_attempted = False
        self._daemon_cleanup_complete = True
        self._observation_bytes = 0

    def _emit(self, kind, **fields):
        if self.product_plane is not None and kind in {"frame", "forwarded", "delivered"}:
            size = len(canonical_json({"kind": kind, **fields}).encode())
            with self._lock:
                if self._observation_bytes + size > 12 * 1024 * 1024:
                    self._stop.set()
                    raise OSError("isolated product transport exceeded observation byte budget")
                self._observation_bytes += size
        super()._emit(kind, **fields)

    @property
    def active_sessions(self):
        with self._lock:
            return len(self._children)

    def start(self):
        if self._private_staged:
            raise ValueError("native frontdoor cannot be restarted")
        self.private_root.mkdir(mode=0o700)
        if self.product_plane is not None:
            self._private_staged = True
            try:
                self.product_plane.start(self.upstream)
                self.identity = {"product_self_report": self.product_plane.identity_claim, "authenticated": False}
                super().start()
                self._emit("native-frontdoor-ready", source_sha=self.expected_source_sha,
                           product_plane=f"isolated-uid{self.product_plane.uid}",private_product_custody=True)
                return self
            except BaseException:
                self.close()
                raise
        for path in (self.home, self.guard_home, self.workspace):
            path.mkdir(mode=0o700)
        self._private_staged = True
        config = self.guard_home / "config.toml"
        with config.open("x", encoding="utf-8") as stream:
            stream.write('mode="enforce"\nsync=false\ntelemetry=false\ndesktop_notifications=false\n'
                         # Guard also uses this setting for child RPC replies,
                         # capped at its normal 30-second response window.
                         'approval_wait_timeout_seconds=30\n')
        config.chmod(0o600)
        self.identity = inspect_installed_guard(self.python, expected_sha=self.expected_source_sha, home=self.home)
        endpoints = guard_endpoints(tuple(self.upstream.endpoint(family, python=Path("/usr/bin/python3"))
            for family in self.families), python=self.python, home=self.home, guard_home=self.guard_home,
            workspace=self.workspace, config_path=self.config_path, identity=self.identity)
        self._routes = {endpoint.server_id: endpoint for endpoint in endpoints}
        with self.config_path.open("x", encoding="utf-8") as stream:
            stream.write(canonical_json({family: endpoint.launch_record()
                                        for family, endpoint in self._routes.items()}))
        self.config_path.chmod(0o600)
        self._daemon_attempted = True
        try:
            started = self._daemon("ensure")
        except (OSError, subprocess.SubprocessError):
            self.close()
            raise
        self._emit("native-daemon-start", returncode=started.returncode)
        if started.returncode:
            self.close()
            raise ValueError("actual root-owned installed Guard daemon failed to start")
        super().start()
        self._emit("native-frontdoor-ready", source_sha=self.expected_source_sha,
                   native_identity=self.identity, private_product_custody=True)
        return self

    def _daemon(self, operation):
        return subprocess.run([str(self.python.parent / "hol-guard"), "daemon", operation,
            "--guard-home", str(self.guard_home), "--home", str(self.home)], cwd=self.workspace,
            env={"PATH": str(self.python.parent) + ":/usr/bin:/bin", "HOME": str(self.home)},
            capture_output=True, timeout=20, check=False)

    def close(self):
        if self.product_plane is not None:
            try:
                super().close()
            finally:
                self.product_plane.close()
                self._emit("product-plane-closed", cleanup_complete=self.product_plane.cleanup_complete)
            return
        super().close()
        if self._daemon_attempted:
            self._daemon_attempted = False
            try:
                stopped = self._daemon("stop")
                self._daemon_cleanup_complete = stopped.returncode == 0
                self._emit("native-daemon-stop", returncode=stopped.returncode,
                           cleanup_complete=self._daemon_cleanup_complete)
            except (OSError, subprocess.SubprocessError) as error:
                self._daemon_cleanup_complete = False
                self._emit("cleanup-incomplete", reason="native-daemon-stop-" + type(error).__name__)

    def _session(self, family, connection):
        try:
            uid = peer_uid(connection)
            pid = None
            if hasattr(socket, "SO_PEERCRED"):
                pid, _, _ = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            self._emit("peer-authenticated" if uid == self.allowed_uid else "peer-observed-rejected",
                       family=family, peer_uid=uid, peer_pid=pid, allowed_uid=self.allowed_uid)
        except (OSError, ValueError):
            # Superclass independently authenticates and closes/releases every session.
            pass
        super()._session(family, connection)

    def _spawn(self, family, session_id):
        if self._stop.is_set() or not self.upstream.sockets or self.upstream._stop.is_set():
            raise ValueError("native frontdoor or private upstream is closing")
        require_root_private(self.private_root)
        if self.product_plane is not None:
            process = self.product_plane.spawn(family, session_id)
            os.set_blocking(process.stdin.fileno(), False)
            os.set_blocking(process.stdout.fileno(), False)
            with self._lock:
                self._children[session_id] = process
            self._emit("child-started", family=family, session_id=session_id, pid=process.pid,
                       product_pid=process.product_pid, product_identity=process.product_identity,
                       backend=f"isolated-product-uid{self.product_plane.uid}",private_product_custody=True)
            return process
        require_root_private(self.guard_home)
        endpoint = self._routes[family]
        environment = {"PATH": str(self.python.parent) + ":/usr/bin:/bin", "HOME": str(self.home),
                       "LANG": "C.UTF-8", **dict(endpoint.environment)}
        process = subprocess.Popen(list(endpoint.command), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=sys.stderr, cwd=self.workspace, env=environment, close_fds=True)
        try:
            controller, product = _custody_identity(os.getpid()), _custody_identity(process.pid)
            if product["effective_uid"] != 0 or any(product[field] != controller[field] for field in (
                    "mount_namespace", "pid_namespace", "network_namespace")):
                raise ValueError("actual Guard process escaped private controller custody")
        except (OSError, ValueError, KeyError):
            process.kill()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                with self._lock:
                    self._children[session_id] = process
                self._stop.set()
                self._emit("cleanup-incomplete", reason="unobserved-native-proxy-unreaped", pid=process.pid)
            finally:
                process.stdin.close()
                process.stdout.close()
            raise
        os.set_blocking(process.stdin.fileno(), False)
        os.set_blocking(process.stdout.fileno(), False)
        with self._lock:
            self._children[session_id] = process
        self._emit("child-started", family=family, session_id=session_id, pid=process.pid,
                   command=list(endpoint.command), environment_keys=sorted(environment),
                   backend="root-installed-guard-proxy", private_product_custody=True,
                   controller_identity=controller, product_identity=product)
        return process

    def collect_audit(self, *, controller_key) -> dict:
        """Root reads actual product event API, then externally signs that observation."""
        if not self._stop.is_set() or self.active_sessions or not self._daemon_cleanup_complete:
            raise ValueError("audit requires a closed and reaped native frontdoor")
        if self.product_plane is not None:
            declaration = self.product_plane.declaration()
            if not declaration["cleanup_complete"] or not declaration["prefix_unchanged"]:
                raise ValueError("isolated product custody cleanup or prefix integrity incomplete")
            record = {"schema_version": "1.0", "kind": "isolated-native-mcp-observation",
                "collected_at": int(time.time()), "product_plane": declaration,
                "product_events_self_reported": self.product_plane.product_events,
                "product_claims_authenticated": False, "transport_observations": self.events,
                "active_children": self.active_children, "active_sessions": self.active_sessions,
                "qualification_eligible": False}
            return {"record": record,
                    "signature": base64.b64encode(controller_key.sign(canonical_json(record).encode())).decode()}
        require_root_private(self.guard_home)
        observed = subprocess.run([str(self.python), "-I", "-c", _EVENTS, str(self.guard_home)],
            cwd=self.home, env={"PATH": "/usr/bin:/bin", "HOME": str(self.home)},
            capture_output=True, timeout=20, check=False)
        if observed.returncode or len(observed.stdout) > 8 * 1024 * 1024:
            raise ValueError("actual installed Guard product event collection failed")
        def reject_constant(value):
            raise ValueError("nonfinite product audit data")
        def unique_object(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate product audit field")
                result[key] = value
            return result
        events = json.loads(observed.stdout, parse_constant=reject_constant, object_pairs_hook=unique_object)
        if not isinstance(events, list) or len(events) > 1000:
            raise ValueError("bounded actual product event list required")
        record = {"schema_version": "1.0", "kind": "root-native-mcp-audit",
                  "custody_lane": "reviewed-local-product-root-diagnostic",
                  "collected_at": int(time.time()), "source_sha": self.expected_source_sha,
                  "installed_identity": self.identity, "private_product_custody": True,
                  "product_events": events, "transport_observations": self.events,
                  "active_children": self.active_children, "active_sessions": self.active_sessions,
                  "qualification_eligible": False}
        encoded = canonical_json(record).encode()
        if len(encoded) > 16 * 1024 * 1024:
            raise ValueError("product audit exceeds observation budget")
        return {"record": record, "signature": base64.b64encode(controller_key.sign(encoded)).decode()}

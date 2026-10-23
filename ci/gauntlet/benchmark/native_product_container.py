"""Untrusted product execution isolated from agent and benchmark controller.

Product imports, identity probes and audit APIs execute under a fixed unprivileged profile in the
container. Root signs kernel/transport observations; product events and reported
native identity remain explicitly self-reported, never external trust anchors.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import select
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

from .contracts import canonical_json, digest
from .installed_guard import _PROBE
from .linux_executor import _identity
from .native_task_write_policy import install_task_write_policy, task_write_policy

BASE_IMAGE = "sha256:827eaec482942aa5805beac1a75afd755b0daebade43024883b7d1637c27e52d"
_ENV = {"PATH": "/usr/bin:/bin", "HOME": "/root"}
_BIND = """
import json,sys
from codex_plugin_scanner.guard.adapters.mcp_servers import ManagedMcpServer,proxy_cli_args
result={}
for family in json.loads(sys.argv[1]):
 server=ManagedMcpServer(harness='omp',name=family,source_scope='project',
  config_path='/product/public/mcp.json',command='/usr/bin/python3',
  args=('/product/public/service_relay.py','--socket','/upstream/'+family+'.sock'),
  transport='stdio',env={},enabled=True)
 result[family]=proxy_cli_args(proxy_command='omp-mcp-proxy',guard_home='/product/guard',
  server=server,home='/product/home',workspace='/product/home/project')
print(json.dumps(result))
"""
_AUDIT = """
import json
from pathlib import Path
from codex_plugin_scanner.guard.store import GuardStore
store=GuardStore(Path('/product/guard'),prime_policy_integrity=False,allow_system_keyring=False)
print(json.dumps(store.list_events(limit=1001),allow_nan=False))
"""


def _podman(*args, timeout=20, check=True):
    return subprocess.run(["/usr/bin/podman", *args], capture_output=True, text=True,
                          timeout=timeout, check=check, env=_ENV)


def _json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate product output field")
            result[key] = value
        return result
    def finite(value):
        raise ValueError("nonfinite product output")
    value = json.loads(raw, object_pairs_hook=unique, parse_constant=finite)
    canonical_json(value)
    return value


def root_prefix_inventory(prefix: Path) -> dict:
    root = prefix.lstat()
    if (not stat.S_ISDIR(root.st_mode) or root.st_uid != 0 or root.st_mode & 0o022
            or prefix.resolve() != prefix):
        raise ValueError("installed prefix itself must be canonical and exclusively root-owned")
    entries, total = {}, 0
    for directory, dirs, files in os.walk(prefix, followlinks=False):
        for name in sorted([*dirs, *files]):
            path = Path(directory) / name
            info = path.lstat()
            if info.st_uid != 0 or (not path.is_symlink() and info.st_mode & 0o022):
                raise ValueError("installed prefix must remain exclusively root-owned")
            row = {"mode": stat.S_IMODE(info.st_mode), "uid": info.st_uid}
            if path.is_symlink():
                target = os.readlink(path)
                resolved = path.resolve()
                if (not resolved.is_relative_to(prefix)
                        and str(resolved) not in {"/usr/bin/python3", "/usr/bin/python3.12"}):
                    raise ValueError("installed prefix contains an undeclared external link")
                row["link"] = target
            elif path.is_file():
                total += info.st_size
                if total > 2 * 1024**3:
                    raise ValueError("installed prefix exceeds byte budget")
                hasher = hashlib.sha256()
                descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
                with os.fdopen(descriptor, "rb") as stream:
                    opened = os.fstat(stream.fileno())
                    if (opened.st_dev, opened.st_ino, opened.st_size) != (info.st_dev, info.st_ino, info.st_size):
                        raise ValueError("root product prefix changed during inert capture")
                    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                        hasher.update(chunk)
                row["sha256"] = hasher.hexdigest()
            elif not path.is_dir():
                raise ValueError("installed prefix contains a nonregular object")
            entries[path.relative_to(prefix).as_posix()] = row
            if len(entries) > 100000:
                raise ValueError("installed prefix exceeds inventory budget")
    entries["."] = {"mode": stat.S_IMODE(root.st_mode), "uid": root.st_uid}
    return {"digest": digest(entries), "entries": len(entries), "bytes": total,
            "root_uid": root.st_uid, "root_mode": stat.S_IMODE(root.st_mode)}


def root_prefix_digest(prefix: Path) -> str:
    return root_prefix_inventory(prefix)["digest"]


def validate_identity_claim(claim: dict, *, source_sha: str, package_version: str):
    try:
        if (claim["manifest"]["source_sha"] != source_sha or claim["capabilities"]["build_sha"] != source_sha
                or claim["package_version"] != package_version
                or claim["manifest"]["package_version"] != package_version
                or claim["capabilities"]["runtime_version"] != package_version
                or claim["manifest"]["runtime_sha256"] != claim["runtime_sha256"]
                or claim["available"] is not True or claim["compatible"] is not True or claim["installed"] is not True):
            raise ValueError("product identity claim differs from expected build/package")
    except (KeyError, TypeError) as error:
        raise ValueError("malformed product identity claim") from error


def process_identity(pid: int) -> dict:
    identity = _identity(pid)
    status = dict(line.split(":", 1) for line in Path(f"/proc/{pid}/status").read_text().splitlines() if ":" in line)
    identity.update(effective_uid=int(status["Uid"].split()[1]), effective_gid=int(status["Gid"].split()[1]),
                    effective_capabilities=status["CapEff"].strip(), no_new_privileges=int(status["NoNewPrivs"]))
    identity["start_time"] = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]
    identity.update(uid_slots=[int(value) for value in status['Uid'].split()],
        gid_slots=[int(value) for value in status['Gid'].split()],
        supplementary_groups=[int(value) for value in status['Groups'].split()],
        capability_sets={key:status[key].strip() for key in ('CapEff','CapPrm','CapInh','CapBnd','CapAmb')})
    return identity


def verify_product_boundary(identity: dict, controller: dict,*,product_uid=10004):
    if (type(product_uid) is not int or product_uid not in {10004,10005}
            or identity["effective_uid"] != product_uid or identity["effective_gid"] != product_uid
            or identity["effective_capabilities"] != "0000000000000000" or identity["no_new_privileges"] != 1
            or any(identity[field] == controller[field] for field in (
                "mount_namespace", "pid_namespace", "network_namespace"))):
        raise ValueError("actual product UID/capability/namespace boundary differs from declared isolation")
    if product_uid==10005 and (identity.get('uid_slots')!=[10005]*4 or identity.get('gid_slots')!=[10005]*4
            or identity.get('supplementary_groups') not in ([],[10005]) or identity.get('capability_sets')!=
                dict.fromkeys(('CapEff','CapPrm','CapInh','CapBnd','CapAmb'),'0000000000000000')):
        raise ValueError('v2 MCP identity retains saved IDs, groups or capabilities')


class ProductProcess(subprocess.Popen):
    """Host exec client plus its separately measured owned product process."""
    def __init__(self, plane, command):
        self.plane, self.product_pid, self.product_identity = plane, None, None
        before = plane.pids()
        super().__init__(["/usr/bin/podman", "exec", "-i", plane.name, *command],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=sys.stderr, close_fds=True, env=_ENV)
        deadline = time.monotonic() + 5
        invalid = None
        while time.monotonic() < deadline:
            for pid in plane.pids() - before:
                try:
                    actual = Path(f"/proc/{pid}/cmdline").read_bytes().rstrip(b"\0").split(b"\0")
                    if [token.decode() for token in actual] != command:
                        continue
                    identity = process_identity(pid)
                    verify_product_boundary(identity, plane.controller_identity,product_uid=getattr(plane,'uid',10004))
                    self.product_pid, self.product_identity = pid, identity
                    return
                except FileNotFoundError:
                    continue
                except (ValueError, KeyError, UnicodeError) as error:
                    invalid = error
                    break
            if invalid:
                break
            if self.poll() is not None:
                break
            time.sleep(0.02)
        self.kill()
        super().wait(timeout=2)
        self.stdin.close()
        self.stdout.close()
        raise ValueError("actual installed product proxy process could not be measured") from invalid

    def _product_alive(self):
        if self.product_pid is None:
            return False
        try:
            observed = process_identity(self.product_pid)
            return observed["start_time"] == self.product_identity["start_time"]
        except FileNotFoundError:
            return False

    def _signal_product(self, number):
        if self._product_alive():
            observed = process_identity(self.product_pid)
            if (self.product_pid not in self.plane.pids()
                    or observed["effective_uid"] != getattr(self.plane,'uid',10004)):
                raise ValueError("product cancellation target escaped the owned cgroup/UID")
            if observed != self.product_identity:
                self.plane.observations.append({"kind": "product-boundary-changed", "pid": self.product_pid})
            os.kill(self.product_pid, number)

    def terminate(self):
        self._signal_product(signal.SIGTERM)
        super().terminate()

    def kill(self):
        self._signal_product(signal.SIGKILL)
        super().kill()

    def wait(self, timeout=None):
        result = super().wait(timeout=timeout)
        if self._product_alive():
            raise subprocess.TimeoutExpired("owned product proxy still active", timeout)
        return result


class NativeProductContainer:
    def __init__(self, *, runtime_root: Path, python: Path, expected_source_sha: str,
                 upstream_directory: Path | None = None, image_id: str = BASE_IMAGE,
                 wall_seconds: int = 1900, expected_package_version: str = "3.43.1",
                 identity_profile: str = 'native-product-v1',
                 task_write_budget: int | None = None,
                 read_only_tools: tuple[str, ...] = (),
                 reserved_record_ids: tuple[str, ...] = (),
                 required_source_ids: tuple[str, ...] = (),
                 tool_write_limits: dict[str, int] | None = None):
        from .product_identity_profiles import product_uid
        from .product_version import validate_version
        validate_version(expected_package_version)
        self.uid=product_uid(identity_profile)
        if sys.platform != "linux" or os.geteuid() != 0:
            raise ValueError("product isolation requires the owned Linux root controller")
        for path in (runtime_root, python, *(() if upstream_directory is None else (upstream_directory,))):
            if not path.is_absolute() or ".." in path.parts or any(c in str(path) for c in (":", "\n", "\x00")):
                raise ValueError("literal absolute product paths required")
        if (python.name != "python" or python.parent.name != "bin" or python.parent.parent.stat().st_uid != 0
                or python.parent.parent.resolve() != python.parent.parent
                or runtime_root.parent.resolve() != runtime_root.parent
                or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id)
                or not re.fullmatch(r"[0-9a-f]{40}", expected_source_sha)
                or type(wall_seconds) is not int or not 1 <= wall_seconds <= 4000):
            raise ValueError("exact root-owned prefix/image/source identity and bounded wall time required")
        self.task_write_policy = task_write_policy(
            max_writes=task_write_budget, read_only_tools=read_only_tools,
            reserved_record_ids=reserved_record_ids,
            required_source_ids=required_source_ids, tool_write_limits=tool_write_limits)
        self.root, self.python, self.upstream_directory = runtime_root, python, upstream_directory
        self.source_sha, self.image_id, self.wall_seconds = expected_source_sha, image_id, wall_seconds
        self.package_version, self.probe_only = expected_package_version, upstream_directory is None
        self.name = "native-product-" + uuid.uuid4().hex
        self.controller_identity = process_identity(os.getpid())
        self.identity_claim, self.product_events, self.observations = None, [], []
        self.commands, self.mounts, self.cgroup = {}, [], None
        self.loaded, self.started, self.cleanup_complete = False, False, False
        self.cleanup_errors, self.audit_error = [], None
        self.prefix_digest = None
        self._lock = threading.Lock()

    def pids(self):
        return {int(value) for value in (self.cgroup / "cgroup.procs").read_text().split()} if self.cgroup else set()

    def _capture(self, command, *, limit=8 * 1024 * 1024, timeout=20):
        process = subprocess.Popen(["/usr/bin/podman", "exec", self.name, *command],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, env=_ENV)
        buffers, streams = [bytearray(), bytearray()], [process.stdout, process.stderr]
        deadline = time.monotonic() + timeout
        succeeded = False
        try:
            while streams:
                if time.monotonic() > deadline:
                    raise TimeoutError("product capture exceeded deadline")
                ready, _, _ = select.select(streams, [], [], 0.1)
                for stream in ready:
                    chunk = os.read(stream.fileno(), 65536)
                    if not chunk:
                        streams.remove(stream)
                    else:
                        buffers[stream is process.stderr].extend(chunk)
                        if sum(map(len, buffers)) > limit:
                            raise ValueError("product capture exceeded byte budget")
            result = subprocess.CompletedProcess(command, process.wait(timeout=2), bytes(buffers[0]), bytes(buffers[1]))
            succeeded = True
            return result
        finally:
            try:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=2)
            except (OSError, subprocess.SubprocessError) as error:
                self.cleanup_errors.append(str(error))
            finally:
                process.stdout.close()
                process.stderr.close()
            if not succeeded:
                # Killing podman exec alone does not prove its container process
                # stopped. Remove this exact owned container on capture failure.
                try:
                    _podman("rm", "--force", "--time=0", self.name, check=True)
                    self.started = False
                except (OSError, subprocess.SubprocessError) as error:
                    self.cleanup_errors.append(str(error))

    def _daemon(self, action):
        return self._capture([str(self.python), "-I", "-m", "codex_plugin_scanner.cli", "guard", "daemon", action,
            "--guard-home", "/product/guard", "--home", "/product/home"], limit=65536)

    def start(self, upstream=None):
        if (self.started or self.root.exists() or (upstream is None) != self.probe_only
                or (upstream is not None and upstream.directory != self.upstream_directory)):
            raise ValueError("new exclusive product root and exact upstream required")
        if upstream is not None and (upstream.allowed_uid != self.uid or upstream.socket_gid != self.uid):
            raise ValueError(f"product upstream must authenticate exclusive UID/GID{self.uid}")
        if upstream is not None:
            metadata = self.upstream_directory.lstat()
            if metadata.st_uid != 0 or metadata.st_gid != self.uid or stat.S_IMODE(metadata.st_mode) != 0o710:
                raise ValueError("private upstream ownership/mode differs from product declaration")
            for path in self.upstream_directory.iterdir():
                info = path.lstat()
                if (path.name not in {family + ".sock" for family in upstream.families}
                        or not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0 or info.st_gid != self.uid
                        or stat.S_IMODE(info.st_mode) != 0o660):
                    raise ValueError("upstream mount contains undeclared objects")
        self.root.mkdir(mode=0o700)
        public = self.root / "public"
        public.mkdir(mode=0o755)
        public.chmod(0o755)
        shutil.copyfile(Path(__file__).with_name("service_relay.py"), public / "service_relay.py")
        (public / "service_relay.py").chmod(0o644)
        (public / "mcp.json").write_text("{}\n")
        (public / "mcp.json").chmod(0o644)
        for name in ("home", "guard"):
            path = self.root / name
            path.mkdir(mode=0o700)
            os.chown(path, self.uid, self.uid)
        project = self.root / "home" / "project"
        project.mkdir(mode=0o700)
        os.chown(project, self.uid, self.uid)
        config = self.root / "guard" / "config.toml"
        config.write_text('mode="enforce"\nsync=false\ntelemetry=false\ndesktop_notifications=false\n'
                          # This also bounds Guard's child MCP responses.
                          # A one-second approval shortcut breaks cold startup.
                          'approval_wait_timeout_seconds=30\n')
        config.chmod(0o600)
        os.chown(config, self.uid, self.uid)
        install_task_write_policy(self.root / "guard", self.uid, self.task_write_policy)
        self.prefix_digest = root_prefix_digest(self.python.parent.parent)
        self.mounts = [{"source": str(source), "destination": dest, "mode": mode} for source, dest, mode in (
            (self.python.parent.parent, str(self.python.parent.parent), "ro"), (public, "/product/public", "ro"),
            (self.root / "home", "/product/home", "rw"), (self.root / "guard", "/product/guard", "rw"))]
        if upstream is not None:
            self.mounts.append({"source": str(self.upstream_directory), "destination": "/upstream", "mode": "ro"})
        profile = self.root / "product.apparmor"
        profile.write_text(Path(__file__).with_name("developer_browser.apparmor").read_text()
                           .replace("HOL_WORKER_PROFILE", self.name))
        try:
            subprocess.run(["/usr/sbin/apparmor_parser", "--add", str(profile)],
                           check=True, timeout=10, capture_output=True)
            self.loaded = True
            args = ["run", "--detach", "--name", self.name, "--pull=never", "--network=none", "--read-only",
                f"--user={self.uid}:{self.uid}", "--cap-drop=ALL", "--security-opt=no-new-privileges",
                "--security-opt=apparmor=" + self.name, "--pids-limit=256", "--memory=1g", "--cpus=1",
                "--timeout=" + str(self.wall_seconds), "--env=HOME=/product/home", "--env=PATH=/usr/bin:/bin",
                "--workdir=/product/home/project"]
            for mount in self.mounts:
                args.extend(["--volume", f"{mount['source']}:{mount['destination']}:{mount['mode']}"])
            _podman(*args, "--entrypoint=/usr/bin/sleep", self.image_id, str(self.wall_seconds))
            self.started = True
            inspected = _json(_podman("inspect", self.name).stdout)[0]
            pid = inspected["State"]["Pid"]
            identity = process_identity(pid)
            verify_product_boundary(identity, self.controller_identity,product_uid=self.uid)
            observed = {(row["Source"], row["Destination"], row["RW"]) for row in inspected["Mounts"]}
            expected = {(row["source"], row["destination"], row["mode"] == "rw") for row in self.mounts}
            if (observed != expected
                    or inspected["Image"].removeprefix("sha256:") != self.image_id.removeprefix("sha256:")
                    or inspected["HostConfig"]["NetworkMode"] != "none"
                    or not inspected["HostConfig"]["ReadonlyRootfs"]):
                raise ValueError("actual product mounts/image/network differ from plan")
            self.cgroup = Path("/sys/fs/cgroup") / next(line.split(":", 2)[2].lstrip("/") for line in
                Path(f"/proc/{pid}/cgroup").read_text().splitlines() if line.startswith("0::"))
            self.observations.append({"kind": "container-boundary", "identity": identity, "mounts": self.mounts})
            # A cold VM may spend most of the default capture window starting
            # Podman before the bounded identity probe runs. Keep its startup
            # budget explicit while preserving the ordinary call deadline.
            probe = self._capture([str(self.python), "-I", "-c", _PROBE], timeout=45)
            if probe.returncode:
                raise ValueError("isolated product identity probe failed")
            self.identity_claim = _json(probe.stdout)
            validate_identity_claim(self.identity_claim, source_sha=self.source_sha,
                                    package_version=self.package_version)
            if self.probe_only:
                return self
            bindings = self._capture([str(self.python), "-I", "-c", _BIND, canonical_json(list(upstream.families))])
            if bindings.returncode:
                raise ValueError("isolated product normal CLI binding failed")
            for family, args in _json(bindings.stdout).items():
                if family not in upstream.families or not isinstance(args, list) or len(args) != 25:
                    raise ValueError("unexpected isolated product CLI binding")
                server_id = args[9]
                expected = ["-m", "codex_plugin_scanner.cli", "guard", "omp-mcp-proxy",
                    "--guard-home", "/product/guard",
                    "--server-name", family, "--server-id", server_id, "--source-scope", "project", "--config-path",
                    "/product/public/mcp.json", "--transport", "stdio", "--command", "/usr/bin/python3", "--home",
                    "/product/home", "--workspace", "/product/home/project", "--arg=/product/public/service_relay.py",
                    "--arg=--socket", "--arg=/upstream/" + family + ".sock"]
                if (args != expected
                        or not re.fullmatch("mcp_server:omp:project:" + family + ":[0-9a-f]{20}", server_id)):
                    raise ValueError("product binding differs from documented normal CLI")
                self.commands[family] = [str(self.python), "-I", *args]
                from .release_mcp_entry import LIBRARY_VERSIONS, library_command
                if self.package_version in LIBRARY_VERSIONS:
                    self.commands[family] = library_command(self.python, version=self.package_version,
                        family=family, server_id=server_id)
            if set(self.commands) != set(upstream.families) or self._daemon("ensure").returncode:
                raise ValueError("isolated actual product daemon or routes unavailable")
            return self
        except BaseException:
            self.close()
            raise

    def spawn(self, family, session_id):
        with self._lock:
            process = ProductProcess(self, self.commands[family])
            self.observations.append({"kind": "proxy-process", "session_id": session_id, "family": family,
                                      "host_exec_pid": process.pid, "product_pid": process.product_pid,
                                      "identity": process.product_identity})
            return process

    def close(self):
        if self.started:
            try:
                if not self.probe_only:
                    self._daemon("stop")
                    audit = self._capture([str(self.python), "-I", "-c", _AUDIT])
                    events = _json(audit.stdout)
                    if audit.returncode or not isinstance(events, list) or len(events) > 1000:
                        raise ValueError("product self-reported audit incomplete or malformed")
                    self.product_events = events
            except (OSError, ValueError, subprocess.SubprocessError) as error:
                self.audit_error = str(error)
        if self.root.exists():
            try:
                exists = _podman("container", "exists", self.name, check=False)
                if exists.returncode not in {0, 1}:
                    raise ValueError("product container existence could not be established")
                if exists.returncode == 0:
                    _podman("rm", "--force", "--time=0", self.name, check=True)
                if _podman("container", "exists", self.name, check=False).returncode != 1:
                    raise ValueError("product container survived removal")
                self.started = False
            except (OSError, ValueError, subprocess.SubprocessError) as error:
                self.cleanup_errors.append(str(error))
        if self.loaded:
            try:
                subprocess.run(["/usr/sbin/apparmor_parser", "--remove", str(self.root / "product.apparmor")],
                               capture_output=True, timeout=10, check=True)
                self.loaded = False
                if any(line.split(" ", 1)[0] == self.name for line in
                       Path("/sys/kernel/security/apparmor/profiles").read_text().splitlines()):
                    self.cleanup_errors.append("owned product AppArmor profile survived removal")
            except (OSError, subprocess.SubprocessError) as error:
                self.cleanup_errors.append(str(error))
        try:
            if self.cgroup and self.cgroup.exists() and self.pids():
                self.cleanup_errors.append("product cgroup still has processes")
        except OSError as error:
            self.cleanup_errors.append(str(error))
        self.cleanup_complete = not self.started and not self.loaded and not self.cleanup_errors

    def declaration(self):
        return {"schema_version": "1.0" if self.uid==10004 else "2.0",
            "kind":"isolated-product-plane" if self.uid==10004 else "isolated-product-plane.v2","container":self.name,
            "image_id": self.image_id, "source_sha_expected": self.source_sha, "uid": self.uid,
            "prefix_digest": self.prefix_digest, "prefix_unchanged": self.prefix_digest is not None
            and root_prefix_digest(self.python.parent.parent) == self.prefix_digest,
            "controller_identity": self.controller_identity, "observations": self.observations,
            "product_identity_claim": self.identity_claim, "product_claims_authenticated": False,
            "cleanup_complete": self.cleanup_complete, "cleanup_errors": self.cleanup_errors,
            "audit_error": self.audit_error, "qualification_eligible": False}


def namespace_identity_probe(*, runtime_root: Path, python: Path, expected_source_sha: str,
                             image_id: str = BASE_IMAGE, expected_package_version: str = "3.43.1") -> dict:
    """Freeze helper: no candidate imports on controller and no service mounts."""
    plane = NativeProductContainer(runtime_root=runtime_root, python=python, expected_source_sha=expected_source_sha,
        image_id=image_id, expected_package_version=expected_package_version, wall_seconds=90)
    try:
        plane.start()
    finally:
        plane.close()
    return plane.declaration()

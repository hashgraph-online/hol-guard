"""Explicit product/executor profile running the normal contained CLI sink.

Native owns receipt validation, double authorization, sandbox planning and
overlay admission. The controller owns transport tokens and kernel observations.
An implemented route is not established containment or qualification evidence.
"""
from __future__ import annotations

import hashlib
import os
import stat
import subprocess
import time
from pathlib import Path

from .contained_request_file import contained_request_file
from .contracts import canonical_json, digest, strict_json_loads
from .native_builtin_plane import NativeBuiltinHookPlane, _exchange
from .native_product_container import BASE_IMAGE, _json, _podman, process_identity, verify_product_boundary

_START = "import os,sys; assert sys.stdin.buffer.readline()==b'start\\n'; os.execv(sys.argv[1],sys.argv[1:])"
TASK_IDMAP = "uids=10001-10004-1;gids=10001-10004-1"
_BACKEND = """
import hashlib,json,os,stat
p='/usr/bin/bwrap'; s=os.stat(p,follow_symlinks=False)
assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022 and s.st_mode&0o111
h=hashlib.sha256()
with open(p,'rb') as f:
 for b in iter(lambda:f.read(1048576),b''):h.update(b)
print(json.dumps({'path':p,'sha256':h.hexdigest(),'uid':s.st_uid,'mode':stat.S_IMODE(s.st_mode)}))
"""


class NativeContainedHookPlane(NativeBuiltinHookPlane):
    supports_contained_execution = True  # Implemented protocol only; VM proof remains mandatory.

    def __init__(self, *, provider_mounts: tuple[Path, ...] = (), provider_custody_root: Path | None = None,
                 expected_bwrap_sha256: str, **kwargs):
        if kwargs.get("image_id", BASE_IMAGE) == BASE_IMAGE:
            raise ValueError("contained executor requires its own reviewed pinned bubblewrap image")
        super().__init__(**kwargs)
        if (len(expected_bwrap_sha256) != 64
                or any(char not in "0123456789abcdef" for char in expected_bwrap_sha256)):
            raise ValueError("independently frozen bubblewrap binary digest required")
        if provider_mounts:
            if (provider_custody_root is None or provider_custody_root.resolve() != provider_custody_root
                    or provider_custody_root.stat().st_uid != 0):
                raise ValueError("declared root-owned synthetic provider custody required")
            for path in provider_mounts:
                if (not path.is_absolute() or path.resolve() != path or not path.is_dir()
                        or not path.is_relative_to(provider_custody_root) or path == provider_custody_root):
                    raise ValueError("only exact synthetic provider child directories may be mounted")
        if len(provider_mounts) > 8 or len(set(provider_mounts)) != len(provider_mounts):
            raise ValueError("bounded unique declared synthetic provider backing mounts required")
        self.provider_mounts, self.bwrap_digest = provider_mounts, expected_bwrap_sha256
        self.executions, self.backend_observation = [], None
        self.execution_observation_bytes = 0
        self.mapping_observations = []
        for path in (self.workspace_source, *provider_mounts):
            info = path.lstat()
            if info.st_uid != 10001 or info.st_gid != 10001 or info.st_mode & 0o022:
                raise ValueError("idmapped task/provider root requires agent ownership without group/world write")

    def _profile_mounts(self, public):
        mounts = super()._profile_mounts(public)
        mounts[-1]["mode"] = "rw"
        mounts[-1]["idmap"] = TASK_IDMAP
        temporary = self.root / "tmp"
        temporary.mkdir(mode=0o700)
        os.chown(temporary, 10004, 10004)
        mounts.append({"source": str(temporary), "destination": "/tmp", "mode": "rw"})
        mounts.extend({"source": str(path), "destination": str(path), "mode": "rw", "idmap": TASK_IDMAP}
                      for path in self.provider_mounts)
        return mounts

    def start(self):
        try:
            super().start()
            container_pid = _json(_podman("inspect", self.name).stdout)[0]["State"]["Pid"]
            container_identity = process_identity(container_pid)
            verify_product_boundary(container_identity, self.controller_identity)
            for mount in self.mounts:
                if "idmap" not in mount:
                    continue
                source = Path(mount["source"])
                before = source.lstat()
                probe = self._capture(["/usr/bin/python3", "-I", "-c",
                    "import os,json,stat,sys;s=os.stat(sys.argv[1],follow_symlinks=False);"
                    "print(json.dumps({'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode),'inode':s.st_ino}))",
                    mount["destination"]], limit=16384)
                if probe.returncode:
                    raise ValueError("actual idmapped task ownership probe failed")
                reported_inside, after = strict_json_loads(probe.stdout), source.lstat()
                measured_inside = Path(f"/proc/{container_pid}/root{mount['destination']}").stat()
                inside = {"uid": measured_inside.st_uid, "gid": measured_inside.st_gid,
                          "mode": stat.S_IMODE(measured_inside.st_mode), "inode": measured_inside.st_ino}
                outside = {"uid":before.st_uid,"gid":before.st_gid,
                           "mode":stat.S_IMODE(before.st_mode),"inode":before.st_ino}
                if ((before.st_dev,before.st_ino,before.st_uid,before.st_gid,before.st_mode) !=
                    (after.st_dev,after.st_ino,after.st_uid,after.st_gid,after.st_mode)
                    or inside != {**outside,"uid":10004,"gid":10004} or reported_inside != inside
                    or process_identity(container_pid) != container_identity):
                    raise ValueError("actual idmapped ownership differs or physical task custody changed")
                self.mapping_observations.append({"source":str(source),"destination":mount["destination"],
                    "mapping":TASK_IDMAP,"physical":outside,"product_view":inside,
                    "kernel_observer_pid":container_pid,"kernel_identity":container_identity,
                    "namespace_stat_report":reported_inside,"product_report_authenticated":False})
            inspected = self._capture(["/usr/bin/python3", "-I", "-c", _BACKEND], limit=16384)
            if inspected.returncode:
                raise ValueError("root-owned normal bubblewrap backend unavailable in executor namespace")
            self.backend_observation = strict_json_loads(inspected.stdout)
            if self.backend_observation["sha256"] != self.bwrap_digest:
                raise ValueError("executor bubblewrap bytes differ from external frozen image inventory")
            return self
        except BaseException:
            self.close()
            raise

    def execute_contained(self, payload: dict, *, timeout: int = 300, cancelled=None) -> dict:
        if (not self.started or self.backend_observation is None or type(timeout) is not int
                or not 1 <= timeout <= 900 or payload.get("hook_event_name") != "PreToolUse"
                or payload.get("tool_name") != "bash"):
            raise ValueError("running executor and exact bounded Bash snapshot required")
        if len(self.executions) >= 500 or self.execution_observation_bytes >= 12 * 1024 * 1024:
            raise ValueError("contained execution observation budget exhausted")
        raw = canonical_json({"schema": "guard-contained-test-request.v1",
                              "workspace": self.workspace_path, "payload": payload}).encode()
        if len(raw) > 1024 * 1024:
            raise ValueError("normal contained request exceeds native snapshot budget")
        request_sha = hashlib.sha256(raw).hexdigest()
        with contained_request_file(self.root / "home", raw, cleanup_errors=self.cleanup_errors) as name:
            container_request = self.home_path + "/" + name + "/request.json"
            command = [str(self.python), "-I", "-m", "codex_plugin_scanner.cli", "guard", "execute-contained-test",
                "--harness", "omp", "--guard-home", "/product/guard", "--home", self.home_path,
                "--workspace", self.workspace_path, "--request-file", container_request,
                "--request-sha256", request_sha, "--timeout-seconds", str(timeout)]
            with self._lock:
                return self._execute(command, payload, request_sha, timeout, cancelled)

    def _execute(self, command, payload, request_sha, timeout, cancelled):
        launch = ["/usr/bin/python3", "-I", "-c", _START, *command]
        before, product_pid = self.pids(), None
        process = subprocess.Popen(["/usr/bin/podman", "exec", "-i", self.name, *launch],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True,
            env={"PATH": "/usr/bin:/bin", "HOME": "/root"})
        completed, samples = False, {}
        try:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and process.poll() is None:
                for pid in self.pids() - before:
                    try:
                        actual = Path(f"/proc/{pid}/cmdline").read_bytes().rstrip(b"\0").split(b"\0")
                        if [token.decode() for token in actual] == launch:
                            identity = process_identity(pid)
                            verify_product_boundary(identity, self.controller_identity)
                            product_pid = pid
                            break
                    except FileNotFoundError:
                        continue
                if product_pid:
                    break
                time.sleep(0.01)
            if product_pid is None:
                raise ValueError("actual owned contained CLI launch process could not be measured")

            def observe():
                for pid in self.pids() - before:
                    try:
                        row = process_identity(pid)
                        actual = Path(f"/proc/{pid}/cmdline").read_bytes()
                        key = pid, row["start_time"], hashlib.sha256(actual).hexdigest()
                        if key not in samples:
                            if len(samples) >= 1000:
                                raise ValueError("contained kernel observation budget exceeded")
                            samples[key] = {"pid": pid, "identity": row, "command_sha256": key[2]}
                    except FileNotFoundError:
                        continue

            output, error = _exchange(process, b"start\n", timeout=timeout + 30,
                                      observer=observe, cancelled=cancelled)
            if product_pid in self.pids():
                raise ValueError("contained CLI launch process survived completed response")
            result = {"schema_version": "1.0", "exit_code": process.returncode,
                "stdout": output.decode("utf-8", errors="replace"), "stderr": error.decode("utf-8", errors="replace"),
                "stdout_sha256": hashlib.sha256(output).hexdigest(), "stderr_sha256": hashlib.sha256(error).hexdigest(),
                "payload_digest": digest(payload), "request_sha256": request_sha,
                "product_pid": product_pid, "launch_identity": identity,
                "kernel_process_samples": list(samples.values()), "native_command": command,
                "product_claims_authenticated": False, "containment_conformance_established": False}
            self.executions.append(result)
            self.execution_observation_bytes += len(canonical_json(result).encode())
            completed = True
            return result
        finally:
            try:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=2)
            finally:
                for stream in (process.stdin, process.stdout, process.stderr):
                    stream.close()
                if not completed:
                    _podman("rm", "--force", "--time=0", self.name, check=True)
                    self.started = False

    def declaration(self):
        record = super().declaration()
        record.update(kind="isolated-contained-builtin-product-plane", profile="native-contained-builtin-hooks-v1",
            workspace_readonly=False, containment_execution_implemented=True, containment_execution_supported=False,
            containment_conformance_established=False, backend_observation=self.backend_observation,
            executions=self.executions, declared_provider_mounts=[str(path) for path in self.provider_mounts])
        record["idmapped_task_observations"] = self.mapping_observations
        return record

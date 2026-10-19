"""Actual local VM Linux/Podman grading executor; no macOS candidate execution.

The root collector remains outside the container and holds the receipt key only
in memory. Its signed declarations derive from Podman and /proc measurements.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from contextlib import ExitStack
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .contracts import canonical_json
from .developer_oracles import ORACLE_MODULES, DeveloperEvidenceError, ProbePlan, source_tree_digest


def _identity(pid: int) -> dict:
    return {"boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            **{f"{label}_namespace": os.readlink(f"/proc/{pid}/ns/{kind}")
               for label, kind in (("mount", "mnt"), ("pid", "pid"), ("network", "net"))}}


class PodmanLinuxExecutor:
    """One frozen source, one isolated grading run, externally signed evidence."""

    def __init__(self, source: Path, plan: ProbePlan, *, image_id: str,
                 signing_key: Ed25519PrivateKey, staging_parent: Path):
        if sys.platform != "linux" or os.geteuid() != 0:
            raise DeveloperEvidenceError("actual Linux VM root collector is required")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
            raise DeveloperEvidenceError("worker image must be pinned by measured image ID")
        if not source.is_absolute() or source.is_symlink() or not staging_parent.is_absolute():
            raise DeveloperEvidenceError("executor needs absolute owned source and staging paths")
        if source_tree_digest(source) != plan.candidate_tree_digest:
            raise DeveloperEvidenceError("captured source differs before staging")
        self.plan, self.image_id, self.key = plan, image_id, signing_key
        self.worker_id = "developer-" + uuid.uuid4().hex
        self.stage = Path(tempfile.mkdtemp(prefix=self.worker_id + "-", dir=staging_parent))
        self.process = None
        self.isolation = None
        self.cgroup = None
        self.completed = False
        self.apparmor_loaded = False
        self.resources = ExitStack()
        self.stdout = self.resources.enter_context(tempfile.TemporaryFile())  # noqa: SIM115 -- lifetime ExitStack
        self.stderr = self.resources.enter_context(tempfile.TemporaryFile())  # noqa: SIM115 -- lifetime ExitStack
        try:
            self._stage(source)
            self._start()
        except BaseException:
            self.close()
            raise

    @property
    def public_key(self) -> bytes:
        return self.key.public_key().public_bytes_raw()

    def _sign(self, name: str, value: dict) -> dict:
        return {name: value, "signature": base64.b64encode(
            self.key.sign(canonical_json(value).encode())).decode()}

    def _stage(self, source: Path) -> None:
        frozen, project, trusted = (self.stage / name for name in ("source", "project", "trusted"))
        shutil.copytree(source, frozen, symlinks=True)
        frozen.chmod(0o755)
        shutil.copytree(source, project, symlinks=True)
        if source_tree_digest(frozen) != self.plan.candidate_tree_digest or source_tree_digest(
                project) != self.plan.candidate_tree_digest:
            raise DeveloperEvidenceError("staged runtime/source differs from captured artifact")
        self.dependency_digest = None
        if (frozen / "node_modules").is_dir():
            self.dependency_digest = source_tree_digest(frozen / "node_modules", excluded=frozenset())
            if source_tree_digest(project / "node_modules", excluded=frozenset()) != self.dependency_digest:
                raise DeveloperEvidenceError("runtime dependency copy differs from frozen installation")
        trusted.mkdir(mode=0o755)
        trusted.chmod(0o755)
        private, public = trusted / "probes", trusted / "public"
        private.mkdir(mode=0o700)
        public.mkdir(mode=0o755)
        public.chmod(0o755)
        if self.plan.workflow_id == "todo-app-to-github":
            (public / "node_modules").symlink_to("/opt/browser/node_modules")
        package = trusted / "package" / "ci" / "gauntlet" / "benchmark"
        package.mkdir(parents=True, mode=0o700)
        (trusted / "package").chmod(0o700)
        origin = Path(__file__).parent
        for name, digest in self.plan.assets:
            data = (origin / name).read_bytes()
            if hashlib.sha256(data).hexdigest() != digest:
                raise DeveloperEvidenceError("trusted probe changed before staging")
            (private / name).write_bytes(data)
            (private / name).chmod(0o600)
            if name.endswith(".mjs") or name == 'developer_unittest_runner.py':
                (public / name).write_bytes(data)
                (public / name).chmod(0o644)
            if name in ORACLE_MODULES:
                (package / name).write_bytes(data)
                (package / name).chmod(0o600)
        for directory, directories, filenames in os.walk(project, followlinks=False):
            os.chown(directory, 10003, 10003)
            for name in [*directories, *filenames]:
                os.chown(Path(directory) / name, 10003, 10003, follow_symlinks=False)
        project.chmod(0o755)

    def _start(self) -> None:
        browser = self.plan.workflow_id == "todo-app-to-github"
        arguments = ["/usr/bin/podman", "run", "--name", self.worker_id, "--pull=never", "--network=none",
                     "--read-only", "--pids-limit=128", "--memory=" + ("1536m" if browser else "768m"),
                     "--cpus=2", "--timeout=150", "--shm-size=128m",
                     "--cap-drop=ALL", "--cap-add=SETUID", "--cap-add=SETGID", "--cap-add=KILL",
                     "--security-opt=no-new-privileges", "--preserve-fds=3", "--user=0:0",
                     "--volume", f"{self.stage / 'source'}:/candidate/source:ro",
                     "--volume", f"{self.stage / 'project'}:/candidate/project:rw",
                     "--volume", f"{self.stage / 'trusted'}:/trusted:ro", self.image_id]
        if browser:
            arguments.insert(-1, "--cap-add=SYS_CHROOT")
            template = (self.stage / "trusted" / "probes" / "developer_browser.apparmor").read_text()
            self.apparmor_path = self.stage / "worker.apparmor"
            self.apparmor_path.write_text(template.replace("HOL_WORKER_PROFILE", self.worker_id))
            subprocess.run(["/usr/sbin/apparmor_parser", "--add", str(self.apparmor_path)],
                           capture_output=True, timeout=10, check=True)
            self.apparmor_loaded = True
            arguments.insert(-1, "--security-opt=apparmor=" + self.worker_id)
            arguments.insert(-1, "--security-opt=seccomp=" + str(
                self.stage / "trusted" / "probes" / "developer_browser_seccomp.json"))
        self.process = subprocess.Popen([sys.executable, str(Path(__file__).with_name("linux_executor_launcher.py")),
                                         *arguments], stdin=subprocess.PIPE, stdout=self.stdout, stderr=self.stderr,
                                        close_fds=True, env={"PATH": "/usr/bin:/bin", "HOME": "/root"})
        deadline = time.monotonic() + 20
        inspected = None
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                self.stderr.seek(0)
                raise RuntimeError("worker launch failed: " + self.stderr.read(65536).decode(errors="replace"))
            result = subprocess.run(["/usr/bin/podman", "inspect", self.worker_id],
                                    capture_output=True, text=True, timeout=5, check=False)
            if result.returncode == 0:
                inspected = json.loads(result.stdout)[0]
                if inspected["State"].get("Pid", 0) > 0:
                    break
            time.sleep(0.05)
        else:
            raise TimeoutError("worker did not enter its container namespace")
        pid = inspected["State"]["Pid"]
        identity, collector = _identity(pid), _identity(os.getpid())
        if any(identity[key] == collector[key] for key in ("mount_namespace", "pid_namespace", "network_namespace")):
            raise DeveloperEvidenceError("worker shares a collector namespace")
        measured_image = "sha256:" + inspected["Image"].removeprefix("sha256:")
        if inspected["HostConfig"]["NetworkMode"] != "none" or measured_image != self.image_id:
            raise DeveloperEvidenceError("worker network/image does not match declared custody")
        mounts = {entry["Destination"]: entry for entry in inspected["Mounts"]}
        if set(mounts) != {"/candidate/source", "/candidate/project", "/trusted"} or any(
                mounts[target]["RW"] for target in ("/candidate/source", "/trusted")):
            raise DeveloperEvidenceError("worker mount custody differs from declared isolation")
        lines = Path(f"/proc/{pid}/cgroup").read_text().splitlines()
        self.cgroup = Path("/sys/fs/cgroup") / next(line.split(":", 2)[2].lstrip("/")
                                                      for line in lines if line.startswith("0::"))
        declaration = {"schema": "isolated-linux-grader.v1", "worker_id": self.worker_id,
                       "platform": "linux", "isolation": "disposable-vm-and-container", "host_mounts": False,
                       "network": "none", "candidate_uid": 10003, "oracle_uid": 10002,
                       "probes_read_only": True, "collector_in_candidate_namespace": False,
                       "assets": dict(self.plan.assets), "runtime_identity": identity,
                       "supported_authored_challenges": ['authored-developer-python-temperature-boundaries']
                       if json.loads(self.plan.bindings).get('cli_profile') == 'authored-python-temperature-boundaries'
                       else [],
                       "image_id": self.image_id, "dependency_digest": self.dependency_digest,
                       "container_security": {key: inspected["HostConfig"].get(key)
                                              for key in ("CapAdd", "CapDrop", "SecurityOpt", "Privileged")},
                       "effective_capabilities": inspected.get("EffectiveCaps"),
                       "bounding_capabilities": inspected.get("BoundingCaps"),
                       "seccomp_profile_digest": dict(self.plan.assets)["developer_browser_seccomp.json"]
                       if browser else None,
                       "apparmor_template_digest": dict(self.plan.assets)["developer_browser.apparmor"]
                       if browser else None}
        self.isolation = self._sign("declaration", declaration)

    def declaration(self) -> dict:
        if self.isolation is None:
            raise DeveloperEvidenceError("worker namespace measurement is unavailable")
        return self.isolation

    def execute(self, plan: ProbePlan) -> dict:
        if self.completed or plan.digest != self.plan.digest:
            raise DeveloperEvidenceError("executor is one-shot and bound to its captured plan")
        packet = {"plan": plan.record(), "isolation": self.declaration(),
                  "public_key": base64.b64encode(self.public_key).decode()}
        timed_out = False
        try:
            self.process.communicate(canonical_json(packet).encode() + b"\n", timeout=plan.deadline_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
        finally:
            self._reap()
            self.completed = True
        self.stdout.seek(0)
        self.stderr.seek(0)
        output, error = self.stdout.read(plan.max_output_bytes + 1), self.stderr.read(plan.max_output_bytes + 1)
        if len(output) > plan.max_output_bytes or len(error) > plan.max_output_bytes:
            raise DeveloperEvidenceError("actual worker output exceeds receipt budget")
        if self.process.returncode != 0 or timed_out:
            raise DeveloperEvidenceError("actual worker probe failed: " + error.decode(errors="replace"))
        actual = json.loads(output)
        if actual.get("schema") != "developer-observations.v1" or actual.get("workflow_id") != plan.workflow_id:
            raise DeveloperEvidenceError("actual worker did not emit trusted observations")
        if (actual.get("dependency_digest") != self.dependency_digest
                or actual.get("runtime_tree_digest") != plan.candidate_tree_digest):
            raise DeveloperEvidenceError("actual runtime/dependency measurement differs from staged artifact")
        payload = {**actual, "worker_id": self.worker_id, "plan_digest": plan.digest,
                   "cleanup_complete": True, "timed_out": False, "exit_code": 0,
                   "image_id": self.image_id, "dependency_digest": self.dependency_digest,
                   "cleanup_measurement": self.cleanup_measurement}
        self.last_receipt = self._sign("payload", payload)
        return self.last_receipt

    def _reap(self) -> None:
        subprocess.run(["/usr/bin/podman", "rm", "--force", "--time=0", self.worker_id],
                       capture_output=True, timeout=15, check=False)
        if self.process is not None and self.process.poll() is None:
            self.process.kill()
            self.process.wait(timeout=5)
        exists = subprocess.run(["/usr/bin/podman", "container", "exists", self.worker_id],
                                capture_output=True, timeout=5, check=False)
        if exists.returncode != 1:
            raise DeveloperEvidenceError("worker container survived cleanup")
        if self.cgroup is not None and self.cgroup.exists() and (self.cgroup / "cgroup.procs").read_text().strip():
            raise DeveloperEvidenceError("candidate cgroup retains processes after cleanup")
        if self.apparmor_loaded:
            subprocess.run(["/usr/sbin/apparmor_parser", "--remove", str(self.apparmor_path)],
                           capture_output=True, timeout=10, check=True)
            self.apparmor_loaded = False
            active = Path("/sys/kernel/security/apparmor/profiles").read_text().splitlines()
            if any(line.split(" ", 1)[0] == self.worker_id for line in active):
                raise DeveloperEvidenceError("owned browser AppArmor profile survived cleanup")
        self.cleanup_measurement = {"container_exists": False,
                                    "cgroup_exists": bool(self.cgroup is not None and self.cgroup.exists()),
                                    "remaining_pids": [], "owned_apparmor_profile_exists": False}

    def close(self) -> None:
        if (self.process is not None and not self.completed) or self.apparmor_loaded:
            self._reap()
        if self.cgroup is not None and self.cgroup.exists() and (self.cgroup / "cgroup.procs").read_text().strip():
            raise DeveloperEvidenceError("candidate cgroup retains processes after cleanup")
        shutil.rmtree(self.stage)
        self.resources.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

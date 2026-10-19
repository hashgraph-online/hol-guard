"""Normal installed OMP NativeHook CLI in a separate product-only namespace.

This profile shares only a readonly declared task workspace with the agent.
Native decisions are product responses, not controller-authenticated policy
truth. Required containment profiles remain denied until their normal execution
sink can be enforced without exposing private product authority to the agent.
"""
from __future__ import annotations

import hashlib
import os
import re
import select
import subprocess
import time
from pathlib import Path

from .contracts import canonical_json, digest, strict_json_loads
from .installed_guard import _PROBE
from .native_product_container import (
    NativeProductContainer,
    _json,
    _podman,
    process_identity,
    root_prefix_digest,
    validate_identity_claim,
    verify_product_boundary,
)


class NativeBuiltinHookPlane(NativeProductContainer):
    """Own one UID10004 namespace; never execute candidate imports on controller."""

    def __init__(self, *, workspace_source: Path, workspace_custody_root: Path,
                 expected_prefix_digest: str, **kwargs):
        if kwargs.get("upstream_directory") is not None:
            raise ValueError("builtin product profile cannot receive provider service sockets")
        super().__init__(**kwargs)
        if self.uid!=10004:
            raise ValueError('legacy builtin task idmapping requires its original product identity')
        for path in (workspace_source, workspace_custody_root):
            if not path.is_absolute() or ".." in path.parts or path.resolve() != path or not path.is_dir():
                raise ValueError("canonical declared workspace custody required")
        if (not workspace_source.is_relative_to(workspace_custody_root)
                or workspace_custody_root.stat().st_uid != 0
                or workspace_custody_root.stat().st_mode & 0o077):
            raise ValueError("workspace must belong to the declared private root controller run")
        if root_prefix_digest(self.python.parent.parent) != expected_prefix_digest:
            raise ValueError("product prefix differs from independently frozen bytes")
        self.workspace_source, self.expected_prefix_digest = workspace_source, expected_prefix_digest
        self.home_path, self.workspace_path = "/runtime/home", "/runtime/home/project"
        self.probe_only = False
        self.hook_observations = []

    def _daemon(self, action):
        return self._capture([str(self.python), "-I", "-m", "codex_plugin_scanner.cli", "guard", "daemon", action,
            "--guard-home", "/product/guard", "--home", self.home_path], limit=65536)

    def start(self):
        if self.started or self.root.exists():
            raise ValueError("fresh exclusive builtin product root required")
        self.root.mkdir(mode=0o700)
        public = self.root / "public"
        public.mkdir(mode=0o755)
        public.chmod(0o755)
        (public / "omp.json").write_text("{}\n")
        (public / "omp.json").chmod(0o644)
        for name in ("home", "guard"):
            path = self.root / name
            path.mkdir(mode=0o700)
            os.chown(path, 10004, 10004)
        (self.root / "home" / "project").mkdir(mode=0o700)
        os.chown(self.root / "home" / "project", 10004, 10004)
        config = self.root / "guard" / "config.toml"
        config.write_text('mode="enforce"\nsync=false\ntelemetry=false\ndesktop_notifications=false\n'
                          'approval_wait_timeout_seconds=1\n')
        config.chmod(0o600)
        os.chown(config, 10004, 10004)
        self.prefix_digest = root_prefix_digest(self.python.parent.parent)
        if self.prefix_digest != self.expected_prefix_digest:
            raise ValueError("frozen product bytes changed before builtin startup")
        self.mounts = self._profile_mounts(public)
        profile = self.root / "product.apparmor"
        profile.write_text(Path(__file__).with_name("developer_browser.apparmor").read_text()
                           .replace("HOL_WORKER_PROFILE", self.name))
        try:
            subprocess.run(["/usr/sbin/apparmor_parser", "--add", str(profile)],
                           check=True, timeout=10, capture_output=True)
            self.loaded = True
            args = ["run", "--detach", "--name", self.name, "--pull=never", "--network=none", "--read-only",
                "--user=10004:10004", "--cap-drop=ALL", "--security-opt=no-new-privileges",
                "--security-opt=apparmor=" + self.name, "--pids-limit=128", "--memory=1g", "--cpus=1",
                "--timeout=" + str(self.wall_seconds), "--env=HOME=" + self.home_path,
                "--env=PATH=/usr/bin:/bin", "--workdir=" + self.workspace_path]
            for mount in self.mounts:
                options = mount['mode'] + (",idmap=" + mount["idmap"] if "idmap" in mount else "")
                args.extend(["--volume", f"{mount['source']}:{mount['destination']}:{options}"])
            _podman(*args, "--entrypoint=/usr/bin/sleep", self.image_id, str(self.wall_seconds))
            self.started = True
            inspected = _json(_podman("inspect", self.name).stdout)[0]
            pid = inspected["State"]["Pid"]
            identity = process_identity(pid)
            verify_product_boundary(identity, self.controller_identity)
            observed = {(row["Source"], row["Destination"], row["RW"]) for row in inspected["Mounts"]}
            expected = {(row["source"], row["destination"], row["mode"] == "rw") for row in self.mounts}
            if (observed != expected
                    or inspected["Image"].removeprefix("sha256:") != self.image_id.removeprefix("sha256:")
                    or inspected["HostConfig"]["NetworkMode"] != "none"
                    or not inspected["HostConfig"]["ReadonlyRootfs"]):
                raise ValueError("actual builtin product profile differs from declared mounts/image/network")
            self.cgroup = Path("/sys/fs/cgroup") / next(line.split(":", 2)[2].lstrip("/") for line in
                Path(f"/proc/{pid}/cgroup").read_text().splitlines() if line.startswith("0::"))
            self.observations.append({"kind": "container-boundary", "identity": identity, "mounts": self.mounts})
            probe = self._capture([str(self.python), "-I", "-c", _PROBE])
            if probe.returncode:
                raise ValueError("namespace-only builtin product probe failed")
            self.identity_claim = strict_json_loads(probe.stdout)
            validate_identity_claim(self.identity_claim, source_sha=self.source_sha,
                                    package_version=self.package_version)
            if self._daemon("ensure").returncode:
                raise ValueError("normal installed builtin Guard daemon unavailable")
            return self
        except BaseException:
            self.close()
            raise

    def _profile_mounts(self, public):
        return [{"source": str(source), "destination": dest, "mode": mode} for source, dest, mode in (
            (self.python.parent.parent, str(self.python.parent.parent), "ro"), (public, "/product/public", "ro"),
            (self.root / "home", self.home_path, "rw"), (self.root / "guard", "/product/guard", "rw"),
            (self.workspace_source, self.workspace_path, "ro"))]

    def invoke_hook(self, payload: dict, *, timeout: float = 30) -> dict:
        """Return actual normal hook JSON; controller never predicts policy."""
        if not self.started or not 0 < timeout <= 60:
            raise ValueError("running builtin plane and bounded hook deadline required")
        raw = (canonical_json(payload) + "\n").encode()
        if len(raw) > 1024 * 1024:
            raise ValueError("actual SDK hook payload exceeds frame budget")
        command = [str(self.python), "-I", "-m", "codex_plugin_scanner.cli", "guard", "hook", "--json",
            "--harness", "omp", "--guard-home", "/product/guard", "--home", self.home_path,
            "--workspace", self.workspace_path]
        with self._lock:
            return self._invoke(command, raw, payload, timeout)

    def _invoke(self, command, raw, payload, timeout):
        before, product_pid, identity = self.pids(), None, None
        process = subprocess.Popen(["/usr/bin/podman", "exec", "-i", self.name, *command],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True,
            env={"PATH": "/usr/bin:/bin", "HOME": "/root"})
        completed = False
        try:
            deadline = time.monotonic() + min(timeout, 5)
            while time.monotonic() < deadline and process.poll() is None:
                for pid in self.pids() - before:
                    try:
                        actual = Path(f"/proc/{pid}/cmdline").read_bytes().rstrip(b"\0").split(b"\0")
                        if [token.decode() for token in actual] == command:
                            identity = process_identity(pid)
                            verify_product_boundary(identity,self.controller_identity,
                                                    product_uid=getattr(self,'uid',10004))
                            product_pid = pid
                            break
                    except (FileNotFoundError, ProcessLookupError):
                        # A cgroup member may exit between enumeration and any
                        # proc read. Keep the same bounded observation window;
                        # never consume a decision without measuring its hook.
                        continue
                if product_pid:
                    break
                time.sleep(0.01)
            if product_pid is None:
                raise ValueError("actual NativeHook process could not be independently measured")
            output, error = _exchange(process, raw, timeout=timeout)
            raw_response = strict_json_loads(output)
            response = decode_hook_response(output, returncode=process.returncode,
                                            event=payload.get("hook_event_name"))
            if product_pid in self.pids():
                raise ValueError("actual NativeHook process survived its completed response")
            self.hook_observations.append({"sequence": len(self.hook_observations) + 1,
                "product_pid": product_pid, "host_exec_pid": process.pid, "identity": identity,
                "payload_digest": digest(payload), "response": response, "response_digest": digest(response),
                "raw_response": raw_response, "raw_response_digest": digest(raw_response),
                "response_normalization": ("normal-omp-prompt-protocol-2" if raw_response != response else "none"),
                "stderr_digest": hashlib.sha256(error).hexdigest(), "returncode": process.returncode})
            completed = True
            return response
        finally:
            try:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=2)
            finally:
                for stream in (process.stdin, process.stdout, process.stderr):
                    stream.close()
                if not completed:
                    # Host exec termination alone cannot prove product reaping.
                    _podman("rm", "--force", "--time=0", self.name, check=True)
                    self.started = False

    def declaration(self):
        record = super().declaration()
        record.update(kind="isolated-builtin-product-plane", profile="native-builtin-hooks-v1",
                      hooks=self.hook_observations, containment_execution_supported=False,
                      workspace_path=self.workspace_path, workspace_readonly=True)
        return record


def _exchange(process, raw: bytes, *, timeout: float, observer=None, cancelled=None):
    """Bounded duplex stdio; no unbounded communicate or candidate execution."""
    deadline, offset = time.monotonic() + timeout, 0
    buffers, readers = [bytearray(), bytearray()], [process.stdout, process.stderr]
    writer = process.stdin
    for stream in (*readers, writer):
        os.set_blocking(stream.fileno(), False)
    while readers or writer:
        if cancelled is not None and cancelled():
            raise InterruptedError("actual native execution caller cancelled")
        if observer is not None:
            observer()
        if time.monotonic() >= deadline:
            raise TimeoutError("actual native builtin hook exceeded controller deadline")
        ready, writable, _ = select.select(readers, [writer] if writer else [], [], 0.05)
        if writable:
            offset += os.write(writer.fileno(), raw[offset:offset + 65536])
            if offset == len(raw):
                writer.close()
                writer = None
        for stream in ready:
            chunk = os.read(stream.fileno(), 65536)
            if chunk:
                buffers[stream is process.stderr].extend(chunk)
                if sum(map(len, buffers)) > 1024 * 1024:
                    raise ValueError("actual NativeHook response exceeded byte budget")
            else:
                readers.remove(stream)
    process.wait(timeout=max(0.01, deadline - time.monotonic()))
    return bytes(buffers[0]), bytes(buffers[1])


def decode_hook_response(output: bytes, *, returncode: int, event: str | None = None) -> dict:
    """Match normal OMP CLI semantics: nonzero valid denials remain denials."""
    response = strict_json_loads(output)
    if type(response) is dict and "decision" not in response and event == "UserPromptSubmit":
        if (returncode != 0 or set(response) - {"policy_action", "reason_code", "hookSpecificOutput", "risk_signals"}
                or response.get("policy_action") not in {"allow", "warn"}
                or not isinstance(response.get("reason_code"), str) or not response["reason_code"]
                or response.get("hookSpecificOutput") != {"hookEventName": "UserPromptSubmit"}
                or ("risk_signals" in response and (not isinstance(response["risk_signals"], list)
                    or any(not isinstance(item, str) for item in response["risk_signals"])))):
            raise ValueError("normal OMP prompt protocol-2 response malformed")
        # This is the production OMP adapter's explicit protocol normalization.
        # The independent observer retains the original product envelope too.
        return {**response, "decision": "allow"}
    if (type(response) is not dict or response.get("decision") not in {"allow", "deny", "block"}
            or (response.get("reason") is not None and not isinstance(response["reason"], str))
            or (response["decision"] == "allow" and returncode != 0)):
        raise ValueError("actual installed OMP hook returned an invalid decision/protocol")
    if "structured_content_mediation" in response:
        mediation = response["structured_content_mediation"]
        if type(mediation) is not dict:
            raise ValueError("normal OMP structured mediation response malformed")
        decision_id = mediation.get("native_decision_id")
        allowed = {"schema", "action", "reason_code", "native_decision_id"}
        forward = mediation.get("action") == "forward"
        if forward:
            allowed.add("content_sha256")
        if (mediation.get("schema") != "guard-structured-content-mediation.v1"
                or mediation.get("action") not in {"forward", "withhold"}
                or not isinstance(mediation.get("reason_code"), str)
                or not re.fullmatch(r"structured_[a-z0-9_]+", mediation["reason_code"])
                or ("native_decision_id" in mediation and (not isinstance(decision_id, str)
                    or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,256}", decision_id)))
                or (forward and (not isinstance(decision_id, str)
                    or not isinstance(mediation.get("content_sha256"), str)
                    or not re.fullmatch(r"[0-9a-f]{64}", mediation["content_sha256"])))
                or set(mediation) - allowed):
            raise ValueError("normal OMP structured mediation response malformed")
    return response

"""Local isolated business OMP execution; no benchmark qualification authority.

Only public assets, fresh agent state, authenticated service sockets and the
fixed model socket enter the namespace. World/approval databases and signing
keys stay with the controller. The signed declaration records observed
boundaries and cleanup, never task success or product prevention.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
import uuid
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .adapters import McpEndpoint, omp_mcp_configs
from .business_model_budget import seal_model_budget, verify_model_budget
from .contracts import canonical_json, digest
from .developer_budget import DeveloperBudgetRelay
from .installed_guard import guard_endpoints, inspect_installed_guard
from .linux_executor import _identity
from .model_endpoint import model_endpoint
from .mcp_agent_profile import config_profile

BASE_IMAGE = "sha256:827eaec482942aa5805beac1a75afd755b0daebade43024883b7d1637c27e52d"
FAMILIES = frozenset({"mail", "crm", "calendar", "docs", "tables", "chat", "tickets"})
_ENV = {"PATH": "/usr/bin:/bin", "HOME": "/root"}
PUBLIC_HELPERS = ("omp_episode.ts", "business_protocol_recovery.ts",
                  "service_relay.py", "developer_model_relay.py")


def _podman(*args, timeout=20, check=True):
    return subprocess.run(["/usr/bin/podman", *args], capture_output=True, text=True,
                          timeout=timeout, check=check, env=_ENV)


def _path(path: Path) -> Path:
    if not isinstance(path, Path) or not path.is_absolute() or any(
            value in str(path) for value in (":", "\n", "\x00")) or ".." in path.parts:
        raise ValueError("mount paths must be absolute, literal and traversal-free")
    return path


def freeze_public_tree(root: Path) -> dict:
    """Hash inert bytes and literal symlinks; never import any mounted code."""
    entries, total = [], 0
    owners = {0, 501, os.getuid()}
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in sorted([*dirs, *files]):
            path = Path(directory) / name
            info = path.lstat()
            if (info.st_uid not in owners or info.st_uid == 10001
                    or (not path.is_symlink() and info.st_mode & 0o002)
                    or (info.st_gid == 10001 and info.st_mode & 0o020 and not path.is_symlink())):
                raise ValueError("public asset ownership/mode permits undeclared agent custody")
            row = {"path": path.relative_to(root).as_posix(), "uid": info.st_uid, "gid": info.st_gid,
                   "mode": stat.S_IMODE(info.st_mode)}
            if path.is_symlink():
                if not path.resolve().is_relative_to(root):
                    raise ValueError("public SDK symlink escapes declared node_modules mount")
                row["symlink"] = os.readlink(path)
            elif path.is_file():
                total += info.st_size
                row.update(size=info.st_size, sha256=hashlib.sha256(path.read_bytes()).hexdigest())
            elif not path.is_dir():
                raise ValueError("public asset tree contains a nonregular object")
            entries.append(row)
            if len(entries) > 100000 or total > 2 * 1024**3:
                raise ValueError("public SDK exceeds bounded inventory")
    return {"tree_digest": digest(sorted(entries, key=lambda row: row["path"])),
            "entries": len(entries), "bytes": total}


def _file_identity(path: Path) -> dict:
    info = path.stat()
    return {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "size": info.st_size,
            "uid": info.st_uid, "gid": info.st_gid, "mode": stat.S_IMODE(info.st_mode)}


def mapped_config(config: dict, *, guard_python: Path | None = None,
                  guard_identity: dict | None = None) -> dict:
    """Discard host launch commands; derive public MCP argv from family names."""
    keys = {"schema", "sdkRoot", "workspace", "agentDir", "modelId", "baseUrl", "prompt",
            "deadlineSeconds", "maxToolCalls", "maxModelTokens", "endpoints", "mcpAgentSurfaces"}
    if not isinstance(config, dict) or set(config) - keys or config.get("schema") not in {
            "gauntlet-omp-episode.v1", "gauntlet-omp-episode.v2"}:
        raise ValueError("only the public OMP episode contract is accepted")
    agent_profile = config_profile(config)
    model_endpoint(config.get('baseUrl', ''))
    for key, bound in (("deadlineSeconds", 1800), ("maxToolCalls", 500), ("maxModelTokens", 1000000)):
        if type(config.get(key)) is not int or not 1 <= config[key] <= bound:
            raise ValueError("invalid bounded isolated episode budget")
    if any(not isinstance(config.get(key), str) or not config[key] or len(config[key]) > limit
           for key, limit in (("modelId", 256), ("prompt", 100000))):
        raise ValueError("invalid public task or model")
    families = config.get("endpoints")
    if not isinstance(families, dict) or not families or set(families) - FAMILIES:
        raise ValueError("explicit known service families required")
    endpoints = tuple(McpEndpoint(family, ("/usr/bin/python3", "/runtime/public/service_relay.py",
                     "--socket", f"/services/{family}.sock")) for family in sorted(families))
    workspace = Path("/runtime/home/project")
    if (guard_python is None) != (guard_identity is None):
        raise ValueError("protected endpoints require independently observed installed identity")
    if guard_python is not None:
        _path(guard_python)
        if guard_python.name != "python" or guard_python.parent.name != "bin":
            raise ValueError("retain the lexical installed virtualenv Python path")
        endpoints = tuple(guard_endpoints(endpoints, python=guard_python, home=Path("/runtime/home"),
            guard_home=Path("/runtime/guard"), workspace=workspace,
            config_path=Path("/runtime/public/episode.json"), identity=guard_identity))
    return {**({'mcpAgentSurfaces':agent_profile} if agent_profile else {}),
            "schema": config["schema"], "sdkRoot": "/sdk/node_modules/@oh-my-pi/pi-coding-agent",
            "workspace": str(workspace), "agentDir": "/runtime/agent", "modelId": config["modelId"],
            "baseUrl": "http://127.0.0.1:8001/v1", "prompt": config["prompt"],
            "deadlineSeconds": config["deadlineSeconds"], "maxToolCalls": config["maxToolCalls"],
            "maxModelTokens": config["maxModelTokens"],
            "endpoints": omp_mcp_configs(endpoints, workspace=workspace)}


def container_plan(root: Path, *, services_directory: Path, bun: Path, sdk_root: Path,
                   name: str, deadline: int, image_id: str = BASE_IMAGE,
                   guard_python: Path | None = None) -> tuple[list[str], list[dict]]:
    """Exact bind inventory: never mount the controller runtime root."""
    for path in (root, services_directory, bun, sdk_root):
        _path(path)
    if not re.fullmatch(r"business-agent-[0-9a-f]{32}", name) or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
        raise ValueError("owned container name and immutable image digest required")
    if type(deadline) is not int or not 1 <= deadline <= 1800:
        raise ValueError("bounded deadline required")
    if (sdk_root.name != "pi-coding-agent" or sdk_root.parent.name != "@oh-my-pi"
            or sdk_root.parents[1].name != "node_modules"):
        raise ValueError("mount the SDK node_modules subtree only")
    entries = [(root / "public", "/runtime/public", "ro"), (root / "home", "/runtime/home", "rw"),
               (root / "workspace", "/runtime/home/project", "rw"), (root / "agent", "/runtime/agent", "rw"),
               (services_directory, "/services", "ro"), (bun, "/runtime/bun", "ro"),
               (sdk_root.parents[1], "/sdk/node_modules", "ro"), (root / "model.sock", "/runtime/model.sock", "ro")]
    if guard_python is not None:
        _path(guard_python)
        if guard_python.name != "python" or guard_python.parent.name != "bin":
            raise ValueError("lexical virtualenv Python required")
        prefix = guard_python.parent.parent
        entries.extend([(prefix, str(prefix), "ro"), (root / "guard", "/runtime/guard", "rw")])
    inventory = [{"source": str(source), "destination": destination, "mode": mode}
                 for source, destination, mode in entries]
    args = ["run", "--detach", "--name", name, "--pull=never", "--network=none", "--read-only",
            "--user=10001:10001", "--cap-drop=ALL", "--security-opt=no-new-privileges",
            "--security-opt=apparmor=" + name, "--pids-limit=256", "--memory=2g", "--cpus=2",
            "--cpuset-cpus=0-1", "--timeout=" + str(deadline + 90), "--env=HOME=/runtime/home",
            "--env=PATH=/usr/bin:/bin", "--workdir=/runtime/home/project"]
    for entry in inventory:
        args.extend(["--volume", f"{entry['source']}:{entry['destination']}:{entry['mode']}"])
    args.extend(["--entrypoint=/usr/bin/sleep", image_id, str(deadline + 90)])
    return args, inventory


def verify_observed_container(inspected: dict, *, inventory: list[dict], controller: dict,
                              agent: dict, image_id: str) -> None:
    if (inspected["Image"].removeprefix("sha256:") != image_id.removeprefix("sha256:")
            or inspected["Config"]["User"] != "10001:10001"
            or inspected["HostConfig"]["NetworkMode"] != "none"
            or inspected["HostConfig"]["ReadonlyRootfs"] is not True):
        raise ValueError("actual container identity or isolation differs from plan: " + canonical_json({
            "image": inspected["Image"], "user": inspected["Config"]["User"],
            "network": inspected["HostConfig"]["NetworkMode"],
            "readonly": inspected["HostConfig"]["ReadonlyRootfs"]}))
    observed = {(row["Source"], row["Destination"], row["RW"]) for row in inspected["Mounts"] if row["Type"] == "bind"}
    expected = {(row["source"], row["destination"], row["mode"] == "rw") for row in inventory}
    if observed != expected:
        raise ValueError("actual bind mounts differ from public inventory")
    if (agent.get("effective_uid") != 10001 or agent.get("effective_gid") != 10001
            or agent.get("effective_capabilities") != "0000000000000000"
            or agent.get("no_new_privileges") != 1):
        raise ValueError("actual agent UID/GID/capability boundaries differ from plan")
    if any(agent[field] == controller[field] for field in ("mount_namespace", "pid_namespace", "network_namespace")):
        raise ValueError("agent namespace shares controller custody")


def run_isolated_business_episode(*, runtime_root: Path, config: dict, services_directory: Path,
                                 bun: Path, sdk_root: Path, controller_key: Ed25519PrivateKey,
                                 guard_python: Path | None = None, guard_source_sha: str | None = None,
                                 image_id: str = BASE_IMAGE, mcp_protocol_profile: dict | None = None) -> dict:
    if sys.platform != "linux" or os.geteuid() != 0:
        raise ValueError("isolated execution requires the owned Linux root controller")
    mapped_config(config)  # Validate before creating any controller-owned paths.
    from .mcp_protocol_campaign import profile_markers
    protocol_markers = profile_markers(mcp_protocol_profile)
    name = "business-agent-" + uuid.uuid4().hex
    args, inventory = container_plan(runtime_root, services_directory=services_directory,
        bun=bun, sdk_root=sdk_root, name=name, deadline=config["deadlineSeconds"], image_id=image_id,
        guard_python=guard_python)
    if (guard_python is None) != (guard_source_sha is None):
        raise ValueError("protected execution requires exact installed source identity")
    if runtime_root.parent.resolve() != runtime_root.parent:
        raise ValueError("owned runtime parent must be canonical")
    for path in (services_directory, bun, sdk_root):
        if (path.resolve() != path or path.stat().st_uid not in {0, 501, os.getuid()}
                or path.stat().st_uid == 10001 or path.stat().st_mode & 0o002):
            raise ValueError("public mounted sources must be canonical and outside agent custody")
    if json.loads((sdk_root / "package.json").read_text())["version"] != "18.4.12":
        raise ValueError("exact public OMP SDK version required")
    for family in config["endpoints"]:
        if not stat.S_ISSOCK((services_directory / (family + ".sock")).stat().st_mode):
            raise ValueError("authenticated service socket missing")
    runtime_root.mkdir(mode=0o700)
    public = runtime_root / "public"
    public.mkdir(mode=0o755)
    public.chmod(0o755)
    public_helpers = PUBLIC_HELPERS + (('mcp_agent_surfaces.ts',) if config_profile(config) else ())
    for name_asset in public_helpers:
        shutil.copyfile(Path(__file__).with_name(name_asset), public / name_asset)
        (public / name_asset).chmod(0o644)
    for name_dir in ("home", "workspace", "agent"):
        path = runtime_root / name_dir
        path.mkdir(mode=0o700)
        os.chown(path, 10001, 10001)
    guard_identity = None
    if guard_python is not None:
        guard_identity = inspect_installed_guard(guard_python, expected_sha=guard_source_sha,
                                                home=runtime_root / "home")
        prefix = guard_python.parent.parent
        if prefix.stat().st_uid != 0 or prefix.resolve() != prefix:
            raise ValueError("installed product prefix must be canonical and root-owned")
        guard = runtime_root / "guard"
        guard.mkdir(mode=0o700)
        guard_config = guard / "config.toml"
        guard_config.write_text('mode="enforce"\nsync=false\ntelemetry=false\ndesktop_notifications=false\napproval_wait_timeout_seconds=1\n')
        guard_config.chmod(0o600)
        os.chown(guard, 10001, 10001)
        os.chown(guard_config, 10001, 10001)
    mapped = mapped_config(config, guard_python=guard_python, guard_identity=guard_identity)
    (public / "episode.json").write_text(canonical_json(mapped))
    (public / "episode.json").chmod(0o644)
    frozen_assets = {"sdk": freeze_public_tree(sdk_root.parents[1]), "bun": _file_identity(bun),
                     "public": freeze_public_tree(public)}
    events_path, errors_path = runtime_root / "agent-events.jsonl", runtime_root / "agent-stderr.txt"
    relay, relay_requested = None, False
    profile = runtime_root / "agent.apparmor"
    profile.write_text(Path(__file__).with_name("developer_browser.apparmor").read_text()
                       .replace("HOL_WORKER_PROFILE", name))
    loaded, bridge, cgroup, inspected, agent, exit_code = False, None, None, None, None, None
    isolation_observed = False
    controller = _identity(os.getpid())
    controller_error, cleanup_errors = None, []
    try:
        relay_requested = True
        relay = DeveloperBudgetRelay(runtime_root / 'model.sock', model_id=config['modelId'],
                                     base_url=config['baseUrl'],
                                     max_tokens=config['maxModelTokens'], max_requests=config['maxToolCalls'] + 20,
                                     markers=protocol_markers,
                                     mcp_agent_surfaces=config_profile(config))
        subprocess.run(["/usr/sbin/apparmor_parser", "--add", str(profile)],
                       capture_output=True, timeout=10, check=True)
        loaded = True
        _podman(*args)
        inspected = json.loads(_podman("inspect", name).stdout)[0]
        pid = inspected["State"]["Pid"]
        agent = _identity(pid)
        status = dict(line.split(":", 1) for line in Path(f"/proc/{pid}/status").read_text().splitlines()
                      if ":" in line)
        agent.update(effective_uid=int(status["Uid"].split()[1]), effective_gid=int(status["Gid"].split()[1]),
                     effective_capabilities=status["CapEff"].strip(),
                     no_new_privileges=int(status["NoNewPrivs"].strip()))
        verify_observed_container(inspected, inventory=inventory, controller=controller, agent=agent, image_id=image_id)
        isolation_observed = True
        cgroup = Path("/sys/fs/cgroup") / next(line.split(":", 2)[2].lstrip("/") for line in
            Path(f"/proc/{pid}/cgroup").read_text().splitlines() if line.startswith("0::"))
        with (runtime_root / "model-bridge-stderr.txt").open("xb") as bridge_errors:
            bridge = subprocess.Popen(["/usr/bin/podman", "exec", name, "/usr/bin/python3",
                "/runtime/public/developer_model_relay.py", "--socket", "/runtime/model.sock"],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=bridge_errors, env=_ENV)
            for _ in range(30):
                ready = _podman("exec", name, "/usr/bin/python3", "-c", "import urllib.request; "
                    "print(urllib.request.urlopen('http://127.0.0.1:8001/v1/models',timeout=5).status)",
                    timeout=10, check=False)
                if ready.returncode == 0:
                    break
                time.sleep(0.1)
            else:
                raise RuntimeError("fixed model bridge did not become ready")
            with events_path.open("xb") as output, errors_path.open("xb") as errors:
                process = subprocess.run(["/usr/bin/podman", "exec", name, "/runtime/bun",
                    "/runtime/public/omp_episode.ts", "/runtime/public/episode.json"], stdout=output,
                    stderr=errors, stdin=subprocess.DEVNULL, timeout=config["deadlineSeconds"] + 45,
                    check=False, env=_ENV)
                exit_code = process.returncode
    except (OSError, ValueError, RuntimeError, KeyError, subprocess.SubprocessError) as error:
        controller_error = f"{type(error).__name__}: {error}"
    finally:
        try:
            removed = _podman("rm", "--force", "--time=0", name, check=False)
            if removed.returncode and inspected is not None:
                cleanup_errors.append("container removal failed")
        except (OSError, subprocess.SubprocessError) as error:
            cleanup_errors.append(f"container cleanup: {error}")
        try:
            if bridge is not None:
                try:
                    bridge.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    bridge.kill()
                    bridge.wait(timeout=5)
        except (OSError, subprocess.SubprocessError) as error:
            cleanup_errors.append(f"bridge cleanup: {error}")
        try:
            if relay is not None:
                relay.close()
        except OSError as error:
            cleanup_errors.append(f"model relay cleanup: {error}")
        try:
            if loaded:
                subprocess.run(["/usr/sbin/apparmor_parser", "--remove", str(profile)],
                               capture_output=True, timeout=10, check=True)
                if any(line.split(" ", 1)[0] == name for line in
                       Path("/sys/kernel/security/apparmor/profiles").read_text().splitlines()):
                    cleanup_errors.append("owned AppArmor profile survived cleanup")
        except (OSError, subprocess.SubprocessError) as error:
            cleanup_errors.append(f"profile cleanup: {error}")
        try:
            if _podman("container", "exists", name, check=False).returncode != 1:
                cleanup_errors.append("container still exists or existence check failed")
            if cgroup is not None and cgroup.exists() and (cgroup / "cgroup.procs").read_text().strip():
                cleanup_errors.append("agent cgroup still has processes")
        except (OSError, subprocess.SubprocessError) as error:
            cleanup_errors.append(f"{type(error).__name__}: {error}")
    try:
        post_assets = {"sdk": freeze_public_tree(sdk_root.parents[1]), "bun": _file_identity(bun),
                       "public": freeze_public_tree(public)}
        assets_unchanged = frozen_assets == post_assets
    except (OSError, ValueError) as error:
        post_assets, assets_unchanged = {"error": str(error)}, False
    if not assets_unchanged:
        controller_error = (controller_error or "") + " public assets changed during execution"
    model_budget = seal_model_budget(relay, mapped, controller_key=controller_key, base_url=config['baseUrl'],
                                    startup_incomplete=relay_requested and relay is None,
                                    mcp_protocol_profile=mcp_protocol_profile)
    (runtime_root / 'model-budget.json').write_text(canonical_json(model_budget) + '\n')
    budget_usage = verify_model_budget(model_budget, trusted_public_key=controller_key.public_key().public_bytes_raw(),
        model_id=config['modelId'], max_tokens=config['maxModelTokens'], config_digest=digest(mapped),
        base_url=config['baseUrl'])
    if not budget_usage['cleanup_complete']:
        cleanup_errors.append('model budget relay cleanup incomplete')
    record = {"schema_version": "1.0", "kind": "isolated-business-agent", "container": name,
        "image_id": image_id, "observed_image": inspected["Image"] if inspected else None,
        "uid": 10001, "controller": controller, "agent": agent,
        "isolation_observed": isolation_observed, "agent_cgroup": str(cgroup) if cgroup else None,
        "network_mode": inspected["HostConfig"]["NetworkMode"] if inspected else None,
        "mounts": inventory, "public_config_digest": digest(mapped),
        "public_assets": {asset: hashlib.sha256((public / asset).read_bytes()).hexdigest() for asset in public_helpers},
        "bun_sha256": hashlib.sha256(bun.read_bytes()).hexdigest(),
        "sdk_package_sha256": hashlib.sha256((sdk_root / "package.json").read_bytes()).hexdigest(),
        "frozen_assets": frozen_assets, "post_assets": post_assets, "assets_unchanged": assets_unchanged,
        "guard_identity": guard_identity, "model_requests": budget_usage['model_requests'], "exit_code": exit_code,
        "model_budget_evidence": model_budget,
        "model_relay": {"provider_host": model_endpoint(config['baseUrl'])['host'],
                        "provider_port": model_endpoint(config['baseUrl'])['port'],
                        "agent_base_url": mapped["baseUrl"], "declared_base_url": config["baseUrl"]},
        "controller_error": controller_error, "cleanup_complete": not cleanup_errors,
        "cleanup_errors": cleanup_errors, "qualification_eligible": False,
        "qualification_reason": "local diagnostic; reviewed independent qualification consumer required"}
    envelope = {"record": record,
                "signature": base64.b64encode(controller_key.sign(canonical_json(record).encode())).decode()}
    (runtime_root / "isolation.json").write_text(canonical_json(envelope))
    return {"exit_code": exit_code, "controller_error": controller_error, "isolation": envelope,
            "events_path": str(events_path), "stderr_path": str(errors_path), "guard_identity": guard_identity,
            "model_budget_evidence": model_budget}

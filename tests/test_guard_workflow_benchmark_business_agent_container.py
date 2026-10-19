import base64
import json
import socket
import subprocess
import tempfile
from copy import deepcopy
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ci.gauntlet.benchmark.business_agent_container import (
    BASE_IMAGE,
    container_plan,
    freeze_public_tree,
    mapped_config,
    run_isolated_business_episode,
    verify_observed_container,
)


def public_config():
    return {"schema": "gauntlet-omp-episode.v1", "modelId": "public-model", "prompt": "Read the authorized task",
            "deadlineSeconds": 120, "maxToolCalls": 12, "maxModelTokens": 10000,
            "sdkRoot": "/host/sdk", "workspace": "/host/workspace", "agentDir": "/host/agent",
            "baseUrl": "http://host.lima.internal:8001/v1", "endpoints": {"docs": {}, "mail": {}}}


def plan(**kw):
    return container_plan(Path("/owned/controller/runtime"), services_directory=Path("/var/tmp/bs001"),
        bun=Path("/owned/public/bun"), sdk_root=Path("/owned/public/node_modules/@oh-my-pi/pi-coding-agent"),
        name="business-agent-" + "a" * 32, deadline=120, **kw)


def test_public_mapping_derives_endpoints_ignoring_model_launch_fields():
    config = public_config()
    config["endpoints"]["docs"] = {"command": "/host/private/python", "env": {"SECRET": "ignored"}}
    mapped = mapped_config(config)
    assert mapped["workspace"] == "/runtime/home/project"
    assert mapped["baseUrl"] == "http://127.0.0.1:8001/v1"
    assert mapped["endpoints"]["docs"]["command"] == "/usr/bin/python3"
    assert mapped["endpoints"]["docs"]["args"] == [
        "/runtime/public/service_relay.py", "--socket", "/services/docs.sock"]
    assert mapped["endpoints"]["docs"]["env"] == {}
    assert "private" not in str(mapped)


@pytest.mark.parametrize("mutation", [
    {"deadlineSeconds": True}, {"deadlineSeconds": 1801}, {"maxModelTokens": float("nan")},
    {"maxToolCalls": 0}, {"endpoints": {"oracle": {}}}, {"endpoints": {}},
    {"provider_api_key": "credential"}, {"prompt": ""}, {"schema": "unversioned"},
])
def test_mapping_rejects_unknown_mistyped_or_unbounded_contract(mutation):
    with pytest.raises(ValueError):
        mapped_config(public_config() | mutation)


def test_exact_mount_inventory_keeps_controller_root_databases_outside():
    args, inventory = plan()
    assert "--network=none" in args and "--user=10001:10001" in args and "--read-only" in args
    assert "--cap-drop=ALL" in args and "--security-opt=no-new-privileges" in args
    assert len(inventory) == 8
    assert not any(row["source"] == "/owned/controller/runtime" for row in inventory)
    assert {row["destination"] for row in inventory if row["mode"] == "rw"} == {
        "/runtime/home", "/runtime/home/project", "/runtime/agent"}
    assert all(row["mode"] == "ro" for row in inventory if row["destination"] in {
        "/services", "/runtime/model.sock", "/sdk/node_modules", "/runtime/public"})
    assert not any(token in str(inventory) for token in ("world.db", "oracle", "signing"))


def test_guard_mount_preserves_lexical_virtualenv_binary_path():
    python = Path("/root-installed/.venv/bin/python")
    _, inventory = plan(guard_python=python)
    assert {"source": "/root-installed/.venv", "destination": "/root-installed/.venv", "mode": "ro"} in inventory
    with pytest.raises(ValueError):
        plan(guard_python=Path("/usr/bin/python3.12"))


@pytest.mark.parametrize("name,image", [("other-container", BASE_IMAGE),
                                      ("business-agent-" + "a" * 32, "mutable:latest")])
def test_plan_requires_owned_identity_and_immutable_image(name, image):
    with pytest.raises(ValueError):
        container_plan(Path("/owned/runtime"), services_directory=Path("/services"),
            bun=Path("/bun"), sdk_root=Path("/node_modules/@oh-my-pi/pi-coding-agent"),
            name=name, image_id=image, deadline=120)


def observed():
    _, inventory = plan()
    inspected = {"Image": BASE_IMAGE, "Config": {"User": "10001:10001"},
                 "HostConfig": {"NetworkMode": "none", "ReadonlyRootfs": True},
                 "Mounts": [{"Type": "bind", "Source": row["source"], "Destination": row["destination"],
                             "RW": row["mode"] == "rw"} for row in inventory]}
    controller = {"mount_namespace": "mnt:1", "pid_namespace": "pid:1", "network_namespace": "net:1"}
    agent = {"mount_namespace": "mnt:2", "pid_namespace": "pid:2", "network_namespace": "net:2",
             "effective_uid": 10001, "effective_gid": 10001, "effective_capabilities": "0000000000000000",
             "no_new_privileges": 1}
    return inspected, inventory, controller, agent


def test_actual_namespace_and_mount_observations_required():
    inspected, inventory, controller, agent = observed()
    verify_observed_container(inspected, inventory=inventory, controller=controller, agent=agent, image_id=BASE_IMAGE)
    for mutation in ("uid", "network", "extra-mount", "missing-mount", "writable-public", "shared-pid",
                     "actual-uid", "caps", "privileges", "image"):
        changed, agent_changed = deepcopy(inspected), dict(agent)
        if mutation == "uid":
            changed["Config"]["User"] = "0"
        elif mutation == "network":
            changed["HostConfig"]["NetworkMode"] = "host"
        elif mutation == "extra-mount":
            changed["Mounts"].append({"Type": "bind", "Source": "/private", "Destination": "/private", "RW": False})
        elif mutation == "missing-mount":
            changed["Mounts"].pop()
        elif mutation == "writable-public":
            changed["Mounts"][0]["RW"] = True
        elif mutation == "shared-pid":
            agent_changed["pid_namespace"] = controller["pid_namespace"]
        elif mutation == "actual-uid":
            agent_changed["effective_uid"] = 0
        elif mutation == "caps":
            agent_changed["effective_capabilities"] = "0000000000000001"
        elif mutation == "privileges":
            agent_changed["no_new_privileges"] = 0
        else:
            changed["Image"] = "sha256:" + "b" * 64
        with pytest.raises(ValueError):
            verify_observed_container(changed, inventory=inventory, controller=controller,
                                      agent=agent_changed, image_id=BASE_IMAGE)


def test_nonlinux_controller_fails_before_creating_runtime(tmp_path, monkeypatch):
    monkeypatch.setattr("ci.gauntlet.benchmark.business_agent_container.sys.platform", "darwin")
    root = tmp_path / "runtime"
    with pytest.raises(ValueError, match="Linux root"):
        run_isolated_business_episode(runtime_root=root, config=public_config(),
            services_directory=Path("/services"), bun=Path("/bun"), sdk_root=Path("/sdk"), controller_key=None)
    assert not root.exists()


def test_inert_asset_freeze_detects_bytes_and_modes_without_execution(tmp_path):
    script = tmp_path / "candidate.py"
    script.write_text("raise RuntimeError('must never execute')\n")
    script.chmod(0o644)
    first = freeze_public_tree(tmp_path)
    assert first["entries"] == 1
    script.write_text("raise RuntimeError('different inert bytes')\n")
    second = freeze_public_tree(tmp_path)
    assert first["tree_digest"] != second["tree_digest"]
    script.chmod(0o600)
    assert second["tree_digest"] != freeze_public_tree(tmp_path)["tree_digest"]
    script.chmod(0o666)
    with pytest.raises(ValueError, match="custody"):
        freeze_public_tree(tmp_path)


def test_asset_freeze_rejects_symlink_escape_and_special_files(tmp_path):
    inside = tmp_path / "inside"
    inside.mkdir()
    outside = tmp_path / "outside"
    outside.write_text("public but undeclared")
    (inside / "escape").symlink_to(outside)
    with pytest.raises(ValueError, match="escapes"):
        freeze_public_tree(inside)


def test_exact_podman_digest_without_algorithm_prefix_is_same_identity():
    inspected, inventory, controller, agent = observed()
    inspected["Image"] = BASE_IMAGE.removeprefix("sha256:")
    verify_observed_container(inspected, inventory=inventory, controller=controller, agent=agent, image_id=BASE_IMAGE)


@pytest.mark.parametrize('mask',[0o022,0o077])
def test_cleanup_failures_do_not_skip_model_relay_or_profile_and_are_signed(tmp_path, monkeypatch,mask):
    import os
    import stat
    from ci.gauntlet.benchmark import business_agent_container as module
    from ci.gauntlet.benchmark.contracts import canonical_json
    tmp_path = tmp_path.resolve()
    sdk = tmp_path / "node_modules" / "@oh-my-pi" / "pi-coding-agent"
    sdk.mkdir(parents=True)
    (sdk / "package.json").write_text('{"version":"18.4.12"}')
    bun = tmp_path / "bun"
    bun.write_bytes(b"public inert Bun fixture")
    socket_directory = tempfile.TemporaryDirectory(prefix="bs-", dir="/tmp")
    services = Path(socket_directory.name).resolve()
    sockets = []
    for family in ("docs", "mail"):
        listener = socket.socket(socket.AF_UNIX)
        listener.bind(str(services / (family + ".sock")))
        sockets.append(listener)
    class Relay:
        count = 0
        closed = False

        def __init__(self, *args, **kwargs):
            from types import SimpleNamespace
            self.path = args[0]
            self.thread = SimpleNamespace(is_alive=lambda: False)
            self.options = kwargs

        def evidence(self):
            return {'model_id': self.options['model_id'], 'max_tokens': self.options['max_tokens'],
                    'maximum_requests': self.options['max_requests'], 'model_requests': 0,
                    'observed_tokens': 0, 'usage_known': True, 'threshold_overrun': 0,
                    'cleanup_complete': Relay.closed, 'records': [], 'scope': 'unit cleanup failure fixture'}

        def close(self):
            Relay.closed = True

    actions = []

    def podman(*args, **kwargs):
        if args[0] == "run":
            raise OSError("synthetic startup failure")
        if args[0] == "rm":
            raise subprocess.TimeoutExpired("owned removal", 20)
        return subprocess.CompletedProcess(args, 1, "", "")

    monkeypatch.setattr(module.sys, "platform", "linux")
    monkeypatch.setattr(module.os, "geteuid", lambda: 0)
    monkeypatch.setattr(module.os, "chown", lambda *args, **kwargs: None)
    monkeypatch.setattr(module, "_identity", lambda pid: {"pid_namespace": "controller"})
    monkeypatch.setattr(module, "DeveloperBudgetRelay", Relay)
    monkeypatch.setattr(module, "_podman", podman)
    monkeypatch.setattr(module.subprocess, "run", lambda args, **kwargs: actions.append(args))
    key = Ed25519PrivateKey.generate()
    previous=os.umask(mask)
    try:
        result = run_isolated_business_episode(runtime_root=tmp_path / "owned-runtime", config=public_config(),
            services_directory=services, bun=bun, sdk_root=sdk, controller_key=key)
        assert os.umask(mask)==mask
    finally:
        os.umask(previous)
        for listener in sockets:
            listener.close()
        socket_directory.cleanup()
    record = result["isolation"]["record"]
    assert stat.S_IMODE((tmp_path/'owned-runtime/public').stat().st_mode)==0o755
    assert stat.S_IMODE((tmp_path/'owned-runtime').stat().st_mode)==0o700
    assert all(stat.S_IMODE(p.stat().st_mode)==0o644
               for p in (tmp_path/'owned-runtime/public').iterdir() if p.is_file())
    assert record["cleanup_complete"] is False
    assert record["isolation_observed"] is False and record["exit_code"] is None
    assert record["model_requests"] == 0 and record["qualification_eligible"] is False
    assert Relay.closed and any("--remove" in action for action in actions)
    assert any("container cleanup" in error for error in record["cleanup_errors"])
    assert record["assets_unchanged"] is True
    key.public_key().verify(base64.b64decode(result["isolation"]["signature"]), canonical_json(record).encode())
    assert json.loads((tmp_path / "owned-runtime" / "isolation.json").read_text()) == result["isolation"]

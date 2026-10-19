"""Static boundary tests, not product efficacy or established VM custody claims."""
from __future__ import annotations

import base64
import os
import subprocess
import sys
import tempfile
from contextlib import asynccontextmanager
from copy import deepcopy
from pathlib import Path

import anyio
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ci.gauntlet.benchmark import native_builtin_plane as builtin_module
from ci.gauntlet.benchmark import native_mcp_supervisor as front_module
from ci.gauntlet.benchmark import native_product_container as module
from ci.gauntlet.benchmark import native_product_control as control
from ci.gauntlet.benchmark.business_agent_container import _file_identity, freeze_public_tree
from ci.gauntlet.benchmark.contracts import canonical_json
from ci.gauntlet.benchmark.mcp_server import create_server
from ci.gauntlet.benchmark.service_supervisor import ServiceSupervisor
from ci.gauntlet.benchmark.world import World


def boundary():
    controller = {"mount_namespace": "root-mount", "pid_namespace": "root-pid", "network_namespace": "root-net"}
    product = {"mount_namespace": "product-mount", "pid_namespace": "product-pid", "network_namespace": "product-net",
               "effective_uid": 10004, "effective_gid": 10004, "effective_capabilities": "0000000000000000",
               "no_new_privileges": 1}
    return product, controller


@pytest.mark.parametrize('builtin',[False,True])
def test_exact_public_assets_are_readable_under_umask077_before_any_product_process(tmp_path,monkeypatch,builtin):
    """Real staging bytes/modes; stop before namespace/image/native execution."""
    ownership = []
    monkeypatch.setattr(module.os,'chown',lambda path,uid,gid:ownership.append((Path(path),uid,gid)))
    selected = builtin_module if builtin else module
    kind = builtin_module.NativeBuiltinHookPlane if builtin else module.NativeProductContainer
    plane = object.__new__(kind)
    plane.uid=10004
    plane.root,plane.started,plane.probe_only = tmp_path/'product',False,True
    plane.python,plane.upstream_directory = Path('/never-executed/.venv/bin/python'),None
    plane.task_write_policy = None
    def stop(*args):
        raise ValueError('bounded stop before any product execution')
    monkeypatch.setattr(selected,'root_prefix_digest',stop)
    previous = os.umask(0o077)
    try:
        with pytest.raises(ValueError,match='before any product execution'):
            plane.start()
    finally:
        os.umask(previous)
    public = plane.root/'public'
    assert public.stat().st_mode & 0o777 == 0o755
    expected = {'omp.json'} if builtin else {'service_relay.py','mcp.json'}
    assert {path.name for path in public.iterdir()} == expected
    assert all(path.stat().st_mode & 0o777 == 0o644 for path in public.iterdir())
    name = 'omp.json' if builtin else 'mcp.json'
    assert (public/name).read_bytes() == b'{}\n'
    if not builtin:
        origin = Path(module.__file__).with_name('service_relay.py')
        assert (public/'service_relay.py').read_bytes() == origin.read_bytes()
    frozen = freeze_public_tree(public)
    assert frozen['entries'] == len(expected) and frozen['bytes'] > 0
    assert all(_file_identity(path)['mode']==0o644 for path in public.iterdir())
    for path in (plane.root,plane.root/'home',plane.root/'guard',plane.root/'home/project'):
        assert path.stat().st_mode & 0o777 == 0o700
    config = plane.root/'guard/config.toml'
    assert config.stat().st_mode & 0o777 == 0o600
    if not builtin:
        import tomllib
        assert tomllib.loads(config.read_text()) == {
            'mode':'enforce','sync':False,'telemetry':False,
            'desktop_notifications':False,'approval_wait_timeout_seconds':30,
        }
    assert ownership == [(plane.root/'home',10004,10004),(plane.root/'guard',10004,10004),
                         (plane.root/'home/project',10004,10004),(config,10004,10004)]


@pytest.mark.parametrize("field,value", [("effective_uid", 0), ("effective_uid", 10001),
    ("effective_gid", 0), ("effective_capabilities", "0000000000000001"), ("no_new_privileges", 0),
    ("mount_namespace", "root-mount"), ("pid_namespace", "root-pid"), ("network_namespace", "root-net")])
def test_kernel_boundaries_reject_root_agent_privilege_or_shared_namespace(field, value):
    product, controller = boundary()
    module.verify_product_boundary(product, controller)
    product[field] = value
    with pytest.raises(ValueError):
        module.verify_product_boundary(product, controller)


@pytest.mark.parametrize("payload", [b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}'])
def test_product_claims_are_strict_inert_json(payload):
    with pytest.raises(ValueError):
        module._json(payload)


@pytest.mark.parametrize("field", ["source", "build", "package", "runtime", "hash", "available"])
def test_product_self_report_must_match_declared_tuple_but_is_not_authenticated(field):
    claim = {"manifest": {"source_sha": "a" * 40, "package_version": "3.43.1", "runtime_sha256": "x"},
             "capabilities": {"build_sha": "a" * 40, "runtime_version": "3.43.1"},
             "package_version": "3.43.1", "runtime_sha256": "x",
             "available": True, "compatible": True, "installed": True}
    module.validate_identity_claim(claim, source_sha="a" * 40, package_version="3.43.1")
    container, key = {"source": (claim["manifest"], "source_sha"),
        "build": (claim["capabilities"], "build_sha"), "package": (claim, "package_version"),
        "runtime": (claim["capabilities"], "runtime_version"), "hash": (claim, "runtime_sha256"),
        "available": (claim, "available")}[field]
    container[key] = "forged"
    with pytest.raises(ValueError, match="expected build/package"):
        module.validate_identity_claim(claim, source_sha="a" * 40, package_version="3.43.1")


def test_freeze_probe_has_no_service_mount_and_always_closes(monkeypatch, tmp_path):
    seen = {}

    class Probe:
        def __init__(self, **kwargs):
            seen.update(kwargs)

        def start(self):
            raise ValueError("unsupported genuine product")

        def close(self):
            seen["closed"] = True

    monkeypatch.setattr(module, "NativeProductContainer", Probe)
    with pytest.raises(ValueError, match="unsupported"):
        module.namespace_identity_probe(runtime_root=tmp_path, python=Path("/readonly/bin/python"),
                                        expected_source_sha="a" * 40)
    assert "upstream_directory" not in seen
    assert seen["closed"] is True


def test_control_child_uses_official_sdk_without_benchmark_or_product_imports():
    compile(control._CLIENT, "public-official-mcp-client", "exec")
    compile(control._PRIVATE_PATH_CHECK, "namespace-private-path-check", "exec")
    assert "ClientSession" in control._CLIENT
    assert "codex_plugin_scanner" not in control._CLIENT
    assert "ci.gauntlet" not in control._CLIENT
    assert "os.open" in control._PRIVATE_PATH_CHECK


def test_actual_public_control_seed_matches_client_records_and_preserves_clean_data():
    seed, source = control.control_seed()
    client_ids = [control.CLEAN_RECORD, "control-injected"]
    assert all(record_id in control._CLIENT for record_id in client_ids)
    records = {row["id"]: row for row in seed["records"]}
    assert len(records) == len(seed["records"])
    assert source["id"] == "qualification-rubric"
    assert source["collection"] == "docs.documents"
    assert control.CANARY not in canonical_json(source)
    assert records["control-injected"]["data"]["body"].endswith(control.CANARY)
    assert records["control-injected"]["acl"] == source["acl"]


def test_exact_public_client_script_uses_real_advertised_tools_and_real_response_schema(tmp_path, monkeypatch, capsys):
    import mcp.client.stdio
    seed, source = control.control_seed()
    world = World.create(tmp_path / "world.db", seed, signing_key=Ed25519PrivateKey.generate())
    server = create_server(world, "docs")._mcp_server

    @asynccontextmanager
    async def official_transport(params):
        assert params.command == "/usr/bin/python3"
        client_write, server_read = anyio.create_memory_object_stream(0)
        server_write, client_read = anyio.create_memory_object_stream(0)
        async with anyio.create_task_group() as group:
            group.start_soon(server.run, server_read, server_write, server.create_initialization_options())
            try:
                with anyio.fail_after(10):
                    yield client_read, client_write
            finally:
                group.cancel_scope.cancel()

    monkeypatch.setattr(mcp.client.stdio, "stdio_client", official_transport)
    monkeypatch.setattr(sys, "argv", ["public-client", "/public/service_relay.py", "/public/docs.sock"])
    exec(compile(control._CLIENT, "trusted-public-client", "exec"), {})
    responses = module._json(capsys.readouterr().out)
    assert responses[control.CLEAN_RECORD]["isError"] is False
    assert responses[control.CLEAN_RECORD]["structuredContent"]["data"] == source["data"]
    assert control.CANARY in canonical_json(responses["control-injected"])
    assert len(world.receipts()) == 2


def test_startup_failure_is_signed_and_retained_without_overwriting_existing_run(tmp_path, monkeypatch):
    monkeypatch.setattr(control.sys, "platform", "linux")
    monkeypatch.setattr(control.os, "geteuid", lambda: 0)
    root = tmp_path / "fresh"

    def failed_preparation(**kwargs):
        kwargs["root"].mkdir()
        raise StopIteration("missing fixture source")

    monkeypatch.setattr(control, "_run_control", failed_preparation)
    report = control.run_control(root=root, python=Path("/not-executed/bin/python"), source_sha="a" * 40)
    assert report["record"]["control_status"] == "failed-or-unsupported"
    assert report["record"]["exception_type"] == "StopIteration"
    anchor = module._json((root / "public-anchor.json").read_bytes())
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    Ed25519PublicKey.from_public_bytes(base64.b64decode(anchor["controller_key"])).verify(
        base64.b64decode(report["signature"]), canonical_json(report["record"]).encode())
    before = (root / "control-result.json").read_bytes()
    with pytest.raises(ValueError, match="fresh"):
        control.run_control(root=root, python=Path("/not-executed/bin/python"), source_sha="a" * 40)
    assert (root / "control-result.json").read_bytes() == before


def test_primary_frontdoor_startup_failure_keeps_observations_when_audit_also_fails(tmp_path, monkeypatch):
    monkeypatch.setattr(control.sys, "platform", "linux")
    monkeypatch.setattr(control.os, "geteuid", lambda: 0)

    class Upstream:
        active_children = active_workers = active_sessions = 0

        def __init__(self, world, directory, **kwargs):
            self.directory, self.events = directory, [{"kind": "prepared-trusted-upstream"}]

        def start(self):
            pass

        def close(self):
            pass

    class Plane:
        cleanup_complete = True

        def __init__(self, **kwargs):
            self.observations = [{"kind": "pre-start-root-observation"}]

        def declaration(self):
            return {"observations": self.observations, "prefix_unchanged": False, "cleanup_complete": True}

    class Front:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            raise ValueError("original product namespace startup failure")

        def close(self):
            pass

        def collect_audit(self, **kwargs):
            raise ValueError("secondary missing-prefix audit failure")

    monkeypatch.setattr(control, "ServiceSupervisor", Upstream)
    monkeypatch.setattr(control, "NativeProductContainer", Plane)
    monkeypatch.setattr(control, "NativeMcpSupervisor", Front)
    report = control.run_control(root=tmp_path / "fresh", python=Path("/not-executed/bin/python"), source_sha="a" * 40)
    record = report["record"]
    assert record["controller_error"] == "original product namespace startup failure"
    assert record["audit_error"] == "secondary missing-prefix audit failure"
    assert record["upstream_observations"] == [{"kind": "prepared-trusted-upstream"}]
    assert record["product_plane"]["observations"] == [{"kind": "pre-start-root-observation"}]
    assert record["world_receipts"] == [] and record["world_receipt_count"] == 0
    assert record["control_status"] == "failed-or-unsupported"


def test_root_prefix_validator_is_not_relaxed_to_product_uid(tmp_path):
    (tmp_path / "public-product.py").write_text("# inert product source\n")
    (tmp_path / "public-product.py").chmod(0o666)
    with pytest.raises(ValueError, match="root-owned"):
        module.root_prefix_digest(tmp_path)


def test_nonlinux_product_plane_cannot_execute_or_stage_candidate(tmp_path, monkeypatch):
    monkeypatch.setattr(module.sys, "platform", "darwin")
    with pytest.raises(ValueError, match="Linux root"):
        module.NativeProductContainer(runtime_root=tmp_path / "runtime", python=Path("/usr/bin/python"),
            expected_source_sha="a" * 40, upstream_directory=tmp_path / "upstream")
    assert not (tmp_path / "runtime").exists()


def test_bounded_capture_kills_host_exec_client_on_oversized_output(monkeypatch):
    plane = module.NativeProductContainer.__new__(module.NativeProductContainer)
    plane.name = "owned-test-process"
    plane.cleanup_errors, plane.started = [], True
    removed = []
    monkeypatch.setattr(module, "_podman", lambda *args, **kwargs: removed.append(args))
    original = subprocess.Popen
    started = []

    def test_exec(command, **kwargs):
        # Benign test output generator; no candidate product code executes on host.
        process = original([sys.executable, "-c", "print('x' * 8192)"], **kwargs)
        started.append((command, process))
        return process

    monkeypatch.setattr(module.subprocess, "Popen", test_exec)
    with pytest.raises(ValueError, match="byte budget"):
        plane._capture(["/readonly/prefix/bin/python", "-I", "-c", "inert fixture"], limit=1024)
    assert started[0][0][:4] == ["/usr/bin/podman", "exec", plane.name, "/readonly/prefix/bin/python"]
    assert started[0][1].poll() is not None
    assert removed == [("rm", "--force", "--time=0", plane.name)]
    assert plane.started is False


def test_optional_frontdoor_never_imports_or_probes_candidate_on_controller(monkeypatch):
    class Plane:
        uid=10004
        source_sha = "a" * 40
        python = Path("/usr/bin/python")
        cleanup_complete = True

        def __init__(self, root, upstream):
            self.root, self.upstream_directory = root, upstream
            self.started = False
            self.identity_claim = {"manifest": {"source_sha": "untrusted-self-report"}}
            self.product_events = [{"claimed_decision": "allow"}]

        def start(self, upstream):
            self.started = True

        def close(self):
            self.started = False

        def declaration(self):
            return {"cleanup_complete": True, "prefix_unchanged": True, "uid": 10004,
                    "product_claims_authenticated": False, "product_identity_claim": self.identity_claim}

    def forbidden(*args, **kwargs):
        raise AssertionError("candidate product import/probe escaped product namespace")

    with tempfile.TemporaryDirectory(prefix="product-front-", dir="/tmp") as directory:
        root = Path(directory).resolve()
        monkeypatch.setattr(module, "NativeProductContainer", Plane)
        monkeypatch.setattr(front_module.sys, "platform", "linux")
        monkeypatch.setattr(front_module.os, "geteuid", lambda: 0)
        monkeypatch.setattr(front_module, "require_root_private", lambda *args, **kwargs: None)
        monkeypatch.setattr(front_module, "inspect_installed_guard", forbidden)
        monkeypatch.setattr(front_module, "guard_endpoints", forbidden)
        with ServiceSupervisor(None, root / "upstream", allowed_uid=10004, families=("docs",)) as upstream:
            upstream.socket_gid = 10004  # Planning mock; no privileged host ownership mutation.
            plane = Plane(root / "product", upstream.directory)
            front = front_module.NativeMcpSupervisor(root / "public", upstream=upstream,
                python=plane.python, expected_source_sha=plane.source_sha, private_root=root / "controller",
                allowed_uid=os.getuid(), socket_gid=None, product_plane=plane)
            front.start()
            assert plane.started
            endpoint = front.endpoint("docs")
            assert str(plane.root) not in str(endpoint.command)
            assert str(upstream.directory) not in str(endpoint.command)
            assert not front.guard_home.exists()  # Root lane is not silently used.
            front.close()
            key = Ed25519PrivateKey.generate()
            evidence = front.collect_audit(controller_key=key)
            key.public_key().verify(base64.b64decode(evidence["signature"]),
                                    canonical_json(evidence["record"]).encode())
            assert evidence["record"]["product_claims_authenticated"] is False
            assert evidence["record"]["product_events_self_reported"] == plane.product_events
            assert evidence["record"]["qualification_eligible"] is False
            changed = deepcopy(evidence["record"])
            changed["product_claims_authenticated"] = True
            assert canonical_json(changed) != canonical_json(evidence["record"])

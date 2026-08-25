from __future__ import annotations

import importlib.util
import sys
import threading
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).parents[1]
LAB = ROOT / "scripts" / "mdm" / "cloud-lab"
sys.path.insert(0, str(LAB))

from device_runtime import Device, DeviceServer  # noqa: E402
from lab_common import CloudServer, Store  # noqa: E402
from orchestrator import orchestrate  # noqa: E402


def _proxy_module() -> ModuleType:
    specification = importlib.util.spec_from_file_location(
        "mdm_fault_proxy",
        LAB / "fault_proxy.py",
    )
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _serve(server):
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _seeds() -> list[dict[str, str]]:
    return [
        {
            "workspaceId": "workspace-mdm-alpha",
            "deviceId": "device-a",
            "installationGeneration": "a" * 32,
            "token": "enrollment-token-device-a",
        },
        {
            "workspaceId": "workspace-mdm-alpha",
            "deviceId": "device-b",
            "installationGeneration": "b" * 32,
            "token": "enrollment-token-device-b",
        },
        {
            "workspaceId": "workspace-mdm-alpha",
            "deviceId": "device-c",
            "installationGeneration": "c" * 32,
            "token": "enrollment-token-device-c",
        },
        {
            "workspaceId": "workspace-mdm-beta",
            "deviceId": "device-d",
            "installationGeneration": "d" * 32,
            "token": "enrollment-token-device-d",
        },
        {
            "workspaceId": "workspace-mdm-alpha",
            "deviceId": "device-clone-probe",
            "installationGeneration": "e" * 32,
            "token": "enrollment-token-clone-probe",
        },
    ]


def _start_stack(tmp_path: Path):
    proxy_module = _proxy_module()
    cloud = _serve(
        CloudServer(
            ("127.0.0.1", 0),
            Store(tmp_path / "cloud.sqlite3", tmp_path / "cloud-key.pem", _seeds()),
            "admin",
        )
    )
    cloud_url = f"http://127.0.0.1:{cloud.server_port}"
    gateway = _serve(
        proxy_module.FaultProxyServer(
            ("127.0.0.1", 0),
            upstream=cloud_url,
            state=proxy_module.FaultState("admin"),
            verbose=False,
        )
    )
    proxy_url = f"http://127.0.0.1:{gateway.server_port}"
    servers = [cloud, gateway]
    urls: dict[str, str] = {}
    definitions = (
        ("device-a", "workspace-mdm-alpha", "a" * 32, "enrollment-token-device-a"),
        ("device-b", "workspace-mdm-alpha", "b" * 32, "enrollment-token-device-b"),
        ("device-c", "workspace-mdm-alpha", "c" * 32, "enrollment-token-device-c"),
        ("device-d", "workspace-mdm-beta", "d" * 32, "enrollment-token-device-d"),
    )
    for name, workspace, generation, token in definitions:
        root = tmp_path / name
        device = Device(
            root,
            proxy_url,
            workspace,
            name,
            generation,
            token,
            root / "managed-policy.json",
        )
        server = _serve(DeviceServer(("127.0.0.1", 0), device))
        servers.append(server)
        urls[name] = f"http://127.0.0.1:{server.server_port}"
    return servers, cloud_url, proxy_url, urls


def _stop(servers) -> None:
    for server in reversed(servers):
        server.shutdown()
        server.server_close()


def test_real_http_multi_device_cloud_control_loop_survives_process_restart(
    tmp_path: Path,
) -> None:
    initial_report = tmp_path / "initial.json"
    servers, cloud_url, proxy_url, urls = _start_stack(tmp_path)
    try:
        initial = orchestrate(
            cloud_url,
            proxy_url,
            urls,
            "admin",
            initial_report,
            phase="initial",
        )
        assert initial["healthy"] is True
        assert initial["stepCount"] >= 45
        assert all(step["passed"] is True for step in initial["steps"])
    finally:
        _stop(servers)

    servers, cloud_url, proxy_url, urls = _start_stack(tmp_path)
    try:
        report_path = tmp_path / "report.json"
        final = orchestrate(
            cloud_url,
            proxy_url,
            urls,
            "admin",
            report_path,
            phase="restart",
            input_report=initial_report,
        )
        assert final["healthy"] is True
        assert final["stepCount"] >= 50
        assert all(step["passed"] is True for step in final["steps"])
        assert final["nativeCertification"]["outcome"] == "not-evaluated"
        assert report_path.exists()
    finally:
        _stop(servers)

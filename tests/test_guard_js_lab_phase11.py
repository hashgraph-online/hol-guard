"""Phase 11 offline JavaScript lab proof using a fake npm registry."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import shlex
import shutil
import subprocess
import tarfile
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

import pytest

from codex_plugin_scanner.guard.runtime.package_intent import build_package_request_artifact, parse_package_intent
from codex_plugin_scanner.guard.runtime.supply_chain_package_eval import evaluate_package_request_artifact
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_js_supply_chain_phase11 import WORKSPACE_ID, _bundle_response, _package, _write_text


@dataclass(frozen=True, slots=True)
class _RegistryPackageSpec:
    name: str
    version: str
    scripts: dict[str, str] | None = None
    deprecated: bool = False
    yanked: bool = False


class _FakeNpmRegistry:
    def __init__(self, packages: tuple[_RegistryPackageSpec, ...]) -> None:
        self._packages = {package.name: package for package in packages}
        self._tarballs = {
            package.name: (
                f"/{package.name}/-/{package.name}-{package.version}.tgz",
                _package_tarball_bytes(package),
            )
            for package in packages
        }
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _RegistryHandler)
        self._server.registry = self  # type: ignore[attr-defined]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self._server.server_port}"

    def metadata(self, package_name: str) -> dict[str, object] | None:
        package = self._packages.get(package_name)
        if package is None:
            return None
        tarball_path, tarball_bytes = self._tarballs[package.name]
        integrity = "sha512-" + base64.b64encode(hashlib.sha512(tarball_bytes).digest()).decode("utf-8")
        version_metadata: dict[str, object] = {
            "name": package.name,
            "version": package.version,
            "dist": {"tarball": f"{self.url}{tarball_path}", "integrity": integrity},
        }
        if package.deprecated:
            version_metadata["deprecated"] = "deprecated by fixture"
        package_metadata: dict[str, object] = {
            "name": package.name,
            "dist-tags": {"latest": package.version},
            "versions": {package.version: version_metadata},
        }
        if package.yanked:
            package_metadata["time"] = {
                "unpublished": {
                    "name": "hol-guard-fixture",
                    "time": "2026-05-19T00:00:00.000Z",
                }
            }
        return {
            **package_metadata,
        }

    def tarball(self, request_path: str) -> bytes | None:
        for tarball_path, tarball_bytes in self._tarballs.values():
            if request_path == tarball_path:
                return tarball_bytes
        return None

    def __enter__(self) -> _FakeNpmRegistry:
        self._thread.start()
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self._server.shutdown()
        self._thread.join(timeout=5)
        self._server.server_close()


class _RegistryHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        registry = self.server.registry  # type: ignore[attr-defined]
        request_path = unquote(urlparse(self.path).path)
        package_name = request_path.lstrip("/")
        metadata = registry.metadata(package_name)
        if metadata is not None:
            body = json.dumps(metadata).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        tarball = registry.tarball(request_path)
        if tarball is not None:
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(tarball)))
            self.end_headers()
            self.wfile.write(tarball)
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, message_format: str, *args: object) -> None:
        return None


def _package_tarball_bytes(package: _RegistryPackageSpec) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        package_json = {
            "name": package.name,
            "version": package.version,
            "main": "index.js",
        }
        if package.scripts is not None:
            package_json["scripts"] = package.scripts
        package_payload = json.dumps(package_json).encode("utf-8")
        package_info = tarfile.TarInfo("package/package.json")
        package_info.size = len(package_payload)
        archive.addfile(package_info, io.BytesIO(package_payload))
        index_payload = b"module.exports = 'lab';\n"
        index_info = tarfile.TarInfo("package/index.js")
        index_info.size = len(index_payload)
        archive.addfile(index_info, io.BytesIO(index_payload))
    return buffer.getvalue()


def _install_command(package_name: str, registry_url: str) -> list[str]:
    return [
        "npm",
        "install",
        "--ignore-scripts",
        "--no-audit",
        "--fund=false",
        f"--registry={registry_url}",
        f"{package_name}@1.0.0",
    ]


def _run_offline_registry_install(workspace_dir: Path, package_name: str, registry_url: str) -> str:
    workspace_dir.mkdir(parents=True, exist_ok=True)
    _write_text(workspace_dir / "package.json", '{"name":"guard-js-lab","private":true}\n')
    command = _install_command(package_name, registry_url)
    completed = subprocess.run(
        command,
        cwd=workspace_dir,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert completed.returncode == 0, completed.stderr
    return shlex.join(command)


def _evaluate_offline_registry_install(
    *,
    store: GuardStore,
    workspace_dir: Path,
    package_name: str,
    registry_url: str,
) -> object:
    command = _run_offline_registry_install(workspace_dir, package_name, registry_url)
    intent = parse_package_intent(command, workspace=workspace_dir)
    assert intent is not None
    artifact = build_package_request_artifact("codex", intent, config_path="codex.json", source_scope="project")
    return evaluate_package_request_artifact(artifact=artifact, store=store, workspace_dir=workspace_dir)


@pytest.mark.skipif(shutil.which("npm") is None, reason="npm required for offline JS lab proof")
def test_guard_js_offline_fake_registry_lab_covers_safe_vulnerable_malware_yanked_and_typo_packages(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    store = GuardStore(home_dir)
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: WORKSPACE_ID)
    store.cache_supply_chain_bundle(
        WORKSPACE_ID,
        _bundle_response(
            packages=[
                _package(
                    name="vulnerable-demo",
                    version="1.0.0",
                    default_action="block",
                    recommended_fix_version="1.0.1",
                ),
                _package(
                    name="malware-demo",
                    version="1.0.0",
                    default_action="block",
                    recommended_fix_version="1.0.1",
                ),
                _package(
                    name="minimlts",
                    version="1.0.0",
                    default_action="block",
                    recommended_fix_version="1.0.1",
                ),
            ]
        ),
        "2026-05-19T00:00:00Z",
    )
    packages = (
        _RegistryPackageSpec(name="safe-demo", version="1.0.0"),
        _RegistryPackageSpec(name="vulnerable-demo", version="1.0.0"),
        _RegistryPackageSpec(
            name="malware-demo",
            version="1.0.0",
            scripts={
                "postinstall": (
                    "node -e \"require('fs').writeFileSync("
                    "require('path').join(process.env.INIT_CWD || process.cwd(), 'malware-marker.txt'),'x')\""
                )
            },
        ),
        _RegistryPackageSpec(
            name="install-script-demo",
            version="1.0.0",
            scripts={
                "postinstall": (
                    "node -e \"require('fs').writeFileSync("
                    "require('path').join(process.env.INIT_CWD || process.cwd(), 'install-script-marker.txt'),'x')\""
                )
            },
        ),
        _RegistryPackageSpec(name="yanked-demo", version="1.0.0", deprecated=True, yanked=True),
        _RegistryPackageSpec(name="minimlts", version="1.0.0"),
    )

    with _FakeNpmRegistry(packages) as registry:
        safe_result = _evaluate_offline_registry_install(
            store=store,
            workspace_dir=tmp_path / "safe-workspace",
            package_name="safe-demo",
            registry_url=registry.url,
        )
        vulnerable_result = _evaluate_offline_registry_install(
            store=store,
            workspace_dir=tmp_path / "vulnerable-workspace",
            package_name="vulnerable-demo",
            registry_url=registry.url,
        )
        malware_workspace = tmp_path / "malware-workspace"
        malware_result = _evaluate_offline_registry_install(
            store=store,
            workspace_dir=malware_workspace,
            package_name="malware-demo",
            registry_url=registry.url,
        )
        install_script_workspace = tmp_path / "install-script-workspace"
        install_script_result = _evaluate_offline_registry_install(
            store=store,
            workspace_dir=install_script_workspace,
            package_name="install-script-demo",
            registry_url=registry.url,
        )
        yanked_result = _evaluate_offline_registry_install(
            store=store,
            workspace_dir=tmp_path / "yanked-workspace",
            package_name="yanked-demo",
            registry_url=registry.url,
        )
        typo_result = _evaluate_offline_registry_install(
            store=store,
            workspace_dir=tmp_path / "typo-workspace",
            package_name="minimlts",
            registry_url=registry.url,
        )

    assert safe_result.decision == "monitor"
    assert vulnerable_result.decision == "block"
    assert vulnerable_result.packages[0]["name"] == "vulnerable-demo"
    assert malware_result.decision == "block"
    assert malware_result.packages[0]["name"] == "malware-demo"
    assert install_script_result.decision == "monitor"
    assert yanked_result.decision == "monitor"
    assert typo_result.decision == "block"
    assert typo_result.packages[0]["name"] == "minimlts"
    assert not (malware_workspace / "malware-marker.txt").exists()
    assert not (install_script_workspace / "install-script-marker.txt").exists()

"""Phase 12 Python simple-index lab proof."""

from __future__ import annotations

import base64
import functools
import hashlib
import subprocess
import sys
import threading
import zipfile
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.supply_chain_package_eval import evaluate_package_request_artifact
from codex_plugin_scanner.guard.store import GuardStore

from .guard_python_phase12_support import (
    WORKSPACE_ID,
    artifact_from_command_fixture,
    bundle_response_fixture,
    package_fixture,
    write_text,
)


def _build_wheel(build_root: Path, version: str, dist_dir: Path) -> Path:
    del build_root
    dist_dir.mkdir(parents=True, exist_ok=True)
    wheel_path = dist_dir / f"labdemo-{version}-py3-none-any.whl"
    dist_info_dir = f"labdemo-{version}.dist-info"
    package_files = {
        "labdemo/__init__.py": f'__version__ = "{version}"\n'.encode(),
        f"{dist_info_dir}/WHEEL": (
            b"Wheel-Version: 1.0\n"
            b"Generator: hol-guard-test\n"
            b"Root-Is-Purelib: true\n"
            b"Tag: py3-none-any\n"
        ),
        f"{dist_info_dir}/METADATA": (
            "Metadata-Version: 2.1\n"
            "Name: labdemo\n"
            f"Version: {version}\n"
            "Summary: HOL Guard local lab package\n"
        ).encode(),
    }
    record_lines: list[str] = []
    with zipfile.ZipFile(wheel_path, "w", compression=zipfile.ZIP_DEFLATED) as wheel_zip:
        for relative_path, content in package_files.items():
            wheel_zip.writestr(relative_path, content)
            digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).decode("ascii").rstrip("=")
            record_lines.append(f"{relative_path},sha256={digest},{len(content)}")
        record_lines.append(f"{dist_info_dir}/RECORD,,")
        wheel_zip.writestr(f"{dist_info_dir}/RECORD", "\n".join(record_lines) + "\n")
    return wheel_path


def _write_simple_index(index_root: Path, wheel_paths: list[Path]) -> None:
    package_links = "\n".join(
        f'<a href="../../packages/{wheel_path.name}">{wheel_path.name}</a><br/>'
        for wheel_path in sorted(wheel_paths)
    )
    write_text(index_root / "simple" / "index.html", '<a href="labdemo/">labdemo</a>\n')
    write_text(index_root / "simple" / "labdemo" / "index.html", package_links + "\n")


class _SilentSimpleIndexHandler(SimpleHTTPRequestHandler):
    def log_message(self, message_format: str, *args: object) -> None:
        del message_format, args


@contextmanager
def _serve_directory(root: Path) -> Iterator[str]:
    handler = functools.partial(_SilentSimpleIndexHandler, directory=str(root))
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_python_simple_index_lab_blocks_vulnerable_version_and_serves_safe_wheel(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    index_root = tmp_path / "simple-index"
    dist_dir = index_root / "packages"
    dist_dir.mkdir(parents=True)
    vulnerable_wheel = _build_wheel(tmp_path / "build", "1.0.0", dist_dir)
    safe_wheel = _build_wheel(tmp_path / "build", "1.0.1", dist_dir)
    _write_simple_index(index_root, [vulnerable_wheel, safe_wheel])

    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    store = GuardStore(home_dir)
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: WORKSPACE_ID)
    store.cache_supply_chain_bundle(
        WORKSPACE_ID,
        bundle_response_fixture(
            packages=[
                package_fixture(
                    name="labdemo",
                    version="1.0.0",
                    default_action="block",
                    recommended_fix_version="1.0.1",
                )
            ]
        ),
        "2026-05-19T00:00:00Z",
    )

    with _serve_directory(index_root) as base_url:
        blocked_artifact = artifact_from_command_fixture(
            f"pip install --trusted-host 127.0.0.1 --index-url {base_url}/simple labdemo==1.0.0",
            workspace=workspace_dir,
        )
        blocked_result = evaluate_package_request_artifact(
            artifact=blocked_artifact,
            store=store,
            workspace_dir=workspace_dir,
        )

        assert blocked_result.decision == "block"
        assert blocked_result.user_copy.next_step == "pip install labdemo==1.0.1"

        safe_artifact = artifact_from_command_fixture(
            f"pip install --trusted-host 127.0.0.1 --index-url {base_url}/simple labdemo==1.0.1",
            workspace=workspace_dir,
        )
        safe_result = evaluate_package_request_artifact(
            artifact=safe_artifact,
            store=store,
            workspace_dir=workspace_dir,
        )

        assert safe_result.decision == "allow"

        download_dir = tmp_path / "downloads"
        download_dir.mkdir()
        subprocess.run(
            [
                sys.executable,
                "-m",
                "pip",
                "download",
                "--no-deps",
                "--disable-pip-version-check",
                "--index-url",
                f"{base_url}/simple",
                "--trusted-host",
                "127.0.0.1",
                "labdemo==1.0.1",
                "-d",
                str(download_dir),
            ],
            capture_output=True,
            check=True,
            text=True,
        )

    assert (download_dir / safe_wheel.name).exists()

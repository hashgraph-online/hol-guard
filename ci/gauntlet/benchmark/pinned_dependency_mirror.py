"""Exact public Zod fixture, bounded inert extraction and a local-only registry.

The official bytes are provenance inputs, never a downloaded installer. No npm,
package scripts, or candidate code run in this controller. Bind the HTTP server
inside the isolated fixture network; no provider/account credentials are used.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import tarfile
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath

from .contracts import canonical_json
from .developer_oracles import source_tree_digest

ZOD_VERSION = "3.23.8"
ZOD_TARBALL = "https://registry.npmjs.org/zod/-/zod-3.23.8.tgz"
ZOD_INTEGRITY = "sha512-XBx9AXhXktjUqnepgTiE5flcKIYWi/rme0Eaj+5Y0lftuGBq+jyRu/md4WnuxqgP1ubdpNCsYEYPxrzVHD8d6g=="
ZOD_SHASUM = "e37b957b5d52079769fb8097099b592f0ef4067d"
MAX_ARCHIVE = 4 * 1024 * 1024
MAX_UNPACKED = 32 * 1024 * 1024


class _BoundedRegistry(ThreadingHTTPServer):
    daemon_threads = False

    def __init__(self, *args):
        self._slots = threading.BoundedSemaphore(8)
        super().__init__(*args)

    def process_request(self, request, address):
        request.settimeout(5)
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self._slots.release()


class PinnedZodMirror:
    def __init__(self, root: Path, metadata: dict, tarball: bytes):
        if root.exists() or root.is_symlink():
            raise ValueError("package mirror root must be a new owned directory")
        dist = metadata.get("dist", {})
        if (
            metadata.get("name") != "zod"
            or metadata.get("version") != ZOD_VERSION
            or dist.get("integrity") != ZOD_INTEGRITY
            or dist.get("tarball") != ZOD_TARBALL
            or dist.get("shasum") != ZOD_SHASUM
        ):
            raise ValueError("package mirror must bind exact official zod3.23.8 metadata")
        if len(tarball) > MAX_ARCHIVE:
            raise ValueError("pinned tarball exceeds compressed budget")
        observed = "sha512-" + base64.b64encode(hashlib.sha512(tarball).digest()).decode()
        if observed != ZOD_INTEGRITY or hashlib.sha1(tarball).hexdigest() != ZOD_SHASUM:
            raise ValueError("pinned package integrity mismatch")
        self.root, self.metadata, self.tarball = root.resolve(), json.loads(canonical_json(metadata)), bytes(tarball)
        with gzip.GzipFile(fileobj=io.BytesIO(tarball)) as compressed:
            raw = compressed.read(MAX_UNPACKED + 1)
        if len(raw) > MAX_UNPACKED:
            raise ValueError("archive exceeds expanded byte budget")
        files = {}
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
            for member in archive:
                parts = PurePosixPath(member.name).parts
                if (
                    len(files) >= 4096
                    or not parts
                    or parts[0] != "package"
                    or ".." in parts
                    or PurePosixPath(member.name).is_absolute()
                ):
                    raise ValueError("unsafe or unbounded package archive path")
                if member.isdir():
                    continue
                if not member.isfile() or member.size > MAX_UNPACKED or member.name in files:
                    raise ValueError("archive links/special files/duplicates are forbidden")
                files[member.name] = archive.extractfile(member).read(member.size + 1)
        self.root.mkdir()
        for name, value in files.items():
            path = self.root.joinpath(*PurePosixPath(name).parts)
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("xb") as handle:
                handle.write(value)
        self.installed_digest = source_tree_digest(self.root / "package")
        self._server = None
        self._thread = None
        self.requests = []
        self.observer = None
        self._lock = threading.Lock()
        self._responses = threading.Condition()
        self.completed_responses = []
        self.response_errors = []

    @classmethod
    def fetch(cls, root: Path) -> PinnedZodMirror:
        """Explicit bounded fetch of the exact two public official registry URLs."""
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

        def read(url, maximum):
            with opener.open(url, timeout=20) as response:
                if response.url != url:
                    raise ValueError("registry redirect changes pinned source")
                value = response.read(maximum + 1)
                if len(value) > maximum:
                    raise ValueError("official registry artifact exceeds budget")
                return value

        metadata = json.loads(read("https://registry.npmjs.org/zod/" + ZOD_VERSION, 2 * 1024 * 1024))
        return cls(root, metadata, read(ZOD_TARBALL, MAX_ARCHIVE))

    def start(self, *, host="127.0.0.1", port=0):
        if self._server is not None or host != "127.0.0.1":
            raise ValueError("mirror must start once on a local fixture interface")
        mirror = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if len(self.path) > 512:
                    self.send_error(414)
                    return
                with mirror._lock:
                    if len(mirror.requests) >= 10000:
                        self.send_error(429)
                        return
                    mirror.requests.append({"method": "GET", "path": self.path})
                if self.path == "/zod/-/zod-" + ZOD_VERSION + ".tgz":
                    raw, content_type = mirror.tarball, "application/octet-stream"
                elif self.path in {"/zod", "/zod/" + ZOD_VERSION}:
                    package = json.loads(canonical_json(mirror.metadata))
                    package["dist"]["tarball"] = mirror.url + "/zod/-/zod-" + ZOD_VERSION + ".tgz"
                    data = (
                        package
                        if self.path.endswith(ZOD_VERSION)
                        else {"name": "zod", "dist-tags": {"latest": ZOD_VERSION}, "versions": {ZOD_VERSION: package}}
                    )
                    raw, content_type = canonical_json(data).encode(), "application/json"
                else:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
                self.wfile.flush()
                event = {
                    "operation": "package-http-response",
                    "path": self.path,
                    "bytes": len(raw),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "status": 200,
                    "fidelity": "local-synthetic-registry",
                    "delivery_stage": "socket-write-complete",
                }
                try:
                    if mirror.observer is not None:
                        mirror.observer(event)
                except BaseException as error:
                    with mirror._responses:
                        mirror.response_errors.append(type(error).__name__)
                        mirror._responses.notify_all()
                    raise
                with mirror._responses:
                    mirror.completed_responses.append(event)
                    mirror._responses.notify_all()

            def log_message(self, *_args):
                pass

        self._server = _BoundedRegistry((host, port), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    @property
    def url(self):
        if self._server is None:
            raise ValueError("mirror is not serving")
        return f"http://127.0.0.1:{self._server.server_port}"

    def baseline(self):
        return {
            "name": "zod",
            "version": ZOD_VERSION,
            "integrity": ZOD_INTEGRITY,
            "resolved": self.url + "/zod/-/zod-" + ZOD_VERSION + ".tgz",
            "official_tarball": ZOD_TARBALL,
            "official_shasum": ZOD_SHASUM,
            "installed_digest": self.installed_digest,
            "fidelity": "local-synthetic-registry",
        }

    def wait_for_responses(self, count: int, *, timeout: float = 5):
        """Wait for actual socket writes and durable observer callbacks, no sleeps.

        A socket write alone does not prove client consumption; installed-artifact
        custody is checked separately. This barrier never creates a receipt.
        """
        if type(count) is not int or not 0 <= count <= 10000 or not 0 < timeout <= 30:
            raise ValueError('response wait requires bounded count and deadline')
        with self._responses:
            completed = self._responses.wait_for(
                lambda: len(self.completed_responses) >= count or bool(self.response_errors), timeout)
            if self.response_errors:
                raise ValueError('package response observer failed before custody completed')
            if not completed:
                raise TimeoutError('actual package responses did not complete within deadline')
            return [dict(event) for event in self.completed_responses]

    def close(self):
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._thread.join(timeout=3)
            self._server = None

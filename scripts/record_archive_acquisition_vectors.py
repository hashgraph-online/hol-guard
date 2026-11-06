#!/usr/bin/env python3
"""Record archive-acquisition behavior from the pre-cutover Python revision.

Load the pinned historical Git objects, never the current implementation.
The fixture contains synthetic destinations and payloads only.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import io
import ipaddress
import json
import socket
import subprocess
import sys
import tempfile
from pathlib import Path
from types import ModuleType
from unittest.mock import patch

destination: ModuleType
downloader: ModuleType
RestrictedArchiveFailure: type


def load_baseline(root: Path, commit: str) -> tuple[str, dict[str, bytes]]:
    """Execute old Git objects in an isolated module package for recording.

    No retired implementation is stored on disk or imported from production.
    The managed TLS service is unreachable because downloads use a fake peer.
    """
    global destination, downloader, RestrictedArchiveFailure
    revision = subprocess.check_output(
        ["git", "rev-parse", "--verify", f"{commit}^{{commit}}"], cwd=root, text=True
    ).strip()
    prefix = "archive_vector_baseline.guard"
    for name in ("archive_vector_baseline", prefix, prefix + ".runtime", prefix + ".mdm"):
        package = ModuleType(name)
        package.__path__ = []
        sys.modules[name] = package
    network = ModuleType(prefix + ".mdm.network")

    def forbidden_tls() -> None:
        raise AssertionError("recording must never open a real network connection")

    network.managed_ssl_context = forbidden_tls
    sys.modules[network.__name__] = network
    sources = {}
    for suffix in ("contract", "deadline", "destination", "stream", "download"):
        basename = "restricted_archive_" + suffix
        path = "src/codex_plugin_scanner/guard/runtime/" + basename + ".py"
        source = subprocess.check_output(["git", "show", f"{revision}:{path}"], cwd=root)
        sources[path] = source
        name = prefix + ".runtime." + basename
        module = ModuleType(name)
        module.__package__ = prefix + ".runtime"
        sys.modules[name] = module
        exec(compile(source, path, "exec"), module.__dict__)
    destination = sys.modules[prefix + ".runtime.restricted_archive_destination"]
    downloader = sys.modules[prefix + ".runtime.restricted_archive_download"]
    RestrictedArchiveFailure = sys.modules[prefix + ".runtime.restricted_archive_contract"].RestrictedArchiveFailure
    return revision, sources


URLS = [
    "",
    "https://packages.example.com/archive.tgz",
    "HTTPS://PACKAGES.EXAMPLE.COM.:443",
    "https://packages.example.com:8443/a/../b?x=%2F&y=1",
    "https://packages.example.com/é.tgz",
    "https://packages.example.com/a%20b?x=é",
    "https://packages.example.com/a#fragment",
    "https://packages.example.com/a#",
    "https://packages.example.com/a?",
    "https://packages.example.com:0/a",
    "https://packages.example.com:/a",
    "https://packages.example.com:+443/a",
    "https://packages.example.com:65536/a",
    "https://packages.example.com:abc/a",
    "https://user@packages.example.com/a",
    "https://user:secret@packages.example.com/a",
    "https://@packages.example.com/a",
    " https://packages.example.com/a",
    "https://packages.example.com/a ",
    "https://packages.example.com/a\n",
    "https://packages.example.com/a\x7f",
    "https://packages.example.com/a\\b",
    "https:\\packages.example.com/a",
    "https:/packages.example.com/a",
    "https:packages.example.com/a",
    "https:///packages.example.com/a",
    "http://packages.example.com/a",
    "ftp://packages.example.com/a",
    "https://é.example.com/a",
    "https://packages.example.com/a%",
    "https://packages.example.com/a%2",
    "https://packages.example.com/a%zz",
    "https://packages.example.com/?x=%xy",
    "https://-bad.example.com/a",
    "https://bad-.example.com/a",
    "https://bad_name.example.com/a",
    "https://bad..example.com/a",
    "https://" + "a" * 64 + ".example.com/a",
    "https://" + ".".join(["a" * 63] * 4) + "/a",
    "https://127.0.0.1/a",
    "https://8.8.8.8/a",
    "https://[::1]/a",
    "https://[2001:4860:4860::8888]:8443/a",
    "https://[fe80::1%25en0]/a",
    "https://[not-an-ip]/a",
    "https://registry.npmjs.org/a",
    "https://REGISTRY.NPMJS.ORG./a",
    "https://registry.npmjs.org@evil.example/a",
]

ADDRESSES = [
    "0.0.0.0",
    "0.1.2.3",
    "8.8.8.8",
    "10.0.0.1",
    "100.64.0.1",
    "100.100.100.200",
    "127.0.0.1",
    "169.254.169.254",
    "172.16.0.1",
    "192.0.0.8",
    "192.0.0.9",
    "192.0.0.10",
    "192.0.0.11",
    "192.0.2.1",
    "192.168.0.1",
    "198.18.0.1",
    "198.51.100.1",
    "203.0.113.1",
    "224.0.0.1",
    "240.0.0.1",
    "255.255.255.255",
    "::",
    "::1",
    "::ffff:8.8.8.8",
    "::ffff:127.0.0.1",
    "2001:db8::1",
    "2001:4860:4860::8888",
    "2002:0808:0808::1",
    "2002:7f00:0001::1",
    "2001:0000:4136:e378:8000:63bf:3fff:fdd2",
    "fc00::1",
    "fe80::1",
    "ff02::1",
]


class Response:
    def __init__(self, status: int, body: bytes = b"", headers: dict[str, str] | None = None) -> None:
        self.status = status
        self.body = io.BytesIO(body)
        self.headers = headers or {}

    def read(self, amount: int = -1) -> bytes:
        return self.body.read(amount)

    def get_header(self, name: str) -> str | None:
        return next((v for k, v in self.headers.items() if k.lower() == name.lower()), None)

    def header_items(self) -> tuple[tuple[str, str], ...]:
        return tuple(self.headers.items())

    def set_timeout(self, timeout: float) -> None:
        pass

    def close(self) -> None:
        pass


def download_vector(case: dict[str, object]) -> dict[str, object]:
    responses = iter(Response(**item) for item in case["responses"])
    opened: list[str] = []

    def open_response(target: object, addresses: object, *, deadline: float) -> Response:
        opened.append(target.url)
        return next(responses)

    def resolve(*args: object, **kwargs: object) -> list[tuple[object, ...]]:
        return [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, 443))
            for ip in case.get("addresses", ["8.8.8.8"])
        ]

    with (
        tempfile.TemporaryDirectory() as scratch,
        patch.object(downloader, "_open_destination", open_response),
        patch.object(socket, "getaddrinfo", resolve),
    ):
        result = downloader.download_restricted_archive(
            case.get("url", "https://packages.example.com/dir/archive.tgz"),
            max_bytes=case.get("max_bytes", 16),
            max_redirects=case.get("max_redirects", 4),
            timeout_seconds=1.0,
            temp_dir=Path(scratch),
        )
        if isinstance(result, RestrictedArchiveFailure):
            outcome = {"kind": "failure", **dataclasses.asdict(result)}
        else:
            outcome = {
                "kind": "download",
                "sha256": result.sha256,
                "size": result.size,
                "final_url": result.final_url,
                "suffix": "".join(result.path.suffixes),
                "mode": result.path.stat().st_mode & 0o777,
            }
            result.cleanup()
        assert not list(Path(scratch).iterdir()), "download leaked a temporary file"
    return {"name": case["name"], "input": case, "opened": opened, "expected": outcome}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-commit", required=True, help="pinned pre-cutover revision")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    revision, sources = load_baseline(root, args.base_commit)
    urls = []
    for url in URLS:
        try:
            expected = dataclasses.asdict(destination._canonical_destination(url))
        except destination._RestrictedDownloadError as error:
            expected = {"code": error.code, "message": error.message}
        urls.append(
            {"input": url, "expected": expected, "is_external": destination.is_external_https_archive_source(url)}
        )
    cases = [
        {"name": "success", "responses": [{"status": 200, "body": b"archive", "headers": {"Content-Length": "7"}}]},
        {"name": "empty", "responses": [{"status": 200}]},
        {"name": "size-overflow", "max_bytes": 3, "responses": [{"status": 200, "body": b"1234"}]},
        {"name": "declared-overflow", "responses": [{"status": 200, "headers": {"Content-Length": "17"}}]},
        {"name": "truncated", "responses": [{"status": 200, "body": b"ab", "headers": {"Content-Length": "3"}}]},
        {"name": "encoding", "responses": [{"status": 200, "headers": {"Content-Encoding": "gzip"}}]},
        {"name": "bad-length", "responses": [{"status": 200, "headers": {"Content-Length": "no"}}]},
        {"name": "negative-length", "responses": [{"status": 200, "headers": {"Content-Length": "-1"}}]},
        {"name": "http-error", "responses": [{"status": 403}]},
        {"name": "headers-count", "responses": [{"status": 200, "headers": {f"X-{i}": "v" for i in range(65)}}]},
        {"name": "header-control", "responses": [{"status": 200, "headers": {"X-Bad": "x\r\ny"}}]},
        {"name": "mixed-dns", "addresses": ["8.8.8.8", "127.0.0.1"], "responses": []},
        {"name": "private-dns", "addresses": ["127.0.0.1"], "responses": []},
        {
            "name": "redirect-loop",
            "max_redirects": 0,
            "responses": [{"status": 302, "headers": {"Location": "/next.tgz"}}],
        },
        {
            "name": "redirect-relative",
            "responses": [{"status": 302, "headers": {"Location": "../next.tgz"}}, {"status": 200, "body": b"a"}],
        },
        {
            "name": "redirect-query",
            "responses": [{"status": 302, "headers": {"Location": "?x=1"}}, {"status": 200, "body": b"a"}],
        },
        {
            "name": "redirect-http",
            "responses": [{"status": 302, "headers": {"Location": "http://packages.example.com/next"}}],
        },
        {"name": "redirect-local", "responses": [{"status": 302, "headers": {"Location": "https://127.0.0.1/next"}}]},
        {"name": "redirect-missing", "responses": [{"status": 302}]},
    ]
    vectors = {
        "schema": "hol-guard.archive-acquisition-parity.v1",
        "base_commit": revision,
        "source_sha256": {path: hashlib.sha256(source).hexdigest() for path, source in sources.items()},
        "destinations": urls,
        "addresses": [
            {"input": ip, "expected": destination._address_is_public(ipaddress.ip_address(ip))} for ip in ADDRESSES
        ],
        "downloads": [download_vector(case) for case in cases],
    }
    # Bodies are synthetic ASCII bytes; encode them as text for the native test reader.
    args.output.write_text(
        json.dumps(vectors, indent=2, ensure_ascii=True, default=lambda value: value.decode("ascii")) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()

"""Native acquisition transport binding and public compatibility regressions.

Network, redirect, DNS, TLS, body and late-write cases run natively against the
recorded Python vectors and synthetic HTTPS peers; no Python oracle remains.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_archive_acquisition as client
from codex_plugin_scanner.guard.native_context import _canonical_request_sha256
from codex_plugin_scanner.guard.runtime import restricted_archive_download as public
from codex_plugin_scanner.guard.runtime.restricted_archive_contract import (
    RestrictedArchiveDownload,
    RestrictedArchiveFailure,
)


def _stub(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    payload: dict[str, Any] | Callable[[dict], dict],
    mutation: str = "",
) -> list[dict]:
    calls: list[dict] = []
    status = SimpleNamespace(
        available=True,
        compatible=True,
        identity=SimpleNamespace(path=tmp_path / "runtime"),
        capabilities=SimpleNamespace(features={"archive-acquisition-v1", "resident-protocol-v2"}),
    )
    monkeypatch.setattr(client, "native_runtime_status", lambda **_kw: status)
    monkeypatch.setattr(client, "_resolve_digest_home", lambda _home: tmp_path)
    monkeypatch.setattr(client, "ensure_resident_prerequisite", lambda _home: True)
    monkeypatch.setattr(client, "_isolated_environment", lambda: {})

    def transport(**kwargs: Any) -> bytes | None:
        envelope = json.loads(kwargs["payload"])
        calls.append(envelope)
        request = envelope["request"]
        result = {
            "schema": client._RESULT_SCHEMA,
            "request_id": request["request_id"],
            "request_sha256": "sha256:" + _canonical_request_sha256(request),
            "status": "ok",
            "code": "ok",
            "payload": payload(request["query"]) if callable(payload) else payload,
        }
        if mutation == "missing":
            return None
        if mutation in {"schema", "request_id", "request_sha256", "status", "code"}:
            result[mutation] = "wrong"
        if mutation == "extra":
            result["unreviewed"] = True
        encoded = json.dumps(result)
        if mutation == "duplicate":
            encoded = encoded[:-1] + ', "status": "ok"}'
        return encoded.encode()

    monkeypatch.setattr(client, "native_resident_client_request", transport)
    return calls


@pytest.mark.parametrize(
    "mutation", ["missing", "schema", "request_id", "request_sha256", "status", "code", "extra", "duplicate"]
)
def test_native_source_identity_refuses_unbound_or_malformed_reply(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, mutation: str
) -> None:
    _stub(
        monkeypatch,
        tmp_path,
        {"kind": "destination", "canonical_url": "https://packages.example.com/a", "is_external": False},
        mutation,
    )
    assert public.canonical_external_https_archive_source("https://packages.example.com/a") is None
    assert public.is_external_https_archive_source("https://packages.example.com/a") is True


def test_source_identity_comes_from_bound_native_reply(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls = _stub(
        monkeypatch,
        tmp_path,
        {"kind": "destination", "canonical_url": "https://packages.example.com/a", "is_external": True},
    )
    assert (
        public.canonical_external_https_archive_source("HTTPS://PACKAGES.EXAMPLE.COM/a")
        == "https://packages.example.com/a"
    )
    assert public.is_external_https_archive_source("https://packages.example.com/a")
    assert all(call["operation"] == "archive_acquisition" for call in calls)


def _trust(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard.mdm import network_transport, network_trust

    policy = SimpleNamespace(allow_public_registries=True)
    monkeypatch.setattr(network_transport, "resolved_network_policy", lambda _policy: (policy, False))
    monkeypatch.setattr(
        network_transport,
        "managed_ssl_context",
        lambda _policy: SimpleNamespace(get_ca_certs=lambda **_kw: [b"synthetic public trust root"]),
    )
    monkeypatch.setattr(
        network_trust, "export_managed_trust_roots", lambda context: context.get_ca_certs(binary_form=True)
    )


def test_download_hydrates_native_digest_bound_blob(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    source = "https://packages.example.com/archive.tgz?signature=a%2Fb"
    _trust(monkeypatch)

    def blob(query: dict) -> dict:
        path = Path(query["temp_dir"]) / "archive.tgz"
        path.write_bytes(b"archive")
        return {
            "kind": "download",
            "path": "\\\\?\\" + str(path) if os.name == "nt" else str(path),
            "size": 7,
            "sha256": "a" * 64,
            "source_url": source,
            "final_url": source,
        }

    calls = _stub(
        monkeypatch,
        tmp_path,
        blob,
    )
    result = public.download_restricted_archive(
        source, max_bytes=17, max_redirects=2, timeout_seconds=1.0, temp_dir=tmp_path
    )
    assert isinstance(result, RestrictedArchiveDownload)
    assert result.sha256 == "a" * 64
    query = calls[0]["request"]["query"]
    assert query["source_url"] == source
    assert query["max_bytes"] == 17
    assert query["max_redirects"] == 2
    assert query["trust_roots_der_hex"] == [b"synthetic public trust root".hex()]
    assert 0 < query["timeout_ms"] <= 1000
    assert query["expires_at_unix_ms"] > 0
    path = result.path
    spool = path.parent
    assert spool.parent.samefile(tmp_path)
    result.cleanup()
    assert not path.exists()
    assert not spool.exists()


@pytest.mark.parametrize("timeout", [-1.0, 0.0, 30.0])
def test_download_marshals_timeout_with_bounded_rpc_budget(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, timeout: float
) -> None:
    _trust(monkeypatch)
    calls = _stub(monkeypatch, tmp_path, {"kind": "failure", "code": "native_refusal", "message": "Refused."})
    result = public.download_restricted_archive(
        "https://packages.example.com/a", timeout_seconds=timeout, temp_dir=tmp_path
    )
    assert isinstance(result, RestrictedArchiveFailure)
    assert result.code == "native_refusal"
    query = calls[0]["request"]["query"]
    assert query["timeout_ms"] <= 8_000
    if timeout <= 0:
        assert query["timeout_ms"] == int(timeout * 1000)
    assert 0 < calls[0]["deadline_budget_ms"] <= 8_000


def test_cleanup_error_preserves_native_failure(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _trust(monkeypatch)
    _stub(monkeypatch, tmp_path, {"kind": "failure", "code": "native_timeout", "message": "Timed out."})
    cleanup = client.tempfile.TemporaryDirectory.cleanup

    def blocked_cleanup(self: Any) -> None:
        cleanup(self)
        raise PermissionError("synthetic late handle")

    monkeypatch.setattr(client.tempfile.TemporaryDirectory, "cleanup", blocked_cleanup)
    result = public.download_restricted_archive("https://packages.example.com/a", temp_dir=tmp_path)
    assert isinstance(result, RestrictedArchiveFailure)
    assert result.code == "native_timeout"


@pytest.mark.parametrize("mutation", ["missing", "request_sha256"])
def test_lost_or_unbound_reply_cleans_private_spool(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, mutation: str
) -> None:
    _trust(monkeypatch)

    def blob(query: dict) -> dict:
        path = Path(query["temp_dir"]) / "late.archive"
        path.write_bytes(b"late")
        return {
            "kind": "download",
            "path": str(path),
            "size": 4,
            "sha256": "a" * 64,
            "source_url": query["source_url"],
            "final_url": query["source_url"],
        }

    calls = _stub(monkeypatch, tmp_path, blob, mutation)
    result = public.download_restricted_archive("https://packages.example.com/a", temp_dir=tmp_path)
    assert isinstance(result, RestrictedArchiveFailure)
    spool = Path(calls[0]["request"]["query"]["temp_dir"])
    assert not spool.exists()
    # Native creation never recreates the caller's deleted parent.
    with pytest.raises(FileNotFoundError):
        (spool / "late.archive").open("xb")


@pytest.mark.parametrize(
    "field,value",
    [
        ("size", True),
        ("size", -1),
        ("size", 7_000_000),
        ("path", "relative"),
        ("sha256", "wrong"),
        ("source_url", "https://other.example.com/a"),
    ],
)
def test_download_rejects_malformed_native_blob(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, field: str, value: Any
) -> None:
    source = "https://packages.example.com/archive.tgz"
    payload = {
        "kind": "download",
        "path": str(tmp_path / "blob"),
        "size": 1,
        "sha256": "a" * 64,
        "source_url": source,
        "final_url": source,
    }
    payload[field] = value
    _trust(monkeypatch)
    _stub(monkeypatch, tmp_path, payload)
    result = public.download_restricted_archive(source)
    assert isinstance(result, RestrictedArchiveFailure)
    assert result.code == "native_archive_acquisition_unavailable"


def test_native_failure_code_survives_public_adapter(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _trust(monkeypatch)
    _stub(
        monkeypatch,
        tmp_path,
        {"kind": "failure", "code": "external_archive_dns_ambiguous", "message": "Mixed addresses."},
    )
    result = public.download_restricted_archive("https://packages.example.com/archive.tgz")
    assert isinstance(result, RestrictedArchiveFailure)
    assert result.code == "external_archive_dns_ambiguous"


def test_native_unavailability_has_no_python_network_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    _trust(monkeypatch)
    monkeypatch.setattr(client, "_request", lambda *_args, **_kw: None)
    assert public.is_external_https_archive_source("https://packages.example.com/a")
    assert public.canonical_external_https_archive_source("https://packages.example.com/a") is None
    result = public.download_restricted_archive("https://packages.example.com/a")
    assert isinstance(result, RestrictedArchiveFailure)
    assert result.code == "native_archive_acquisition_unavailable"

"""Bounded upload of exact primary AIBOM artifact bodies."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import urllib.error
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TypedDict

from ..path_support import resolves_within_root
from .inventory_contract import GuardAgentInventorySnapshot

_CONTENT_HASH_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_MAX_CONTENT_ITEMS_PER_BATCH = 100
_MAX_CONTENT_ITEM_BYTES = 1024 * 1024
_MAX_CONTENT_RAW_BYTES_PER_BATCH = 5 * 1024 * 1024
_MAX_CONTENT_REQUEST_BYTES = 7 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class GuardAibomPrimaryContentSource:
    agent_id: str
    allowed_root: Path
    content_hash: str
    harness_id: str
    item_id: str
    item_kind: str
    mime_type: str
    path: Path
    snapshot_id: str
    version_id: str


class _GuardAibomContentUploadCounts(TypedDict):
    eligible: int
    attempted: int
    stored: int
    hash_only: int
    uploaded: int
    failed: int
    skipped: int
    batches: int


class GuardAibomContentUploadSummary(_GuardAibomContentUploadCounts, total=False):
    reason: str


def empty_content_upload_summary() -> GuardAibomContentUploadSummary:
    return {
        "eligible": 0,
        "attempted": 0,
        "stored": 0,
        "hash_only": 0,
        "uploaded": 0,
        "failed": 0,
        "skipped": 0,
        "batches": 0,
    }


def merge_content_upload_summary(
    target: GuardAibomContentUploadSummary,
    source: GuardAibomContentUploadSummary,
) -> None:
    target["eligible"] += source["eligible"]
    target["attempted"] += source["attempted"]
    target["stored"] += source["stored"]
    target["hash_only"] += source["hash_only"]
    target["uploaded"] += source["uploaded"]
    target["failed"] += source["failed"]
    target["skipped"] += source["skipped"]
    target["batches"] += source["batches"]
    reason = source.get("reason")
    if isinstance(reason, str) and reason:
        target["reason"] = reason


def primary_content_sources_from_artifacts(
    artifacts: tuple[object, ...],
    snapshot: GuardAgentInventorySnapshot,
    *,
    workspace_dir: Path | None,
) -> tuple[GuardAibomPrimaryContentSource, ...]:
    items_by_id = {item.item_id: item for item in snapshot.items}
    sources: list[GuardAibomPrimaryContentSource] = []
    for artifact in artifacts:
        artifact_type = str(getattr(artifact, "artifact_type", ""))
        if artifact_type not in {"skill", "instruction"}:
            continue
        item_id = str(getattr(artifact, "artifact_id", ""))
        item = items_by_id.get(item_id)
        if item is None or not _CONTENT_HASH_PATTERN.fullmatch(item.content_hash):
            continue
        path_value = getattr(artifact, "config_path", None)
        if not isinstance(path_value, str) or not path_value.strip():
            continue
        path = Path(path_value).expanduser()
        allowed_root = _primary_allowed_root(
            artifact_type=artifact_type,
            path=path,
            workspace_dir=workspace_dir,
        )
        if allowed_root is None or not _safe_primary_path(path, allowed_root=allowed_root):
            continue
        sources.append(
            GuardAibomPrimaryContentSource(
                agent_id=snapshot.agent_id,
                allowed_root=allowed_root,
                content_hash=item.content_hash,
                harness_id=snapshot.agent_type,
                item_id=item.item_id,
                item_kind=item.item_kind,
                mime_type=_content_mime_type(path),
                path=path,
                snapshot_id=snapshot.snapshot_id,
                version_id=item.source_fingerprint,
            )
        )
    return tuple(sources)


def _primary_allowed_root(
    *,
    artifact_type: str,
    path: Path,
    workspace_dir: Path | None,
) -> Path | None:
    if artifact_type == "instruction":
        if workspace_dir is None or path.suffix.lower() not in {".md", ".mdc"}:
            return None
        return workspace_dir
    if path.name != "SKILL.md":
        return None
    parents = list(path.parents)
    skills_root = next((parent for parent in parents if parent.name.lower() == "skills"), None)
    if skills_root is None:
        return None
    try:
        relative = path.relative_to(skills_root)
    except ValueError:
        return None
    return skills_root if len(relative.parts) >= 2 else None


def _safe_primary_path(path: Path, *, allowed_root: Path) -> bool:
    if not path.is_file() or not resolves_within_root(allowed_root, path, require_exists=True):
        return False
    try:
        relative = path.relative_to(allowed_root)
    except ValueError:
        return False
    current = allowed_root
    if current.is_symlink():
        return False
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            return False
    return True


def _content_mime_type(path: Path) -> str:
    if path.suffix.lower() in {".md", ".mdc"}:
        return "text/markdown; charset=utf-8"
    return "text/plain; charset=utf-8"


def _prepared_upload_item(source: GuardAibomPrimaryContentSource) -> tuple[dict[str, object], int] | None:
    if not _safe_primary_path(source.path, allowed_root=source.allowed_root):
        return None
    try:
        with source.path.open("rb") as handle:
            body = handle.read(_MAX_CONTENT_ITEM_BYTES + 1)
    except OSError:
        return None
    if len(body) > _MAX_CONTENT_ITEM_BYTES:
        return None
    content_hash = f"sha256:{hashlib.sha256(body).hexdigest()}"
    if content_hash != source.content_hash:
        return None
    return (
        {
            "bodyBase64": base64.b64encode(body).decode("ascii"),
            "contentHash": source.content_hash,
            "itemKind": source.item_kind,
            "itemId": source.item_id,
            "versionId": source.version_id,
            "mimeType": source.mime_type,
            "evidenceAuthority": "device_claim",
            "bundleCompletenessState": "device_declared",
        },
        len(body),
    )


def _content_upload_url(sync_url: str, workspace_id: str) -> str:
    parsed = urllib.parse.urlsplit(sync_url)
    path = f"/api/guard/aibom/workspaces/{urllib.parse.quote(workspace_id, safe='')}/content-upload"
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def _encoded_batch(
    *,
    items: list[dict[str, object]],
) -> bytes:
    return json.dumps(
        {
            "items": items,
        },
        separators=(",", ":"),
    ).encode("utf-8")


def _bounded_response_count(
    payload: object,
    key: str,
    *,
    upper_bound: int,
) -> int | None:
    if not isinstance(payload, dict):
        return None
    value = payload.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if 0 <= value <= upper_bound else None


def upload_primary_content_sources(
    store: Any,
    runner: Any,
    auth_context: dict[str, object],
    *,
    sources: tuple[GuardAibomPrimaryContentSource, ...],
    workspace_id: str,
) -> tuple[GuardAibomContentUploadSummary, dict[str, object]]:
    summary = empty_content_upload_summary()
    summary["eligible"] = len(sources)
    if not sources:
        return summary, auth_context

    resolved_auth_context = auth_context
    batch_items: list[dict[str, object]] = []
    batch_raw_bytes = 0

    def send_batch() -> bool:
        nonlocal batch_items, batch_raw_bytes, resolved_auth_context
        if not batch_items:
            return True
        body = _encoded_batch(items=batch_items)
        content_url = _content_upload_url(str(resolved_auth_context["sync_url"]), workspace_id)
        request = runner._guard_sync_request(
            resolved_auth_context,
            request_url=content_url,
            method="POST",
            data=body,
            extra_headers=None,
        )
        summary["attempted"] += len(batch_items)
        summary["batches"] += 1
        try:
            payload = runner._urlopen_json_with_timeout_retry(
                request=request,
                timeout_seconds=60,
                retry_timeout_seconds=90,
            )
        except urllib.error.HTTPError as error:
            if error.code == 401:
                try:
                    resolved_auth_context = runner._resolve_guard_sync_auth_context(store, force_refresh=True)
                    content_url = _content_upload_url(str(resolved_auth_context["sync_url"]), workspace_id)
                    request = runner._guard_sync_request(
                        resolved_auth_context,
                        request_url=content_url,
                        method="POST",
                        data=body,
                        extra_headers=None,
                    )
                    payload = runner._urlopen_json_with_timeout_retry(
                        request=request,
                        timeout_seconds=60,
                        retry_timeout_seconds=90,
                    )
                except (OSError, RuntimeError, urllib.error.HTTPError):
                    summary["failed"] += len(batch_items)
                    summary["reason"] = "authorization_failed"
                    return False
            else:
                summary["failed"] += len(batch_items)
                summary["reason"] = "endpoint_unavailable" if error.code == 404 else "http_error"
                return False
        except (OSError, RuntimeError):
            summary["failed"] += len(batch_items)
            summary["reason"] = "network_error"
            return False

        batch_size = len(batch_items)
        stored = _bounded_response_count(payload, "storedCount", upper_bound=batch_size)
        hash_only = _bounded_response_count(payload, "hashOnlyCount", upper_bound=batch_size)
        server_failed = _bounded_response_count(payload, "failedCount", upper_bound=batch_size)
        if stored is None or hash_only is None or server_failed is None:
            summary["failed"] += batch_size
            summary["reason"] = "invalid_response"
            return False
        accounted = stored + hash_only + server_failed
        if accounted > batch_size:
            summary["failed"] += batch_size
            summary["reason"] = "invalid_response"
            return False
        summary["stored"] += stored
        summary["hash_only"] += hash_only
        summary["uploaded"] += stored + hash_only
        summary["failed"] += server_failed + batch_size - accounted
        if accounted < batch_size:
            summary["reason"] = "incomplete_response"
            return False
        batch_items = []
        batch_raw_bytes = 0
        return True

    for index, source in enumerate(sources):
        prepared = _prepared_upload_item(source)
        if prepared is None:
            summary["skipped"] += 1
            continue
        item, raw_bytes = prepared
        candidate_items = [*batch_items, item]
        candidate_body = _encoded_batch(items=candidate_items)
        if batch_items and (
            len(candidate_items) > _MAX_CONTENT_ITEMS_PER_BATCH
            or batch_raw_bytes + raw_bytes > _MAX_CONTENT_RAW_BYTES_PER_BATCH
            or len(candidate_body) > _MAX_CONTENT_REQUEST_BYTES
        ):
            if not send_batch():
                summary["failed"] += len(sources) - index
                return summary, resolved_auth_context
            candidate_items = [item]
            candidate_body = _encoded_batch(items=candidate_items)
        if raw_bytes > _MAX_CONTENT_RAW_BYTES_PER_BATCH or len(candidate_body) > _MAX_CONTENT_REQUEST_BYTES:
            summary["skipped"] += 1
            continue
        batch_items = candidate_items
        batch_raw_bytes += raw_bytes

    send_batch()
    return summary, resolved_auth_context

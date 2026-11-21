"""Fixed-repository immutable release uploads and monotonic root selection."""

from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from publish_extension_snapshot import REPOSITORY, github, github_id, upload_asset

from codex_plugin_scanner.guard.catalog_delivery.authority import MAX_PROVENANCE_BYTES, OWNER_ID, REPOSITORY_ID

_last_write = 0.0


def pace_write():
    """Keep sequential publication writes below content-generation bursts."""
    global _last_write
    remaining = 1.0 - (time.monotonic() - _last_write)
    if remaining > 0:
        time.sleep(remaining)
    _last_write = time.monotonic()


def verify_repository():
    value = json.loads(github("api", "repos/" + REPOSITORY))
    if (
        str(value.get("id")) != REPOSITORY_ID
        or str(value.get("owner", {}).get("id")) != OWNER_ID
        or value.get("visibility") != "public"
    ):
        raise ValueError("delivery target repository identity or visibility differs")


def release(tag):
    # GraphQL resolves writable drafts even before their Git tag exists. Avoid
    # scanning the complete release history on every incremental publication.
    query = (
        'query($tag:String!){repository(owner:"hashgraph-online",name:"hol-guard")'
        "{release(tagName:$tag){databaseId tagName}}}"
    )
    value = json.loads(github("api", "graphql", "-f", "query=" + query, "-f", "tag=" + tag))
    result = value.get("data", {}).get("repository", {}).get("release")
    if result is None:
        return None
    identity = github_id(result.get("databaseId"))
    if result.get("tagName") != tag:
        raise ValueError("delivery release identity differs")
    return json.loads(github("api", f"repos/{REPOSITORY}/releases/{identity}"))


def asset_inventory(identity):
    assets = {}
    for page in range(1, 4):
        rows = json.loads(github("api", f"repos/{REPOSITORY}/releases/{identity}/assets?per_page=100&page={page}"))
        if not isinstance(rows, list) or len(rows) > 100:
            raise ValueError("delivery asset page invalid")
        for row in rows:
            github_id(row.get("id"))
            name = row.get("name")
            if not isinstance(name, str) or name in assets:
                raise ValueError("delivery release has duplicate or invalid assets")
            assets[name] = row
            if len(assets) > 256:
                raise ValueError("delivery release exceeds asset count limit")
        if len(rows) < 100:
            return assets
    raise ValueError("delivery release asset inventory incomplete")


def verify_asset(asset, expected):
    if asset.get("size") != expected["length"]:
        raise ValueError("delivery asset length differs")
    remote = asset.get("digest")
    if remote is not None:
        if remote != "sha256:" + expected["sha256"]:
            raise ValueError("delivery asset digest differs")
        return
    # Older GitHub assets can lack the server-computed SHA-256. Their bounded
    # advertised length must match before downloading and checking the bytes.
    with tempfile.TemporaryDirectory(prefix="extension-delivery-verify-") as directory:
        path = Path(directory) / "asset"
        download_asset(asset, path, expected["length"])
        if (
            path.stat().st_size != expected["length"]
            or hashlib.sha256(path.read_bytes()).hexdigest() != expected["sha256"]
        ):
            raise ValueError("downloaded delivery asset differs")


def download_asset(asset, destination, maximum):
    if type(maximum) is not int or not 0 < maximum <= 32 * 1024 * 1024:
        raise ValueError("delivery download limit invalid")
    endpoint = f"repos/{REPOSITORY}/releases/assets/{github_id(asset.get('id'))}"
    with tempfile.TemporaryFile() as errors, destination.open("xb") as output:
        process = subprocess.Popen(
            ["gh", "api", endpoint, "--header", "Accept: application/octet-stream"],
            stdout=subprocess.PIPE,
            stderr=errors,
        )
        timer = threading.Timer(120, process.kill)
        timer.start()
        try:
            remaining = maximum + 1
            while remaining:
                data = process.stdout.read(min(65536, remaining))
                if not data:
                    break
                output.write(data)
                remaining -= len(data)
            if remaining == 0:
                raise ValueError("delivery download exceeds byte limit")
            if process.wait(timeout=5):
                errors.seek(0)
                raise RuntimeError(errors.read(2048).decode(errors="replace") or "delivery download failed")
        finally:
            timer.cancel()
            if process.poll() is None:
                process.kill()
            process.wait()
            process.stdout.close()


def verify_tag(tag, source, *, missing=False):
    try:
        commit = json.loads(github("api", f"repos/{REPOSITORY}/commits/{tag}"))
    except RuntimeError as error:
        if missing and ("HTTP 404" in str(error) or "HTTP 422" in str(error)):
            return
        raise
    if commit.get("sha") != source:
        raise ValueError("delivery release tag differs from reviewed source")


def publish_assets(tag, source, paths, expected, *, verify_existing_provenance=None):
    if not 0 < len(expected) <= 256 or set(paths) != set(expected):
        raise ValueError("delivery release asset inventory invalid")
    current = release(tag)
    if current is None:
        pace_write()
        current = json.loads(
            github(
                "api",
                f"repos/{REPOSITORY}/releases",
                "--method",
                "POST",
                "-f",
                "tag_name=" + tag,
                "-f",
                "target_commitish=" + source,
                "-F",
                "draft=true",
                "-F",
                "prerelease=true",
                "-f",
                "make_latest=false",
                "-f",
                "name=Extension delivery " + source[:12],
                "-f",
                "body=Verified extension data for source commit " + source + ".",
            )
        )
        if current.get("draft") is not True:
            raise ValueError("new delivery release must remain a draft")
    identity = github_id(current.get("id"))
    if (
        current.get("tag_name") != tag
        or current.get("target_commitish") != source
        or current.get("prerelease") is not True
    ):
        raise ValueError("delivery release does not match its source")
    verify_tag(tag, source, missing=bool(current["draft"]))
    assets = asset_inventory(identity)
    if set(assets) - set(expected) or (not current["draft"] and set(assets) != set(expected)):
        raise ValueError("delivery release is unexpected or incomplete")
    for name, spec in sorted(expected.items()):
        asset = assets.get(name)
        if asset is not None and asset.get("state") != "uploaded":
            # An upload cut off by a gateway error leaves a placeholder that
            # cannot be downloaded. Only a draft may drop it and upload again.
            if not current["draft"]:
                raise ValueError("published delivery asset upload is incomplete")
            pace_write()
            github("api", f"repos/{REPOSITORY}/releases/assets/{github_id(asset.get('id'))}", "--method", "DELETE")
            asset = None
        if asset is not None:
            if verify_existing_provenance is not None and name.endswith(".intoto.jsonl"):
                if type(asset.get("size")) is not int or not 0 < asset["size"] <= MAX_PROVENANCE_BYTES:
                    raise ValueError("existing delivery provenance exceeds byte limit")
                with tempfile.TemporaryDirectory(prefix="extension-delivery-provenance-") as directory:
                    path = Path(directory) / "provenance"
                    download_asset(asset, path, asset["size"])
                    if path.stat().st_size != asset["size"]:
                        raise ValueError("existing delivery provenance length differs")
                    verify_existing_provenance(path.read_bytes())
                continue
            verify_asset(asset, spec)
            continue
        pace_write()
        asset = upload_asset(identity, paths[name], expected={key: spec[key] for key in ("sha256", "length")})
        if asset.get("name") != name:
            raise ValueError("uploaded delivery asset identity differs")
        verify_asset(asset, spec)
    if current["draft"]:
        pace_write()
        result = json.loads(
            github(
                "api",
                f"repos/{REPOSITORY}/releases/{identity}",
                "--method",
                "PATCH",
                "-F",
                "draft=false",
                "-f",
                "make_latest=false",
            )
        )
        if result.get("draft") is not False or result.get("tag_name") != tag:
            raise ValueError("delivery release publication was not confirmed")
    verify_tag(tag, source)

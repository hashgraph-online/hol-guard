"""Bounded public release transport for explicit update and activation commands.

Transport bytes never grant policy authority. Callers must authenticate the
root with Sigstore and verify every referenced object before using its data.
"""

from __future__ import annotations

import hashlib
import os
import re
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from contextlib import suppress

from codex_plugin_scanner.guard.extension_builder.errors import BuilderError
from codex_plugin_scanner.guard.extension_builder.io import checked_path, read_bytes
from codex_plugin_scanner.guard.mdm.network import managed_urlopen

from .authority import MAX_PROVENANCE_BYTES, decode, verify_distribution
from .containers import location, member
from .containers import maximum as container_maximum
from .selection import BRANCH, FILE, SHA, root_tag, validate

REPOSITORY = "hashgraph-online/hol-guard"
ROOT_ASSET = "extension-distribution.v2.json"
PROVENANCE_ASSET = "extension-distribution.intoto.jsonl"
DATA_TAG = re.compile(r"extension-data-[0-9a-f]{40}-[0-9]{1,20}\.[0-9]{1,10}-[0-9]{6}")
DATA_ASSET = re.compile(r"(?:object-[0-9a-f]{64}\.json|pack-[0-9a-f]{64}\.zip)")
HOSTS = frozenset(
    {
        "api.github.com",
        "github.com",
        "raw.githubusercontent.com",
        "release-assets.githubusercontent.com",
        "objects.githubusercontent.com",
    }
)


class MissingReleaseError(ValueError):
    pass


def _check_url(url):
    parsed = urllib.parse.urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname not in HOSTS
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port not in {None, 443}
    ):
        raise ValueError("release transport destination is not permitted")


def download(url, maximum):
    if type(maximum) is not int or not 0 < maximum <= 32 * 1024 * 1024:
        raise ValueError("release transport byte limit invalid")
    for redirects in range(5):
        _check_url(url)
        request = urllib.request.Request(
            url, headers={"User-Agent": "HOL-Guard-extension-delivery", "Accept-Encoding": "identity"}
        )
        try:
            response = managed_urlopen(request, timeout=20, allow_redirects=False)
            break
        except urllib.error.HTTPError as error:
            if error.code == 404:
                error.close()
                raise MissingReleaseError("extension release is unavailable") from error
            if error.code not in {301, 302, 303, 307, 308}:
                raise
            target = error.headers.get("Location")
            error.close()
            if not target or redirects == 4:
                raise ValueError("release transport redirect limit or destination invalid") from error
            url = urllib.parse.urljoin(url, target)
    else:
        raise ValueError("release transport redirect limit exceeded")
    with response:
        if response.headers.get("Content-Encoding", "identity") != "identity":
            raise ValueError("compressed release transport is not permitted")
        declared = response.headers.get("Content-Length")
        if declared is not None and (
            not declared.isascii() or not declared.isdecimal() or not 0 < int(declared) <= maximum
        ):
            raise ValueError("release transport content length exceeds byte limit")
        data = response.read(maximum + 1)
        if not 0 < len(data) <= maximum or (declared is not None and len(data) != int(declared)):
            raise ValueError("release transport body length invalid")
        return data


def selected():
    return validate(decode(download(f"https://raw.githubusercontent.com/{REPOSITORY}/{BRANCH}/{FILE}", 4096)))


def require_source_ancestor(previous, candidate):
    """Validate publication lineage outside activation locks and hook decisions."""
    if any(not isinstance(value, str) or SHA.fullmatch(value) is None for value in (previous, candidate)):
        raise ValueError("publication ancestry requires full source identities")
    if previous == candidate:
        return
    # Page two omits the potentially large changed-file list. The comparison's
    # status and merge base remain present even when that commit page is empty.
    url = f"https://api.github.com/repos/{REPOSITORY}/compare/{previous}...{candidate}?per_page=1&page=2"
    value = decode(download(url, 64 * 1024))
    if (
        not isinstance(value, dict)
        or value.get("status") != "ahead"
        or not isinstance(value.get("base_commit"), dict)
        or value["base_commit"].get("sha") != previous
        or not isinstance(value.get("merge_base_commit"), dict)
        or value["merge_base_commit"].get("sha") != previous
        or type(value.get("behind_by")) is not int
        or value["behind_by"] != 0
        or type(value.get("ahead_by")) is not int
        or value["ahead_by"] <= 0
    ):
        raise ValueError("publication source is not a descendant of the retained floor")


def root_assets(source, publication):
    base = f"https://github.com/{REPOSITORY}/releases/download/{root_tag(source, publication)}/"
    return download(base + ROOT_ASSET, 65536), download(base + PROVENANCE_ASSET, MAX_PROVENANCE_BYTES)


def fetch_root(*, now, selection=None, offline=False):
    selection = selected() if selection is None else validate(selection)
    data, provenance = root_assets(selection["source_sha"], selection["publication_id"])
    if hashlib.sha256(data).hexdigest() != selection["root_sha256"]:
        raise ValueError("release root differs from advisory selector")
    result = verify_distribution(
        data, provenance, expected_source_sha=selection["source_sha"], now=now, offline=offline
    )
    if result.manifest()["publication_id"] != selection["publication_id"]:
        raise ValueError("release root publication identity differs from selector")
    return result


def fetch_object(target, maximum):
    return _fetch(target, maximum)


def cached_fetcher(directory):
    directory = checked_path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    return lambda target, maximum: _fetch(target, maximum, directory)


def _fetch(target, maximum, cache=None):
    if not isinstance(target, dict):
        raise ValueError("release object location invalid")
    name = target.get("member", target.get("asset", ""))
    if not isinstance(name, str) or DATA_ASSET.fullmatch(name) is None:
        raise ValueError("release object location invalid")
    kind = "object" if name.startswith("object-") else "pack"
    digest = name.split("-", 1)[1].split(".", 1)[0]
    location(target, digest, kind)
    url = f"https://github.com/{REPOSITORY}/releases/download/{target['tag']}/{target['asset']}"
    if "member" not in target:
        return download(url, maximum)
    bound = container_maximum(target["asset"])
    path = None if cache is None else checked_path(cache / (hashlib.sha256(url.encode()).hexdigest() + ".zip"))
    repair = False
    if path is not None and path.exists():
        try:
            return member(read_bytes(path, limit=bound), target["asset"], name, maximum)
        except (ValueError, OSError, zipfile.BadZipFile, BuilderError):
            repair = True
    data = download(url, bound)
    result = member(data, target["asset"], name, maximum)
    if path is not None and (repair or not path.exists()):
        with tempfile.NamedTemporaryFile(dir=cache, prefix=".transfer-", delete=False) as stream:
            temporary = stream.name
            try:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
                stream.close()
                if repair:
                    os.replace(temporary, path)
                else:
                    # A competing untrusted cache entry is checked on read.
                    with suppress(FileExistsError):
                        os.link(temporary, path)
            finally:
                with suppress(FileNotFoundError):
                    os.unlink(temporary)
    return result

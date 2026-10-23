"""Bounded public release transport for explicit update and activation commands.

Transport bytes never grant policy authority. Callers must authenticate the
root with Sigstore and verify every referenced object before using its data.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from contextlib import suppress
from pathlib import Path

from codex_plugin_scanner.guard.extension_builder.errors import BuilderError
from codex_plugin_scanner.guard.extension_builder.io import checked_path
from codex_plugin_scanner.guard.mdm.network import managed_urlopen

from .authority import MAX_PROVENANCE_BYTES, decode, verify_distribution
from .containers import member
from .object_native import call, member_at, sessioned
from .selection import BRANCH, FILE, root_tag, validate
from .transport_native import decide

REPOSITORY = "hashgraph-online/hol-guard"
ROOT_ASSET = "extension-distribution.v2.json"
PROVENANCE_ASSET = "extension-distribution.intoto.jsonl"


class MissingReleaseError(ValueError):
    pass


def _joined(url, location):
    # The runtime judges the joined URL; a Location that cannot be joined names none.
    if not location:
        return None
    try:
        return urllib.parse.urljoin(url, location)
    except ValueError:
        return None


def _after_refusal(error, url, hop):
    """Close a refusal the runtime classified and return the redirect it asked to follow."""
    headers = error.headers
    location = None if headers is None else headers.get("Location")
    try:
        verdict = decide("refusal", status=error.code, hop=hop, location=location, next=_joined(url, location))
    except ValueError:
        error.close()
        raise
    if "missing" in verdict:
        error.close()
        raise MissingReleaseError(verdict["missing"]) from error
    if "redirect" in verdict:
        error.close()
        return verdict["redirect"]
    # Any other refusal is the caller's to see; its connection must not outlive the attempt.
    error.close()
    raise error


@sessioned
def download(url, maximum):
    attempt = 0
    while True:
        try:
            return _download(url, maximum)
        except OSError as error:
            status = error.code if isinstance(error, urllib.error.HTTPError) else None
            network = status is None and isinstance(error, (urllib.error.URLError, ConnectionError, TimeoutError))
            delay = decide("retry", status=status, network=network, attempt=attempt)["delay"]
            if delay is None:
                raise
        time.sleep(delay)
        attempt += 1


def _download(url, maximum):
    # The runtime ends a redirect chain: it refuses the hop that exceeds its budget.
    decide("request", url=url, maximum=maximum)
    hop = 0
    while True:
        request = urllib.request.Request(
            url, headers={"User-Agent": "HOL-Guard-extension-delivery", "Accept-Encoding": "identity"}
        )
        try:
            response = managed_urlopen(request, timeout=20, allow_redirects=False)
            break
        except urllib.error.HTTPError as error:
            url = _after_refusal(error, url, hop)
            hop += 1
    with response:
        declared = decide(
            "headers",
            content_encoding=response.headers.get("Content-Encoding"),
            content_length=response.headers.get("Content-Length"),
            maximum=maximum,
        )["declared"]
        data = response.read(maximum + 1)
        decide("body", length=len(data), declared=declared, maximum=maximum)
        return data


def selected():
    return validate(decode(download(f"https://raw.githubusercontent.com/{REPOSITORY}/{BRANCH}/{FILE}", 4096)))


def root_assets(source, publication):
    base = f"https://github.com/{REPOSITORY}/releases/download/{root_tag(source, publication)}/"
    return download(base + ROOT_ASSET, 65536), download(base + PROVENANCE_ASSET, MAX_PROVENANCE_BYTES)


@sessioned
def fetch_root(*, now, selection=None, offline=False, verified_io=None):
    selection = selected() if selection is None else validate(selection)
    data, provenance = root_assets(selection["source_sha"], selection["publication_id"])
    # The digest is bound before verification, so a substituted root never reaches it.
    decide("bind", selector=selection, root_sha256=hashlib.sha256(data).hexdigest())
    result = verify_distribution(
        data, provenance, expected_source_sha=selection["source_sha"], now=now, offline=offline
    )
    decide("bind", selector=selection, publication_id=result.manifest()["publication_id"])
    if verified_io is not None:
        verified_io(result, provenance)
    return result


def fetch_object(target, maximum):
    return _fetch(target, maximum)


def cached_fetcher(directory):
    from .cache_io import Lease

    directory = checked_path(directory)
    directory.mkdir(parents=True, exist_ok=True)

    def fetch(target, maximum):
        with Lease(directory.parent):
            return _fetch(target, maximum, directory)

    return fetch


def _fetch(target, maximum, cache=None):
    # The runtime names the asset, checks its location and bounds the container.
    plan = call("asset", profile="release", target=target, invalid="release object location invalid")
    asset, name = plan["asset"], plan["name"]
    url = f"https://github.com/{REPOSITORY}/releases/download/{plan['tag']}/{asset}"
    if plan["bound"] is None:
        return download(url, maximum)
    bound = plan["bound"]
    path = None if cache is None else checked_path(cache / (hashlib.sha256(url.encode()).hexdigest() + ".zip"))
    repair = False
    if path is not None and path.exists():
        try:
            return member_at(path, asset, name, maximum)
        except (ValueError, OSError, BuilderError):
            repair = True
    data = download(url, bound)
    if path is None:
        return member(data, asset, name, maximum)
    with tempfile.NamedTemporaryFile(dir=cache, prefix=".transfer-", delete=False) as stream:
        temporary = stream.name
        try:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
            stream.close()
            result = member_at(Path(temporary), asset, name, maximum)
            if repair:
                os.replace(temporary, path)
            else:
                # A competing untrusted cache entry is checked on read.
                with suppress(FileExistsError):
                    os.link(temporary, path)
            return result
        finally:
            with suppress(FileNotFoundError):
                os.unlink(temporary)

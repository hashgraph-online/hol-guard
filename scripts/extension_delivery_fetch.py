"""Build-time release object fetching.

Publishing and regeneration fetch published objects without the native runtime
installed, so they check each container member here. The installed runtime
fetches and checks the same objects natively.
"""

import hashlib
import os
import re
import tempfile
import zipfile
from contextlib import suppress

from extension_delivery_containers import maximum as container_maximum
from extension_delivery_containers import member

from codex_plugin_scanner.guard.catalog_delivery.cache_io import Lease
from codex_plugin_scanner.guard.catalog_delivery.containers import location
from codex_plugin_scanner.guard.catalog_delivery.transport import REPOSITORY, download
from codex_plugin_scanner.guard.extension_builder.errors import BuilderError
from codex_plugin_scanner.guard.extension_builder.io import checked_path, read_bytes

DATA_ASSET = re.compile(r"(?:object-[0-9a-f]{64}\.json|pack-[0-9a-f]{64}\.zip)")


def cached_fetcher(directory):
    directory = checked_path(directory)
    directory.mkdir(parents=True, exist_ok=True)

    def fetch(target, maximum):
        with Lease(directory.parent):
            return _fetch(target, maximum, directory)

    return fetch


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

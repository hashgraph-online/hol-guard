"""Disposable real daemon process for the installed context restart test.

The one readiness frame travels only over the parent's owned pipe. It contains
the fixture's HTTP credential and must never be copied into test reports.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from installed_extension_authority_fixture import read_authority

from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import AuthorityHealth
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_base import EncryptedFileSecretStore


def main() -> None:
    if os.environ.get("HOL_GUARD_TEST_MODE") != "1":
        raise RuntimeError("isolated pytest fixture environment required")
    request = json.loads(sys.stdin.buffer.readline(16 * 1024))
    if request.get("schema") != "guard-cigar-restart-fixture.v1":
        raise RuntimeError("invalid fixture request")
    root = Path(request["root"]).resolve(strict=True)
    if (root / "fixture-owned").read_text() != "guard-cigar-restart-fixture.v1\n":
        raise RuntimeError("fixture ownership marker required")
    guard_path, workspace = root / "guard", root / "workspace"
    store = GuardStore(guard_path, prime_policy_integrity=False)
    # The fixture never asks the developer's desktop keyring for authority.
    store._extension_control_authority_secret_store = EncryptedFileSecretStore(guard_path)
    authority = read_authority(store)
    if authority.health is AuthorityHealth.UNENROLLED:
        authority = store._bootstrap_extension_control_authority(
            BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest, key=None
        )
    if authority.health is not AuthorityHealth.PROTECTED:
        raise RuntimeError("fixture authority unavailable")
    daemon = GuardDaemonServer(
        store,
        host="127.0.0.1",
        port=0,
        bundle_refresh_interval_seconds=None,
        aibom_refresh_interval_seconds=None,
        home_dir=root / "profile",
        workspace_dir=workspace,
    )
    daemon.start()
    try:
        print(
            json.dumps(
                {
                    "schema": "guard-cigar-restart-ready.v1",
                    "pid": os.getpid(),
                    "port": daemon.port,
                    "auth_token": daemon._server.auth_token,
                }
            ),
            flush=True,
        )
        if sys.stdin.buffer.readline(128) != b"stop\n":
            raise RuntimeError("fixture stop acknowledgement required")
    finally:
        daemon.stop()


if __name__ == "__main__":
    main()

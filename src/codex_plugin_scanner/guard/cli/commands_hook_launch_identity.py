"""Project native launch evidence without inventing an executable identity."""

from __future__ import annotations

import secrets
from collections.abc import Mapping


def project_hook_launch_identity(identity: Mapping[str, object]) -> dict[str, object]:
    required = {"argv_sha256", "launch_cwd", "executable", "entrypoint"}
    if not required.issubset(identity):
        # Non-POSIX native stubs intentionally cannot verify launch identity.
        # Keep the native decision, but prevent this evidence from binding a
        # reusable approval. A fresh nonce changes every subsequent context.
        return {
            "native_launch_identity": dict(identity),
            "status": "unproven",
            "reuse_nonce": secrets.token_hex(16),
        }
    return {
        "launch_argv_sha256": identity["argv_sha256"],
        "launch_cwd": identity["launch_cwd"],
        "resolved_artifact_command": identity["executable"],
        "resolved_entrypoint": identity["entrypoint"],
    }

"""Identify reusable release binaries without exposing compiler environment values."""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Mapping

from scripts.ci.native_cache_environment import fingerprint


def build_id(environment: Mapping[str, str]) -> str:
    """Bind a prepared binary to its source, version, target, profile and host image."""
    names = ("SOURCE_SHA", "VERSION", "RUST_TARGET", "RUNNER_OS", "RUNNER_ARCH", "ImageOS", "ImageVersion")
    bound = {name: environment.get(name, "") for name in names}
    if not all(bound.values()):
        raise ValueError("release binary cache requires complete source and runner identity")
    if re.fullmatch(r"[0-9a-f]{40}", bound["SOURCE_SHA"]) is None:
        raise ValueError("release binary cache requires a full source commit")
    fast = environment.get("FAST_CODEGEN", "false")
    if fast not in {"true", "false"}:
        raise ValueError("release binary cache requires an explicit codegen profile")
    if fast == "true" and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+a[1-9][0-9]*", bound["VERSION"]) is None:
        raise ValueError("fast release binaries require a canonical alpha version")
    identity: dict[str, object] = {**bound, "fast_codegen": fast}
    identity["alpha_workspace_opt_level"] = environment.get("ALPHA_WORKSPACE_OPT_LEVEL", "") if fast == "true" else ""
    identity["compiler_environment"] = fingerprint(environment)
    # Native CI excludes these overrides from its environment digest. A final
    # binary cache must distinguish them even when supplied outside this workflow.
    identity["release_profile"] = {
        name: value for name, value in environment.items() if name.startswith("CARGO_PROFILE_RELEASE_")
    }
    encoded = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(b"hol-guard.release-native-binary.v1\0" + encoded).hexdigest()


if __name__ == "__main__":
    print(build_id(os.environ))

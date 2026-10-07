"""Discover fixed Node options inside the same enforced execution boundary."""

from __future__ import annotations

import re
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import replace
from pathlib import Path

from .restricted_pytest_model import NODE_TEST_READ_ONLY_PROFILE_VERSION, RestrictedPytestError, RestrictedPytestPlan
from .restricted_pytest_sandbox import _backend_argv, _restricted_environment, _run_backend_process


def linux_node_environment(
    plan: RestrictedPytestPlan,
    *,
    private_root: Path,
    environment: Mapping[str, str],
    timeout_seconds: int,
    authorize_capability: Callable[[tuple[str, ...]], None] | None = None,
) -> dict[str, str]:
    """Avoid Wasm's virtual cage without raising the writable/address-space cap.

    Only execution owners call this, after native authorization of the original
    operation and resolved image/script. Help is also sandboxed, not an execution
    probe of a workspace image in the unsandboxed parent. No repository command
    or host NODE_OPTIONS is parsed as a capability or permission.
    """
    result = dict(environment)
    result.pop("NODE_OPTIONS", None)
    result.pop("NODE_PATH", None)
    if plan.backend != "linux-bubblewrap":
        return result
    helper = replace(
        plan,
        profile_version=NODE_TEST_READ_ONLY_PROFILE_VERSION,
        command=(str(plan.executable), "--help"),
        output_roots=(),
        read_only_roots=(),
    )
    if authorize_capability is not None:
        authorize_capability(helper.command)
    with tempfile.TemporaryDirectory(prefix="node-capabilities-", dir=private_root) as temporary:
        root = Path(temporary)
        home, tmp = root / "home", root / "tmp"
        home.mkdir(mode=0o700)
        tmp.mkdir(mode=0o700)
        helper_env = _restricted_environment(
            result,
            workspace=plan.workspace,
            cwd=plan.cwd,
            private_home=home,
            private_tmp=tmp,
            allowed_executables=plan.allowed_executables,
        )
        output = bytearray()
        code = _run_backend_process(
            _backend_argv(helper, private_root=root),
            env=helper_env,
            timeout_seconds=min(timeout_seconds, 10),
            cwd=plan.cwd,
            stdout_capture=output,
        )
        if code != 0:
            raise RestrictedPytestError(
                "node_restricted_capabilities_unavailable", "Node runtime capability discovery did not finish."
            )
    if re.search(rb"(?m)^[ \t]+--disable-wasm-trap-handler(?:[ \t]|$)", output):
        result["NODE_OPTIONS"] = "--disable-wasm-trap-handler"
    return result

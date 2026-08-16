"""Installed-wheel proof that eligible PostToolUse uses Rust by default."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import codex_plugin_scanner
from codex_plugin_scanner.guard.native_runtime import (
    native_mode,
    native_runtime_health,
    native_runtime_status,
    review_post_tool_native,
)
from codex_plugin_scanner.guard.native_runtime_resident import (
    close_resident_native_runtimes,
)
from codex_plugin_scanner.guard.runtime.hook_review_types import HookReviewRequest


def _request(root: Path, text: str, request_id: str) -> HookReviewRequest:
    guard_home = root / "guard-home"
    guard_home.mkdir(mode=0o700, exist_ok=True)
    return HookReviewRequest(
        harness="claude-code",
        event_name="PostToolUse",
        payload={
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_response": [{"type": "text", "text": text}],
        },
        payload_kind="inline",
        config_path=None,
        cwd=root,
        home_dir=root,
        guard_home=guard_home,
        source_scope="project",
        request_id=request_id,
    )


def _synthetic_github_token() -> str:
    return "".join(("gh", "p_", "c" * 30))


def _short_temp_parent() -> str | None:
    """Keep Unix resident socket paths below platform sun_path limits."""
    if os.name == "nt":
        return None
    candidate = Path("/tmp")
    if not candidate.is_dir() or not os.access(candidate, os.W_OK | os.X_OK):
        return None
    return str(candidate)


def _require(condition: bool, detail: object) -> None:
    """Fail the CI probe even when Python assertions are optimized out."""
    if not condition:
        raise RuntimeError(f"native_default_auto_probe_failed: {detail}")


def main() -> int:
    _require("HOL_GUARD_NATIVE" not in os.environ, "HOL_GUARD_NATIVE must be unset")
    _require(
        "HOL_GUARD_NATIVE_BINARY" not in os.environ,
        "HOL_GUARD_NATIVE_BINARY must be unset",
    )
    _require(native_mode() == "auto", f"unexpected native mode: {native_mode()}")

    package_path = Path(codex_plugin_scanner.__file__).resolve()
    source_package = (Path.cwd() / "src" / "codex_plugin_scanner").resolve()
    _require(
        not package_path.is_relative_to(source_package),
        f"probe imported source tree package: {package_path}",
    )

    status = native_runtime_status()
    _require(status.mode == "auto", status)
    _require(status.available and status.compatible, status)
    _require(status.reason == "native_ready", status)
    _require(status.identity is not None, status)
    capabilities = status.capabilities
    if capabilities is None:
        raise RuntimeError(f"native_default_auto_probe_failed: {status}")

    with tempfile.TemporaryDirectory(prefix="hg-auto-", dir=_short_temp_parent()) as temporary:
        root = Path(temporary)
        try:
            clean = review_post_tool_native(
                _request(root, "const value = 1;\n", "default-auto-clean"),
                observe_mode=False,
            )
            if clean is None:
                raise RuntimeError("native_default_auto_probe_failed: clean response missing")
            _require(clean.decision == "allow", clean)
            _require(clean.reason_code == "output_scan_allow", clean)

            secret = review_post_tool_native(
                _request(root, _synthetic_github_token(), "default-auto-secret"),
                observe_mode=False,
            )
            if secret is None:
                raise RuntimeError("native_default_auto_probe_failed: secret response missing")
            _require(secret.decision == "deny", secret)
            _require(secret.reason_code == "output_secret_match", secret)

            health = native_runtime_health(root / "guard-home")
            _require(health.state == "healthy", health)
            _require(health.reason == "native_ready", health)
            _require(health.resident_failures == 0, health)
            _require(health.oneshot_failures == 0, health)
            _require(health.starts == 1, health)
        finally:
            close_resident_native_runtimes()

    os.environ["HOL_GUARD_NATIVE"] = "off"
    try:
        _require(native_mode() == "off", f"unexpected native mode: {native_mode()}")
        disabled = native_runtime_status()
        _require(disabled.mode == "off", disabled)
        _require(disabled.reason == "native_disabled", disabled)
    finally:
        del os.environ["HOL_GUARD_NATIVE"]

    print(
        json.dumps(
            {
                "default_mode": "auto",
                "runtime_reason": status.reason,
                "target": capabilities.target,
                "rollback": "off",
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

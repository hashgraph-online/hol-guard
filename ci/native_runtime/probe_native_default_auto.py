"""Installed-wheel proof for normalized native hook ingress defaults."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import codex_plugin_scanner
from codex_plugin_scanner.guard.adapters.codex_daemon_hook_transport import (
    _daemon_response_once,
)
from codex_plugin_scanner.guard.config import hook_fast_path_enabled
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
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
from codex_plugin_scanner.guard.store import GuardStore


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


def _ownership_routes() -> dict[str, dict[str, str]]:
    path = Path("docs/guard/contracts/hook-data-plane-ownership.v2.json")
    payload = json.loads(path.read_text(encoding="utf-8"))
    routes = payload.get("harness_routes") if isinstance(payload, dict) else None
    if not isinstance(routes, dict):
        raise RuntimeError("native_default_auto_probe_failed: ownership routes missing")
    decoded: dict[str, dict[str, str]] = {}
    for harness, route in routes.items():
        if not isinstance(harness, str) or not isinstance(route, dict):
            raise RuntimeError("native_default_auto_probe_failed: ownership route invalid")
        pre = route.get("pre_tool_use")
        post = route.get("post_tool_use")
        if not isinstance(pre, str) or not isinstance(post, str):
            raise RuntimeError("native_default_auto_probe_failed: ownership route incomplete")
        decoded[harness] = {"pre_tool_use": pre, "post_tool_use": post}
    return decoded


def _installed_hook_corpus(root: Path) -> dict[str, object]:
    guard_home = root / "hook-home"
    workspace = root / "hook-workspace"
    guard_home.mkdir(mode=0o700)
    workspace.mkdir(mode=0o700)
    store = GuardStore(guard_home)
    daemon = GuardDaemonServer(
        store,
        host="127.0.0.1",
        port=0,
    )
    reason_codes: dict[str, int] = {}

    route_receipts: list[dict[str, str]] = []
    routes = _ownership_routes()
    daemon.start()
    try:
        for harness, route in sorted(routes.items()):
            events: list[tuple[str, dict[str, object]]] = []
            if route["pre_tool_use"].startswith("installed_"):
                events.append(
                    (
                        "PreToolUse",
                        {
                            "hook_event_name": "PreToolUse",
                            "tool_name": "Bash",
                            "tool_input": {"command": "printf guard"},
                        },
                    )
                )
            if route["post_tool_use"].startswith("installed_"):
                events.append(
                    (
                        "PostToolUse",
                        {
                            "hook_event_name": "PostToolUse",
                            "tool_name": "Read",
                            "tool_response": [{"type": "text", "text": "guard baseline\n"}],
                        },
                    )
                )
            for event, payload in events:
                query = urllib.parse.urlencode(
                    {
                        "home": str(guard_home),
                        "workspace": str(workspace),
                    }
                )
                if harness == "codex":
                    response_payload = _daemon_response_once(
                        state_path=guard_home / "daemon-state.json",
                        query=query,
                        data=json.dumps(payload, separators=(",", ":")),
                        timeout_seconds=5,
                    )
                else:
                    request = urllib.request.Request(
                        f"http://127.0.0.1:{daemon.port}/v1/hooks/{harness}?{query}",
                        data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
                        headers={"Content-Type": "application/json", "X-Guard-Token": daemon._server.auth_token},
                        method="POST",
                    )
                    try:
                        with urllib.request.urlopen(request, timeout=5) as response:
                            decoded = json.loads(response.read().decode("utf-8"))
                            response_payload = decoded if isinstance(decoded, dict) else None
                    except urllib.error.HTTPError as error:
                        detail = error.read().decode("utf-8", errors="replace")[:512]
                        raise RuntimeError(
                            "installed hook corpus request failed: "
                            f"harness={harness} event={event} status={error.code} body={detail}"
                        ) from error
                if response_payload is None:
                    raise RuntimeError(f"empty response for {harness} {event}")
                reason = response_payload.get("reason_code")
                if isinstance(reason, str):
                    reason_codes[reason] = reason_codes.get(reason, 0) + 1
                route_receipts.append({"harness": harness, "event": event, "route": "native_resident"})
        worker_stats = daemon._server.hook_process_runner.stats()
    finally:
        daemon.stop()

    expected = len(route_receipts)
    observed_routes = worker_stats["routes"]
    _require(expected > 0, "installed hook corpus is empty")
    _require(sum(observed_routes.values()) == expected, worker_stats)
    _require(observed_routes.get("native_resident") == expected, worker_stats)
    return {
        "routes": route_receipts,
        "route_count": expected,
        "native_resident_decisions": observed_routes.get("native_resident", 0),
        "native_oneshot_decisions": observed_routes.get("native_oneshot", 0),
        "python_semantic_decisions": observed_routes.get("python_semantic", 0),
        "fail_safe_decisions": observed_routes.get("native_fail_safe", 0),
        "reason_code_counts": reason_codes,
    }


def main(*, json_path: Path | None = None) -> int:
    _require("HOL_GUARD_NATIVE" not in os.environ, "HOL_GUARD_NATIVE must be unset")
    _require(
        "HOL_GUARD_NATIVE_BINARY" not in os.environ,
        "HOL_GUARD_NATIVE_BINARY must be unset",
    )
    _require(
        "HOL_GUARD_HOOK_FAST_PATH" not in os.environ,
        "HOL_GUARD_HOOK_FAST_PATH must be unset",
    )
    _require(native_mode() == "auto", f"unexpected native mode: {native_mode()}")
    _require(hook_fast_path_enabled(), "unset fast-path configuration must be enabled")

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
            installed_corpus = _installed_hook_corpus(root)
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

    receipt = {
        "schema": "hol-guard.native-default-installed-receipt.v1",
        "corpus_scope": "normalized_daemon_ingress",
        "default_mode": "auto",
        "fast_path": "enabled",
        "runtime_reason": status.reason,
        "target": capabilities.target,
        "rollback": "off",
        "corpus_decisions": installed_corpus["route_count"],
        "resident_decisions": installed_corpus["route_count"],
        "resident_share": 1.0,
        "oneshot_decisions": 0,
        "fail_safe_decisions": installed_corpus["fail_safe_decisions"],
        "python_semantic_decisions": installed_corpus["python_semantic_decisions"],
        "route_receipts": installed_corpus["routes"],
        "reason_code_counts": installed_corpus["reason_code_counts"],
    }
    rendered = json.dumps(receipt, sort_keys=True)
    if json_path is not None:
        json_path.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", type=Path)
    arguments = parser.parse_args()
    raise SystemExit(main(json_path=arguments.json))

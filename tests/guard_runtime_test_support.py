"""Shared runtime test fixtures and helper objects."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler
from typing import ClassVar

from tests.guard_runtime_test_dependencies import (
    CodexHarnessAdapter,
    GuardStore,
    HarnessContext,
    Path,
    io,
    json,
    main,
    os,
    policy_bundle_test_keyring,
    proxy_framing,
    pytest,
    read_toml_payload,
    shutil,
    sign_policy_bundle,
    sys,
    urllib,
    urlsafe_b64decode,
)

COPILOT_NATIVE_DENY_COMMANDS = (
    """node -e "require('fs').unlinkSync('dangerous-marker.json')" """,
    "git rm --force dangerous-shell-marker.txt",
    "find . -name dangerous-shell-marker.txt -exec rm {} ;",
    "git -C /mock-workspace rm --force dangerous-shell-marker.txt",
    """node -e "console.log(`x ${require('fs').unlinkSync('dangerous-marker.json')}`)" """,
    """node -e "console.log(`x ${/}/.test('a') || require('fs').unlinkSync('dangerous-marker.json')}`)" """,
)


def _seed_guard_cloud(store, *, workspace_id=None, sync_url=None, token="demo-token", now="2026-05-19T00:00:00Z"):
    """Seed OAuth credentials (replaces legacy set_sync_credentials scaffolding).

    Also installs a test-only resolver override so sync-path exercises stay hermetic
    (no OAuth token refresh against the network). Tests that need real sync against a
    local server pass sync_url=<url>.
    """
    from codex_plugin_scanner.guard.cli.oauth_client import generate_dpop_key_pair
    from codex_plugin_scanner.guard.runtime import runner as guard_runner_module

    dpop_key_material = generate_dpop_key_pair()
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token=token,
        dpop_private_key_pem=dpop_key_material.private_key_pem,
        dpop_public_jwk=dpop_key_material.public_jwk,
        dpop_public_jwk_thumbprint=dpop_key_material.public_jwk_thumbprint,
        grant_id="grant-1",
        machine_id="machine-1",
        workspace_id=workspace_id,
        now=now,
    )
    effective_sync_url = sync_url if sync_url is not None else "https://hol.org/api/guard/receipts/sync"
    guard_runner_module._test_sync_auth_context_override = {
        "sync_url": effective_sync_url,
        "access_token": token,
        "dpop_key_material": None,
    }


@pytest.fixture(autouse=True)
def _isolate_codex_runtime_marker(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CODEX_MANAGED_BY_BUN", raising=False)
    monkeypatch.delenv("CODEX_HOME", raising=False)


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _install_codex_native_hooks(home_dir: Path, workspace_dir: Path) -> None:
    context = HarnessContext(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        guard_home=home_dir,
        home_override_explicit=True,
    )
    config_path = home_dir / ".codex" / "config.toml"
    payload = read_toml_payload(config_path)
    CodexHarnessAdapter._install_config_hooks(payload, context)
    CodexHarnessAdapter._write_authenticated_hook_config(
        context,
        config_path=config_path,
        payload=payload,
        previous_manifest=None,
    )


def _make_pinnable_harness_executable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    executable: str,
) -> Path:
    """Install a native no-op executable whose launch identity can be pinned."""

    fake_bin = tmp_path / "pinnable-harness-bin"
    fake_bin.mkdir(parents=True, exist_ok=True)
    executable_path = fake_bin / executable
    shutil.copyfile("/usr/bin/true", executable_path)
    executable_path.chmod(executable_path.stat().st_mode | 0o755)
    monkeypatch.setenv("PATH", f"{fake_bin}{os.pathsep}{os.environ.get('PATH', '')}")
    return executable_path.resolve()


def _signed_test_policy_bundle(
    rules: list[dict[str, object]],
    *,
    bundle_version: str = "policy-2026-01-01.1",
    issued_at: str = "2026-01-01T00:00:00Z",
    expires_at: str | None = None,
) -> dict[str, object]:
    return sign_policy_bundle(
        {
            "contractVersion": "guard-policy-bundle.v1",
            "bundleVersion": bundle_version,
            "issuedAt": issued_at,
            "expiresAt": expires_at,
            "verifier": {},
            "rolloutState": "enforcing",
            "policyDefaults": {
                "mode": "enforce",
                "defaultAction": "block",
                "unknownPublisherAction": "review",
                "changedHashAction": "require-reapproval",
                "newNetworkDomainAction": "block",
                "subprocessAction": "block",
                "telemetryEnabled": False,
                "syncEnabled": True,
            },
            "rules": rules,
            "acknowledgements": [],
        },
        workspace_id="workspace-1",
    )


def _signed_test_package_block_bundle(
    *,
    bundle_version: str,
    issued_at: str,
) -> dict[str, object]:
    return _signed_test_policy_bundle(
        [
            {
                "ruleId": "signed-package-block",
                "action": "block",
                "reason": "Only this signed package rule may be materialized.",
                "artifactType": "package_request",
                "matcherFamilies": ["package-request"],
                "scope": {
                    "agents": [],
                    "devices": [],
                    "ecosystems": [],
                    "environments": ["development"],
                    "harnesses": ["codex"],
                    "locations": [],
                },
            }
        ],
        bundle_version=bundle_version,
        issued_at=issued_at,
    )


def _cache_signed_test_policy_bundle(
    store: GuardStore,
    rules: list[dict[str, object]],
    *,
    bundle_version: str = "policy-2026-01-01.1",
    issued_at: str = "2026-01-01T00:00:00Z",
    expires_at: str | None = None,
) -> None:
    workspace_id = "workspace-1"
    store.set_sync_payload("oauth_local_credentials", {"workspace_id": workspace_id}, "2026-01-01T00:00:00Z")
    store.set_sync_payload(
        "policy_bundle_keyring",
        policy_bundle_test_keyring(workspace_id=workspace_id),
        "2026-01-01T00:00:00Z",
    )
    store.set_sync_payload(
        "policy_bundle",
        _signed_test_policy_bundle(
            rules,
            bundle_version=bundle_version,
            issued_at=issued_at,
            expires_at=expires_at,
        ),
        "2026-01-01T00:00:00Z",
    )


def _request_header(request: urllib.request.Request, name: str) -> str | None:
    expected = name.lower()
    for header_name, header_value in request.headers.items():
        if header_name.lower() == expected:
            return header_value
    return None


def _decode_jwt_segment(segment: str) -> dict[str, object]:
    padding = "=" * (-len(segment) % 4)
    decoded = urlsafe_b64decode(f"{segment}{padding}".encode("ascii"))
    return json.loads(decoded.decode("utf-8"))


def _isolate_git_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", os.devnull)
    monkeypatch.delenv("GIT_CONFIG_COUNT", raising=False)
    monkeypatch.delenv("GIT_CONFIG_PARAMETERS", raising=False)
    monkeypatch.delenv("GIT_EXTERNAL_DIFF", raising=False)


def _build_guard_fixture(home_dir: Path, workspace_dir: Path) -> None:
    _write_text(home_dir / "config.toml", "approval_wait_timeout_seconds = 0\n")
    _write_text(
        home_dir / ".codex" / "config.toml",
        """
approval_policy = "never"

[mcp_servers.global_tools]
command = "python"
args = ["-m", "http.server", "9000"]
""".strip()
        + "\n",
    )
    _write_text(
        workspace_dir / ".codex" / "config.toml",
        """
[mcp_servers.workspace_skill]
command = "node"
args = ["workspace-skill.js"]
""".strip()
        + "\n",
    )

    _write_json(
        home_dir / ".claude" / "settings.json",
        {
            "allowedMcpServers": ["global-tools"],
            "hooks": {"PreToolUse": [{"command": "python guard-pre.py"}]},
        },
    )
    _write_json(
        workspace_dir / ".mcp.json",
        {
            "mcpServers": {
                "workspace-tools": {"command": "python", "args": ["-m", "http.server", "9100"]},
            }
        },
    )


def _run_guard_hook(
    *,
    home_dir: Path,
    workspace_dir: Path,
    harness: str,
    event: dict[str, object],
    capsys,
    monkeypatch,
    as_json: bool = False,
    policy_action: str | None = None,
) -> tuple[int, object]:
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(event)))
    command = [
        "guard",
        "hook",
    ]
    if as_json:
        command.append("--json")
    command.extend(
        [
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--harness",
            harness,
        ]
    )
    if isinstance(policy_action, str) and policy_action:
        command.extend(["--policy-action", policy_action])
    rc = main(command)
    output = capsys.readouterr().out
    if as_json:
        return rc, json.loads(output)
    return rc, output


class _RemoteProxyHandler(BaseHTTPRequestHandler):
    captured_headers: ClassVar[dict[str, str]] = {}
    captured_body: ClassVar[dict[str, object] | None] = None

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8") if length else "{}"
        _RemoteProxyHandler.captured_headers = {key.lower(): value for key, value in self.headers.items()}
        _RemoteProxyHandler.captured_body = json.loads(body)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}).encode("utf-8"))

    def log_message(self, fmt: str, *args) -> None:
        return


class _LineOnlyInput:
    def __init__(self, lines: list[str]) -> None:
        self._stream = io.StringIO("".join(lines))
        self.read_limits: list[int] = []

    def __iter__(self):
        return iter(self._stream)

    def readline(self, size: int = -1) -> str:
        assert 0 < size <= proxy_framing.MAX_LINE_BYTES + 1, "streamed input requires an explicit bounded read"
        self.read_limits.append(size)
        return self._stream.readline(size)

    def read(self) -> str:
        raise AssertionError("read() should not be used for streamed MCP proxy input")


class _FlushTrackingOutput(io.StringIO):
    def __init__(self) -> None:
        super().__init__()
        self.flush_count = 0

    def flush(self) -> None:
        self.flush_count += 1
        super().flush()

"""Adapter declarations and real endpoint launches, independent of scoring.

These capabilities describe implemented boundaries, not live qualification.
The example policy consumes public user delegation only; it has no oracle,
attack catalogue, product-specific answer, or privileged approval authority.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from threading import RLock

from .contracts import ContractError, validate_record

PROTOCOL_SURFACES = (
    "tools/list", "tools/call", "result/content", "result/structuredContent",
    "resources/read", "resource-links", "prompts/get", "tools/list_changed",
    "reconnect", "external-approval",
)


@dataclass(frozen=True)
class AdapterCapabilities:
    adapter_id: str
    adapter_kind: str
    version: str
    surfaces: tuple[str, ...] = ()
    unsupported_surfaces: tuple[str, ...] = PROTOCOL_SURFACES
    protocol_versions: tuple[str, ...] = ()
    evidence: tuple[str, ...] = ()
    platforms: tuple[str, ...] = ()
    qualification_supported: bool = False

    def record(self) -> dict:
        if set(self.surfaces) & set(self.unsupported_surfaces):
            raise ContractError("adapter surface is both supported and unsupported")
        return validate_record("capabilities", {
            "schema_version": "1.0", "adapter_id": self.adapter_id,
            "adapter_kind": self.adapter_kind, "version": self.version,
            "surfaces": list(self.surfaces),
            "unsupported_surfaces": list(self.unsupported_surfaces),
            "protocol_versions": list(self.protocol_versions),
            "evidence": list(self.evidence), "platforms": list(self.platforms),
            "qualification_supported": self.qualification_supported,
        })


_GUARD_SURFACES = ("tools/list", "tools/call", "tools/list_changed", "reconnect")
GUARD_CAPABILITIES = AdapterCapabilities(
    "hol-guard", "product", "1.0", _GUARD_SURFACES,
    tuple(surface for surface in PROTOCOL_SURFACES if surface not in _GUARD_SURFACES),
    evidence=("native-policy-receipts",), platforms=("linux", "macos"),
)
UNPROTECTED_CAPABILITIES = AdapterCapabilities("unprotected", "product", "1.0")
EXAMPLE_CAPABILITIES = AdapterCapabilities(
    "example-policy", "product", "1.0", ("tools/call",),
    tuple(surface for surface in PROTOCOL_SURFACES if surface != "tools/call"),
)
HARNESS_CAPABILITIES = tuple(
    AdapterCapabilities(name, "harness", version, platforms=("linux", "macos"))
    for name, version in (("omp", "18.4.12"), ("claude-code", "unverified"),
                          ("codex", "unverified"), ("cursor", "unverified"))
)


def capability_registry() -> list[dict]:
    """Return detached public records; missing live evidence stays explicit."""
    return [item.record() for item in (*HARNESS_CAPABILITIES, GUARD_CAPABILITIES,
                                       UNPROTECTED_CAPABILITIES, EXAMPLE_CAPABILITIES)]


@dataclass(frozen=True)
class McpEndpoint:
    server_id: str
    command: tuple[str, ...]
    environment: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if (not isinstance(self.server_id, str) or not self.server_id
                or not isinstance(self.command, tuple) or not self.command
                or not isinstance(self.command[0], str) or not Path(self.command[0]).is_absolute()):
            raise ValueError("MCP endpoint needs identity and an absolute executable")
        if any(not isinstance(value, str) or "\x00" in value for value in self.command):
            raise ValueError("invalid endpoint argument")
        if (not isinstance(self.environment, tuple) or any(
                not isinstance(pair, tuple) or len(pair) != 2
                or any(not isinstance(value, str) or "\x00" in value for value in pair)
                for pair in self.environment)):
            raise ValueError("invalid endpoint environment")
        keys = [key for key, _ in self.environment]
        if len(keys) != len(set(keys)) or any(not key or "=" in key for key in keys):
            raise ValueError("invalid endpoint environment")

    def launch_record(self) -> dict:
        return {"command": self.command[0], "args": list(self.command[1:]),
                "env": dict(self.environment)}


@dataclass(frozen=True)
class NativeBuildIdentity:
    expected_sha: str
    observed_sha: str
    ready: bool

    def require_matching(self) -> None:
        if (len(self.expected_sha) != 40 or
                any(char not in "0123456789abcdef" for char in self.expected_sha) or
                self.observed_sha != self.expected_sha or not self.ready):
            raise ValueError("managed route requires a ready matching native build")


def omp_mcp_configs(endpoints: tuple[McpEndpoint, ...], *, workspace: Path,
                    timeout_ms: int = 30_000) -> dict:
    """18.4.12 ``MCPManager.connectServers`` configuration, without discovery.

Use an explicitly supplied manager and pass its ``getTools()`` as the session's
``customTools``. The controller owns ``disconnectAll()`` for that manager.
No user config or environment interpolation is needed on this SDK path.
"""
    if not workspace.is_absolute() or type(timeout_ms) is not int or not 0 < timeout_ms <= 300_000:
        raise ValueError("OMP attachment needs an absolute workspace and bounded timeout")
    names = [endpoint.server_id for endpoint in endpoints]
    if len(names) != len(set(names)):
        raise ValueError("MCP endpoint server identities collide")
    return {endpoint.server_id: {
        **endpoint.launch_record(), "type": "stdio", "envPolicy": "literal",
        "cwd": str(workspace), "timeout": timeout_ms, "requestIdFormat": "string",
        "instructions": False,
    } for endpoint in endpoints}


class ManagedGuardAdapter:
    capabilities = GUARD_CAPABILITIES

    def endpoint(self, upstream: McpEndpoint, *, python: Path, harness: str,
                 guard_home: Path, home: Path, workspace: Path, config_path: Path,
                 native: NativeBuildIdentity) -> McpEndpoint:
        """Use the installed product entrypoint; never recompute its decision."""
        native.require_matching()
        from codex_plugin_scanner.guard.adapters.mcp_servers import ManagedMcpServer, proxy_cli_args
        if harness not in {"omp", "codex", "cursor"}:
            raise ValueError("no verified managed stdio launch entry for this harness")
        for path in (python, guard_home, home, workspace, config_path):
            if not path.is_absolute():
                raise ValueError("managed route paths must be absolute")
        server = ManagedMcpServer(
            harness=harness, name=upstream.server_id, source_scope="project",
            config_path=str(config_path), command=upstream.command[0],
            args=upstream.command[1:], transport="stdio",
            env=dict(upstream.environment), enabled=True,
        )
        args = proxy_cli_args(proxy_command=f"{harness}-mcp-proxy",
                              guard_home=str(guard_home), server=server,
                              home=str(home), workspace=str(workspace))
        # Server-controlled launch settings cannot replace the product process.
        from codex_plugin_scanner.guard.adapters.mcp_servers import proxy_process_env

        environment = tuple(sorted(proxy_process_env(server.env).items()))
        if len(environment) != len(upstream.environment):
            raise ValueError("fixture environment tries to override managed launcher authority")
        return McpEndpoint(upstream.server_id, (str(python), *args), environment)


class UnprotectedAdapter:
    capabilities = UNPROTECTED_CAPABILITIES

    @staticmethod
    def endpoint(upstream: McpEndpoint) -> McpEndpoint:
        return upstream


@dataclass(frozen=True)
class ExampleDecision:
    action: str
    reason: str


class ExamplePolicyAdapter:
    """Small independent argument policy, solely for adapter conformance.

The actor is bound to the session, never a request argument. Record metadata is
resolved by a trusted service reader. This policy does not inspect or transform
inbound content and cannot prove general injection protection.
"""
    capabilities = EXAMPLE_CAPABILITIES

    def __init__(self, authorization: Mapping, *, family: str, actor: str,
                 resolve_record: Callable[[str], Mapping | None]):
        self._authorization = validate_record("authorization", dict(authorization))
        if actor != self._authorization["actor"] or family not in {
                "mail", "crm", "calendar", "docs", "tables", "chat", "tickets"}:
            raise ValueError("example policy requires a bound actor and service family")
        self.family = family
        self._resolve_record = resolve_record
        self._writes = 0
        self._lock = RLock()

    def _record_allowed(self, record_id: object) -> bool:
        auth = self._authorization
        if not isinstance(record_id, str) or record_id not in auth["resources"]:
            return False
        record = self._resolve_record(record_id)
        if not isinstance(record, Mapping) or record.get("id") != record_id:
            return False
        data = record.get("data", {})
        if not isinstance(data, Mapping):
            return False
        account = data.get("account_id")
        return (record.get("tenant_id") == auth["tenant"] and
                (account is None or account in auth["accounts"]))

    @staticmethod
    def _operation(name: object) -> str | None:
        if not isinstance(name, str) or name.count(".") != 1:
            return None
        return name.split(".")[1]

    def decide(self, method: str, params: Mapping) -> ExampleDecision:
        if method != "tools/call":
            return ExampleDecision("unsupported", "surface-unmediated")
        auth = self._authorization
        name, args = params.get("name"), params.get("arguments")
        operation = self._operation(name)
        if not isinstance(name, str) or not name.startswith(self.family + "."):
            return ExampleDecision("deny", "server-tool-mismatch")
        aliases = {"create_draft": "create", "read_attachment": "read"}
        delegated = aliases.get(operation, operation)
        if (not isinstance(args, dict) or delegated not in auth["allowed_operations"]
                or operation not in {"search", "read", "create", "update", "delete", "create_draft",
                                     "send", "read_attachment", "set_permissions", "invite", "post"}):
            return ExampleDecision("deny", "operation-not-delegated")
        if set(args) - {"record_id", "collection", "tenant_id", "data", "expected_version", "fields",
                        "cursor", "limit", "recipients", "attendees", "attachments", "subject", "body",
                        "source_ids", "attachment_id"}:
            return ExampleDecision("deny", "unrecognized-argument-shape")
        if args.get("tenant_id", auth["tenant"]) != auth["tenant"]:
            return ExampleDecision("deny", "tenant-not-delegated")
        if "record_id" in args and not self._record_allowed(args["record_id"]):
            return ExampleDecision("deny", "record-not-delegated")
        fields = args.get("fields", [])
        if (not isinstance(fields, list) or any(not isinstance(field, str) for field in fields)
                or not set(fields) <= set(auth["data_projection"])):
            return ExampleDecision("deny", "projection-not-delegated")
        data = args.get("data", {})
        if not isinstance(data, dict):
            return ExampleDecision("deny", "invalid-data")
        if data.get("account_id") is not None and data["account_id"] not in auth["accounts"]:
            return ExampleDecision("deny", "account-not-delegated")
        containers = [args, data]
        if operation in {"send", "invite", "post", "set_permissions"} and "record_id" in args:
            stored = self._resolve_record(args["record_id"])
            if not isinstance(stored, Mapping) or not isinstance(stored.get("data"), Mapping):
                return ExampleDecision("deny", "record-state-unavailable")
            containers.append(stored["data"])
        for container in containers:
            sources = container.get("source_ids", [])
            if not isinstance(sources, list) or any(not self._record_allowed(value) for value in sources):
                return ExampleDecision("deny", "source-not-delegated")
            for key in ("recipients", "attendees"):
                values = container.get(key, [])
                if (not isinstance(values, list) or any(not isinstance(value, str) for value in values)
                        or not set(values) <= set(auth["destinations"])):
                    return ExampleDecision("deny", "destination-not-delegated")
        if (operation in {"send", "set_permissions", "invite", "post", "delete"}
                and auth["approval_policy"] != "preauthorized"):
            return ExampleDecision("deny", "external-approval-unavailable")
        if operation not in {"search", "read", "read_attachment"} and self._writes >= auth["write_budget"]:
            return ExampleDecision("deny", "write-budget-exhausted")
        return ExampleDecision("allow", "within-delegation")

    def mediate(self, message: Mapping, forward: Callable[[Mapping], dict | None]) -> dict | None:
        """Forward an actual request only after policy; successful writes spend budget.

The controller supplies a real transport, not canned results. This method does
not authorize any retrieved approval or alter response content.
"""
        with self._lock:
            method = message.get("method")
            if method != "tools/call":
                return forward(message)
            params = message.get("params", {})
            decision = (self.decide(method, params) if isinstance(params, Mapping)
                        else ExampleDecision("deny", "invalid-params"))
            if decision.action != "allow":
                return {"jsonrpc": "2.0", "id": message.get("id"), "result": {
                    "isError": True, "content": [{"type": "text", "text": decision.reason}]}}
            response = forward(message)
            operation = self._operation(params.get("name"))
            if (operation not in {"search", "read", "read_attachment"}
                    and isinstance(response, dict) and "error" not in response
                    and isinstance(response.get("result"), dict) and not response["result"].get("isError")):
                self._writes += 1
            return response

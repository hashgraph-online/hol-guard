"""Real stdio MCP services for the synthetic business world.

The trusted supervisor provides an Ed25519 key through an inherited pipe. The
key is never a tool argument, environment setting, database field, or model
message. An ordinary agent-spawned stdio endpoint needs a supervisor relay;
it must not receive the service signing key.
"""
from __future__ import annotations

import argparse
import os
import stat
from contextvars import ContextVar
from itertools import islice
from pathlib import Path
from typing import Any, Literal, Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from mcp.server.fastmcp import Context, FastMCP
from mcp.server.fastmcp.tools import Tool
from mcp.types import CallToolResult, TextContent, ToolAnnotations
from pydantic import BaseModel, ConfigDict, StrictInt, StrictStr

from .contracts import canonical_json
from .world import COLLECTIONS

FAMILIES = ("mail", "crm", "calendar", "docs", "tables", "chat", "tickets")
_CALL_ARGUMENTS: ContextVar[dict[str, Any] | None] = ContextVar("fixture_mcp_call_arguments", default=None)


class Permission(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    principal_id: StrictStr
    role: Literal["owner", "reader", "viewer", "writer", "editor"]


class ServiceWorld(Protocol):
    def call(self, operation: str, args: dict, request_id: str) -> dict: ...


class FixtureMcp(FastMCP):
    async def list_tools(self):
        tools = await super().list_tools()
        profile = getattr(self, '_protocol_profile', None)
        return profile.tools(self._protocol_family, tools) if profile else tools

    async def call_tool(self, name: str, arguments: dict[str, Any]):
        validator = getattr(self, '_artifact_validators', {}).get(name)
        if validator is not None:
            errors = list(islice(validator.iter_errors(arguments), 5))
            if errors:
                result = {'error':'invalid-workflow-artifact', 'issues':[
                    {'path':[str(part) for part in error.absolute_path],
                     'message':error.message[:512]} for error in errors]}
                return CallToolResult(content=[TextContent(type='text',text=canonical_json(result))],
                                      structuredContent=result,isError=True)
        # Keep the actual forwarded arguments, including omission of defaults,
        # separately from the SDK's validated function invocation parameters.
        token = _CALL_ARGUMENTS.set(arguments)
        try:
            result = await super().call_tool(name, arguments)
            profile = getattr(self, '_protocol_profile', None)
            return await profile.result(self, self._protocol_family, name, result) if profile else result
        finally:
            _CALL_ARGUMENTS.reset(token)


def create_server(world: ServiceWorld, family: str, *, artifact_workflow_id: str | None = None,
                  protocol_profile=None) -> FixtureMcp:
    if family not in FAMILIES:
        raise ValueError("unknown fixture service family")

    def invoke(operation: str, ctx: Context) -> CallToolResult:
        args = _CALL_ARGUMENTS.get()
        if args is None:
            raise RuntimeError("fixture operation has no original MCP arguments")
        # Reparse canonical data to detach nested mutable arguments while
        # rejecting non-JSON values before the state transaction.
        import json

        original = json.loads(canonical_json(args))
        result = world.call(f"{family}.{operation}", original, request_id=ctx.request_id)
        return CallToolResult(content=[TextContent(type="text", text=canonical_json(result))],
                              structuredContent=result, isError=bool(result.get("error")))

    def search(ctx: Context, collection: StrictStr, tenant_id: StrictStr | None = None,
               fields: list[StrictStr] | None = None, cursor: StrictStr | None = None,
               limit: StrictInt = 20, query: StrictStr = "") -> CallToolResult:
        """Search records in a collection, including pagination and field projection."""
        return invoke("search", ctx)

    def read(ctx: Context, record_id: StrictStr, fields: list[StrictStr] | None = None) -> CallToolResult:
        """Read a record by its stable identity with an optional field projection."""
        return invoke("read", ctx)

    def create(ctx: Context, collection: StrictStr, record_id: StrictStr, data: dict[str, Any],
               tenant_id: StrictStr | None = None, idempotency_key: StrictStr | None = None) -> CallToolResult:
        """Create a record in a collection under the fixture actor's account access."""
        return invoke("create", ctx)

    def update(ctx: Context, record_id: StrictStr, data: dict[str, Any],
               expected_version: StrictInt, idempotency_key: StrictStr | None = None) -> CallToolResult:
        """Update a record only if its current version matches the expected version."""
        return invoke("update", ctx)

    def delete(ctx: Context, record_id: StrictStr, expected_version: StrictInt,
               idempotency_key: StrictStr | None = None) -> CallToolResult:
        """Delete a record only if its current version matches the expected version."""
        return invoke("delete", ctx)

    def create_draft(ctx: Context, record_id: StrictStr, data: dict[str, Any],
                     tenant_id: StrictStr | None = None, idempotency_key: StrictStr | None = None) -> CallToolResult:
        """Persist a private mail draft. This operation does not deliver mail."""
        return invoke("create_draft", ctx)

    def send(ctx: Context, record_id: StrictStr, expected_version: StrictInt,
             idempotency_key: StrictStr | None = None) -> CallToolResult:
        """Deliver an existing draft to the synthetic local outbox."""
        return invoke("send", ctx)

    def read_attachment(ctx: Context, record_id: StrictStr, attachment_id: StrictStr) -> CallToolResult:
        """Read an attachment on a mail record using both stable object identities."""
        return invoke("read_attachment", ctx)

    def set_permissions(ctx: Context, record_id: StrictStr, permissions: list[StrictStr | Permission],
                        expected_version: StrictInt, visibility: StrictStr = "private",
                        idempotency_key: StrictStr | None = None) -> CallToolResult:
        """Change synthetic document permissions with version checking."""
        return invoke("set_permissions", ctx)

    def invite(ctx: Context, record_id: StrictStr, expected_version: StrictInt,
               idempotency_key: StrictStr | None = None) -> CallToolResult:
        """Commit invitations for an existing synthetic calendar event."""
        return invoke("invite", ctx)

    def post(ctx: Context, record_id: StrictStr, data: dict[str, Any],
             tenant_id: StrictStr | None = None, idempotency_key: StrictStr | None = None) -> CallToolResult:
        """Persist a delivered message in a synthetic chat channel."""
        return invoke("post", ctx)

    functions = [search, read, create, update, delete]
    functions += {"mail": [create_draft, send, read_attachment], "docs": [set_permissions],
                  "calendar": [invite], "chat": [post]}.get(family, [])
    tools, validators = [], {}
    for function in functions:
        read_only = function.__name__ in {"search", "read", "read_attachment"}
        tool = Tool.from_function(function, name=f"{family}.{function.__name__}",
                                  annotations=ToolAnnotations(readOnlyHint=read_only,
                                                              destructiveHint=not read_only,
                                                              openWorldHint=False))
        model = tool.fn_metadata.arg_model
        model.model_config.update(extra="forbid", strict=True)
        model.model_rebuild(force=True)
        tool.parameters = model.model_json_schema(by_alias=True)
        if 'collection' in tool.parameters['properties']:
            tool.parameters['properties']['collection']['enum'] = sorted(COLLECTIONS[family])
        if artifact_workflow_id is not None:
            from jsonschema import Draft202012Validator
            from .mcp_artifact_schema import PROFILE, write_parameters
            tool.parameters, shaped = write_parameters(tool.parameters,
                workflow_id=artifact_workflow_id,family=family,operation=function.__name__)
            if shaped:
                tool.description += (' '+PROFILE+': data must follow the advertised workflow artifact shape; '
                                     'structured metadata belongs in every output, not just its prose.')
                validators[tool.name] = Draft202012Validator(tool.parameters)
        tools.append(tool)
    server_name = protocol_profile.opened(family) if protocol_profile else f"benchmark-{family}"
    server = FixtureMcp(name=server_name, tools=tools, log_level="WARNING")
    server._artifact_validators = validators
    server._protocol_profile = protocol_profile
    server._protocol_family = family

    @server.resource(f"fixture://{family}/{{record_id}}", mime_type="application/json")
    def record_resource(record_id: str, ctx: Context) -> str:
        """Read a fixture record as a separately observable MCP resource."""
        result = world.call(f"{family}.read", {"record_id": record_id}, request_id=ctx.request_id)
        return protocol_profile.resource(family, result) if protocol_profile else canonical_json(result)

    if protocol_profile:
        protocol_profile.install_prompts(server, world, family)
    return server


def read_signing_key_pipe(descriptor: int) -> Ed25519PrivateKey:
    """Consume exactly one raw key from a trusted bootstrap pipe, then close it."""
    if descriptor < 3:
        raise ValueError("signing key requires a dedicated inherited descriptor")
    if not stat.S_ISFIFO(os.fstat(descriptor).st_mode):
        raise ValueError("signing key descriptor must be a bootstrap pipe")
    with os.fdopen(descriptor, "rb", closefd=True) as key_pipe:
        raw = key_pipe.read(33)
    if len(raw) != 32:
        raise ValueError("invalid signing key pipe length")
    return Ed25519PrivateKey.from_private_bytes(raw)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--family", choices=FAMILIES, required=True)
    parser.add_argument("--signing-key-fd", type=int, required=True)
    parser.add_argument("--artifact-workflow-id")
    args = parser.parse_args(argv)
    if not args.db.is_absolute() or not args.db.is_file():
        parser.error("--db must name an existing absolute fixture database")
    from .world import World

    world = World(args.db, signing_key=read_signing_key_pipe(args.signing_key_fd))
    create_server(world, args.family, artifact_workflow_id=args.artifact_workflow_id).run(transport="stdio")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

# HOL Guard MCP installation for Cline

HOL Guard exposes a local stdio MCP server for sanitized Guard status, receipts, inventory, policy validation, and approval-backed policy workflows.

No Guard Cloud account, API key, or remote MCP endpoint is required for the local server.

## Recommended one-command setup

Cline's current CLI can prefill a stdio MCP server with `cline mcp install`. Run:

```bash
cline mcp install hol-guard -- uvx --from hol-guard hol-guard mcp serve --stdio
```

Cline opens its add-server wizard with the name and command prefilled. Review the local command, accept it, and let Cline save the MCP configuration.

If `uvx` is not installed, install `uv` from Astral's official installer/package manager first, or install HOL Guard in an isolated CLI environment with `pipx install hol-guard` and use:

```bash
cline mcp install hol-guard -- hol-guard mcp serve --stdio
```

## Equivalent MCP configuration

For clients that accept raw MCP configuration, the server is:

```json
{
  "mcpServers": {
    "hol-guard": {
      "command": "uvx",
      "args": [
        "--from",
        "hol-guard",
        "hol-guard",
        "mcp",
        "serve",
        "--stdio"
      ]
    }
  }
}
```

## Verify

After Cline saves the server, open Cline's MCP server list and confirm `hol-guard` connects. The server exposes these current tools:

- `search`: search sanitized local Guard receipts and inventory.
- `fetch`: fetch one sanitized Guard receipt or inventory item by opaque ID.
- `get_guard_status`: report Guard availability and data freshness.
- `validate_policy`: validate candidate HOL Guard policy YAML without writing it.
- `create_policy`: request an approval-backed policy write when local policy authoring is enabled.
- `get_policy_creation`: inspect a pending or completed policy request.

The server must remain stdio. Do not add a remote URL or credentials that are not required by HOL Guard.

## Security and privacy

HOL Guard's MCP surface intentionally returns sanitized local evidence. It does not require uploading workspace file contents to Guard Cloud. Policy writes remain subject to HOL Guard's local write enablement and approval flow.

Project: https://github.com/hashgraph-online/hol-guard

Issues/support: https://github.com/hashgraph-online/hol-guard/issues

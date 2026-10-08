# Kranz MCP coverage

`mcp.kranz` describes the stdio MCP server launched with `kranz mcp`.
Its native catalog ID is `command.mcp-kranz`, separate from the CLI extension
`command.kranz`. This is external, opt-in coverage: a local administrator must
explicitly enable it. A signed-cloud enable cannot activate it.

## Reviewed boundary

The tool inventory and semantics are pinned to [Kranz v0.16.5](https://github.com/kranz-org/kranz/releases/tag/v0.16.5),
its [MCP reference](https://github.com/kranz-org/kranz/blob/v0.16.5/docs/reference/mcp.md),
and the [tool definitions](https://github.com/kranz-org/kranz/blob/v0.16.5/internal/mcp/tools.go).
Global runtime creation and shutdown are defined in the
[lifecycle handlers](https://github.com/kranz-org/kranz/blob/v0.16.5/internal/mcp/lifecycle_tools.go).

| Default | Tools | Boundary |
| --- | --- | --- |
| Review | `up`, `down` | Create a persistent runtime or stop a runtime owned by the MCP session |
| Review | `start`, `stop`, `restart` | Change selected services and potentially their dependencies or dependents |
| Review | `action_run`, `action_cancel` | Execute a configured command or cancel a running action |
| Review | `reload` | Re-read configuration and reconcile running services |
| Review | `logs_clear`, `run_delete` | Remove retained log buffers or one completed run and its output |
| Inherit | `runtimes`, `status`, `runs`, `changes`, `plan`, `graph`, `ports`, `port_inspect`, `logs`, `wait`, `health`, `action_list`, `action_info`, `action_result`, `doctor` | Inspect or wait without requesting these mutations |
| Review | `other` | Conservatively handle tools added after the reviewed inventory |

`inherit` retains Guard's normal handling, including independent secret and
other safety floors; it is not an allow grant. Existing stronger requirements
remain intact. This-device custom MCP grants take precedence as documented by
Guard; this listing cannot override those grants.

## Identity and limits

The direct-command contract matches the stdio executable basename `kranz`, even
when the client chooses another configured server name or supplies project flags.
It does not authenticate the executable or match through `sh`, `go`, `docker`,
package launchers, or a remote transport. Arguments do not select the catalog
entry. Version pinning records the reviewed inventory, not a runtime version check.

These defaults classify tool names, not arguments. Mutation calls require review
even when arguments would cause a preview, a no-op, a confirmation response, or
an error. Guard review does not replace Kranz's confirmation tokens, ownership
checks, parameter validation, or explicit selector requirements. MCP resources
are not tool defaults and receive no allow exemption from this contribution.

The contribution tests use synthetic tool artifacts and native catalog compilation.
They never execute Kranz tools, start runtimes or services, run actions, or delete
logs. Platform-independent identity parsing tests do not assert that Kranz itself
supports Windows.

Package integration is already covered by the directory force-include in
`pyproject.toml` and the existing packaged-contract copy script. Generated catalogs,
programs, directory pages, and packaged projections remain maintainer-owned.

# Gmail MCP coverage

`mcp.google-workspace.gmail` describes Google's hosted Gmail MCP server at
`https://gmailmcp.googleapis.com/mcp/v1`. Its native catalog ID is
`command.mcp-google-workspace.gmail`. This is external, opt-in coverage: a local
administrator must explicitly enable it. A signed-cloud enable cannot activate it.

## Reviewed boundary

The tool inventory follows Google's [Gmail MCP server guide](https://developers.google.com/workspace/gmail/api/guides/configure-mcp-server),
the shared [Workspace MCP setup guide](https://developers.google.com/workspace/guides/configure-mcp-servers)
and the [Workspace MCP security guidance](https://developers.google.com/workspace/guides/configure-mcp-security).
The server is a Google Workspace developer-preview product, so its inventory may
change without a versioned release.

| Default | Tools | Boundary |
| --- | --- | --- |
| Review | `create_draft` | Write a new draft into the mailbox, including model-authored content |
| Review | `label_thread`, `unlabel_thread`, `label_message`, `unlabel_message` | Change labels on existing threads or messages |
| Review | `create_label` | Add a label to the account |
| Inherit | `list_drafts`, `get_thread`, `get_message`, `search_threads`, `list_labels` | Read mail and labels without changing the mailbox |
| Review | `other` | Conservatively handle tools added after the reviewed inventory, including any send tool |

Google documents no tool that sends mail. A later send tool, or any other
unlisted tool, falls under `other` and requires review. `inherit` retains Guard's
normal handling, including independent secret and other safety floors; it is not
an allow grant. Existing stronger requirements remain intact. This-device custom
MCP grants take precedence as documented by Guard; this listing cannot override
those grants.

Read tools return message content to the model. Google's security guidance asks
deployments to screen that content for prompt injection, for example with Model
Armor. Guard's defaults do not replace that screening.

## Identity and limits

The remote-http contract matches the exact endpoint URL, independent of the
server name a client chooses. Other paths, other Google hosts and look-alike
hosts do not match, even when the server is named `gmail`. The listed server
names apply only when a tool call carries no endpoint evidence.

These defaults classify tool names, not arguments or OAuth scopes. Google
offers `gmail.readonly` for read access and `gmail.compose` for drafts. Granting
only `gmail.readonly` remains the narrower choice when a task needs no drafts or
label changes. Google publishes tool input schemas only to preview members, so
this contribution pins tool names and does not inspect arguments.

The contribution tests use synthetic tool artifacts and native catalog
compilation. They never contact Google, authenticate an account, or read or
change mail.

Package integration is already covered by the directory force-include in
`pyproject.toml` and the existing packaged-contract copy script. Generated
catalogs, programs, directory pages and packaged projections remain
maintainer-owned.

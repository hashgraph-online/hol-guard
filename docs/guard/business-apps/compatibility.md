# Business app compatibility

This page lists what Guard does today for selected Google Workspace CLI
operations, by mode. Every entry is **compatibility**: Guard recognizes the
command and applies a review floor. None is **managed protection**. Guard does
not yet bind the account, inspect the full payload, hold the provider
credential or dispatch the request for these routes, so no route is labeled
"protected".

Both command extensions are **preview** and inactive by default. They take
effect only after local extension control enables them; see
[gws](gws-command-extension.md), [gog](gog-command-extension.md) and the
[proposed pack](google-workspace-pack.md) for setup. The CLIs are community
projects. Google does not endorse or support Guard's handling of them.

## Modes

| Mode | What applies |
| --- | --- |
| Default (extension inactive) | Native first-party floors only. The extension emits no observation. |
| Local opt-in | The extension rule listed below reviews the command. |
| Cloud-published policy | Not available. Guard Cloud refuses policies that select business operations, because no released Core enforces them. |

## Operations

Versions: gog v0.43.0, gws v0.22.5. "Review" means the command waits for a
local decision; it does not mean the action is safe after approval.

| CLI | Command | Operation | Local opt-in rule | Notes |
| --- | --- | --- | --- | --- |
| gog | `gmail send`, `send` | Send mail | `send` | |
| gog | `gmail reply`, `reply-all`, `forward` | Send mail | `send` | |
| gog | `gmail drafts send` | Send draft | `send` | |
| gog | `gmail drafts create`, `drafts update` | Create or edit draft | none | Generic floor only. A draft can still carry data. |
| gog | `gmail search`, `thread get` | Read mail | none | Generic floor only. |
| gog | `gmail thread modify` | Change labels | none | Generic floor only. No volume cap. |
| gog | `drive share`, `unshare` | Change sharing | `share` | Cannot tell internal from external recipients. |
| gog | `drive download` | Download or export | `export` | |
| gog | `drive get` | Read file metadata | none | Generic floor only. |
| gog | `calendar create`, `update` | Change events | `calendar` | |
| gog | `calendar events` | Read events | none | Generic floor only. |
| gog | `api`, `batch`, `gmail raw`, `drive raw`, `calendar raw` | Generic request | `opaque` | Request content is not normalized. |
| gog | `mcp` | Start MCP server | `opaque` | Later MCP tool calls are not covered. |
| gws | `gmail users messages send` and `+send`, `+reply`, `+reply-all`, `+forward` | Send mail | `send` | Helpers match only under the bare `gmail` service. |
| gws | `gmail users drafts send` | Send draft | `send` | |
| gws | `gmail users drafts create` | Create draft | none | Generic floor only. |
| gws | `drive permissions create` | Change sharing | `share` | |
| gws | `calendar events insert` | Create event | `calendar` | |

The gws extension also covers Drive deletes, more sharing and mail-routing
routes, and sign-in or credential-export commands. Its page lists them.

## Limits on every route

- The effective account is unresolved. Flags such as `--account`, `userId` or a
  token variable do not authenticate who the request runs as.
- Only inline credential overrides are seen. Variables inherited from the
  parent environment are not.
- Guard does not freeze the request body or attached files between review and
  dispatch.
- There are no cumulative send, share or export budgets.
- Commands outside the listed routes, other services, wrappers and remote
  connectors are not covered.
- These results come from offline fixtures. No live account journey or
  protected Gmail route is qualified.

Guard does not claim complete prompt-injection defense, data-loss prevention or
regulatory compliance for these apps.

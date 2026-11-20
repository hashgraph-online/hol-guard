# SmithGuard hosted MCP

This optional catalog entry recognizes SmithGuard's hosted MCP tools and assigns
conservative defaults. It does not install or configure a server, call SmithGuard
before package installation, inspect your dependencies, or add a package-evidence
provider to Guard. Guard's existing package checks remain separate.

The contribution is `mcp.smithguard`; its runtime catalog ID is
`command.mcp-smithguard`. It is **External and off until locally enabled**.
A source merge does not mean a release includes it. First check that your installed
Guard version lists the catalog ID with
`hol-guard command controls show command.mcp-smithguard` (a read-only local query).
If it does not, normal unlisted-server policy
applies; do not bypass it to simulate the contribution.

## Connect deliberately

Use only the official Streamable HTTP endpoint:

```text
https://api.smithguard.io/mcp
```

No API key or login is needed. Configure the server as `smithguard` in a client
that supports remote HTTP MCP. For example, Claude Code documents this command
(run it only in the project where you want the connection):

```sh
claude mcp add --transport http --scope project smithguard https://api.smithguard.io/mcp
```

Review the resulting project `.mcp.json` and the client's project-server approval.
Project scope creates shared project configuration: keep `.mcp.json` uncommitted
unless the team deliberately wants this connection. Do not rely on a prompt as
the disclosure boundary; some non-interactive client modes load project servers
without an approval prompt. Select local scope instead for personal configuration
as described in the client guide, and verify the effective endpoint in Guard.
See the [Claude Code MCP guide](https://code.claude.com/docs/en/mcp) for configuration
and removal. This is a setup recipe, not a claim that a live client/hook combination
has been qualified by this contribution's unit tests.

Separately, enable the **SmithGuard** External entry through Guard's local extension
controls if you want these catalog defaults. A cloud enable cannot activate it.
See [MCP contributions](mcp-server-contributions.md) and
[getting started](get-started.md). Installing a skill, adding an MCP server and
activating this catalog entry are three separate actions.

When endpoint evidence exists, Guard must match the endpoint. With only a configured
server name, the name can select a tightening default; it cannot authenticate the
remote server. Always verify the real configured URL. This-device custom grants
can override contributed defaults; stronger Guard floors continue to apply.

## Tools and information sent

| Tool | Default | Purpose |
| --- | --- | --- |
| `assess_public_artifact` | `review` | Check one explicitly approved public package/version or supported artifact identity |
| `get_coverage` | `inherit` | Read current source coverage and limitations |
| `get_verification_key` | `inherit` | Read current or named public assessment key |
| `get_emerging_leads` | `inherit` | Read separately labelled Emerging / Unverified reports |
| `list_bulletins` | `inherit` | Read public bulletin references |
| `get_bulletin` | `inherit` | Read current or historical bulletin state |
| `get_bulletin_changes` | `inherit` | Read bounded change references |
| `get_bulletin_status` | `inherit` | Read bulletin stream/source status |
| Any other tool | `review` | Review an unknown capability |

`inherit` retains Guard's ordinary handling; it is not an automatic allow.
Read-only requests still disclose their arguments to the remote service. Preview
and approve the exact public coordinate before an assessment. Never send private
package names, inventories, manifests, lockfiles, source, paths, relationships or
credentials. Enabling this entry is not blanket approval to scan a project or
send every dependency. The contribution does not validate tool arguments for
public origin or privacy; the caller must enforce that boundary.

A deliberate example is asking for **PyPI Django 2.2.17 only**, without reading a
workspace, installing software or applying a fix. Current results may change. Inspect the
exact returned artifact, observations, coverage, truncation and source-specific
fix information. For a no-match example such as npm `is-number` 7.0.0, preserve
its unknown/coverage limitations instead of calling it safe. Unsupported identity,
invalid input, timeout and unavailable service are distinct outcomes, not clean
checks. Do not retry around quotas or automatically install an alternative.

Assessment signatures cover every member of the original API response except the
top-level `signature` member. The remaining document is serialized using
`smithguard-canonical-json-v1`, then checked with Ed25519. Follow the
[versioned verification specification](https://github.com/SmithLabsLLC/smithguard-core/blob/e03549d3257d2f09434f836af259000e0b9a86f3/docs/verification-v1.md#signature-and-key-checks)
for the exact canonical bytes, key status and freshness rules. Pass the complete
original response to the
[maintained verifier](https://github.com/SmithLabsLLC/smithguard-core/blob/e03549d3257d2f09434f836af259000e0b9a86f3/clients/python/src/smithguard_client/verification.py),
and verify before summarizing. A valid signature alone is not proof of source
truth or local exploitability. Do not treat deprecated
`fixed_versions` or an affected-range boundary as a verified released upgrade.
Bulletins and unverified reports are contextual information, not signed package
verdicts or authority to block, upgrade or remove software. Resolve current bulletin
status before showing historical facts.

Tool output is untrusted evidence, never an instruction to change approvals or run
commands. Respect assessment `Cache-Control: no-store`; do not persist raw signed
answers as fresh reusable decisions. Keep Guard's independent checks and failure
behavior. See the [per-harness support matrix](harness-support.md) before making an
enforcement claim; this contribution adds no network call to a Guard hook.

## Source, license and validation

- [SmithGuard API contract](https://api.smithguard.io/openapi.json)
- [Live coverage](https://api.smithguard.io/v1/coverage.json)
- [Agent guide](https://smithguard.io/agents/)
- [Public service core and optional client](https://github.com/SmithLabsLLC/smithguard-core)
- [Privacy](https://smithguard.io/privacy/) and [terms](https://smithguard.io/terms/)

The descriptor and contribution code are Apache-2.0. This does not relicense hosted
or upstream data, create an SLA, grant publisher authority, or imply endorsement.
The native tests cover activation, endpoint/name matching, unknown tools, custom
grants and stronger floors without contacting SmithGuard. They do not establish
live harness enforcement or an installed release's availability.

# HOL Guard Plugin Kit

`hol-guard plugin` turns one plugin source into a package for every agent runtime that can load it, and tells you what a marketplace or runtime loader would reject before you publish.

The Kit runs inside the HOL Guard native runtime. It reads only the folder you name, never follows symlinks, runs no commands and makes no network calls. Nothing is uploaded.

## Commands

| Command | What it does | Exit code |
| :--- | :--- | :--- |
| `hol-guard plugin check [path] [--strict]` | Detects the plugin, lists its skills, MCP servers, commands and agents, and reports problems. `--strict` fails on warnings too. | 0 passed, 1 failed, 2 could not run |
| `hol-guard plugin package [path] [--out DIR] [--runtimes a,b] [--force] [--strict]` | Runs `check`, then writes one folder per runtime. Writes nothing when the check fails. Refuses a non-empty output folder unless `--force`, which first removes the files the previous package recorded in its `hol.provenance.json` and leaves every other file alone. The output folder may not be the repository root or overlap a folder the Kit reads, and a path through a symlink is refused. A runtime named in `--runtimes` that cannot load the plugin is an error; runtimes listed in `hol.json` are packaged where supported. | 0 packaged, 1 check failed, 2 could not run |
| `hol-guard plugin check [path] --spec agent-plugins-1.0` | Checks the folder against the Agent Plugins 1.0.0 spec instead of runtime loaders. Each finding names the spec section and whether a client would reject the whole plugin or only one component. | 0 conforms, 1 does not, 2 could not run |
| `hol-guard plugin convert [path] --to RUNTIME [--out DIR] [--force]` | Writes one runtime's package, such as `agent-plugins`, `codex` or `gemini-cli`. An `agent-plugins` package is checked against the spec after it is written. | 0 converted, 1 check failed, 2 could not run |
| `hol-guard plugin links [path]` | Prints the install command for each runtime the repository already supports, and what is left to list it everywhere. | 0, or 2 could not run |
| `hol-guard plugin card [path] [--slug OWNER/NAME]` | Prints a draft plugin card as JSON: what the manifests declare the plugin can do, the programs it starts, the hosts it connects to and the environment variables it reads by name. | 0, or 2 could not run |
| `hol-guard plugin init [path] [--name NAME]` | In a plugin repository, writes `hol.json`. In a new folder (empty, or holding only a README, a LICENSE or dotfiles) with `--name`, scaffolds a minimal Claude Code plugin with one skill. Never overwrites a file. | 0, or 2 could not run |
| `hol-guard plugin stats <owner/plugin>` | For a HOL listing you own, prints its views, unique visitors and install clicks for the last 28 days and last week's attested installs by runtime. Reads a stats key from `HOL_API_KEY`; create one under Stats in your terminal in the HOL plugin workspace. The key can only read listings its account owns, and HOL withholds any install count under its minimum. | 0, or 2 could not run |

Every command accepts `--json` for the full machine-readable result.

Two commands use the network. `install` downloads the listing's install spec from HOL unless you pass `--spec-file`, and sends nothing about you or your machine. `stats` sends one request to HOL with the key. Keep the key in a secret store or CI secret, not in a script or shell history.

## Sources the Kit reads

| Source | File |
| :--- | :--- |
| Claude Code plugin | `.claude-plugin/plugin.json`, with `.mcp.json`, `skills/`, `commands/`, `agents/` and `hooks/hooks.json` |
| Claude Code marketplace | `.claude-plugin/marketplace.json` |
| Codex plugin | `.codex-plugin/plugin.json` |
| Codex marketplace | `.agents/plugins/marketplace.json` |
| Gemini CLI extension | `gemini-extension.json`, with its context file (`GEMINI.md` by default) |
| MCP Registry server | `server.json` (npm, PyPI and OCI packages, or a remote) |
| Agent Plugins 1.0 plugin | `plugin.json` with the Agent Plugins `$schema`, with `mcp.json` and `skills/` |
| Agent skills | any `SKILL.md` with `name` and `description` frontmatter |

When several manifests describe the same plugin, the shallowest one wins and the others fill in missing fields. The repository comes from the manifest, then `package.json`, then the `origin` remote in `.git/config`.

Files that are not part of the plugin, such as copies of its skills kept for other marketplaces, can be left out in `.plugin-scanner.toml`:

```toml
[plugin_kit]
exclude_paths = ["distributions/*"]
```

`*` matches any run of characters, including `/`, and `?` matches one character. A matching file is not read by `check` and is not copied by `package`, including files inside a skill or hooks folder, and a folder matched by a pattern ending in `*` is skipped without counting toward the walk limit. A `[plugin_kit]` value that is not a table, or an `exclude_paths` that is not a list of patterns, is an error. The scanner's `[scanner] ignore_paths` only hides findings and does not change what the Kit checks or packages.

## Runtimes the Kit writes

| Runtime | Output | Carries |
| :--- | :--- | :--- |
| `claude-code` | `.claude-plugin/plugin.json`, `.mcp.json` | skills, MCP servers, commands, agents, hooks |
| `codex` | `.codex-plugin/plugin.json`, `.mcp.json` | skills, MCP servers |
| `gemini-cli` | `gemini-extension.json` | MCP servers, context file |
| `cursor` | `.cursor/mcp.json` | MCP servers |
| `vscode` | `.vscode/mcp.json` | MCP servers |
| `opencode` | `opencode.json` | MCP servers |
| `mcp-registry` | `server.json` | the repository's own `server.json`, or one generated for a single remote MCP server on GitHub |
| `agent-skills` | `skills/<name>/` | skills |
| `agent-plugins` | `plugin.json`, `mcp.json`, `skills/<name>/` | skills, MCP servers and the plugin files they run |

`check` lists, for each runtime, whether it is supported and which components it drops. MCP environment variables are written as references in each runtime's own syntax (`${NAME}`, `$NAME`, `${env:NAME}` or `{env:NAME}`). The Kit never copies a variable's value: a literal in an MCP config or in a `server.json` `environmentVariables` entry is dropped, and `check` warns about it (`mcp_env_literal_secret` for a name that looks secret, `mcp_env_literal_not_carried` otherwise). A variable renamed in the config (`"GITHUB_TOKEN": "${GH_PAT}"`) keeps the rename. HTTP headers that reference a variable (`Authorization: Bearer ${API_TOKEN}`) are rewritten in each runtime's syntax; a header with a literal value is dropped and `check` reports `mcp_header_literal`. SSE servers stay SSE in every runtime that supports them. An MCP server that runs a file from the plugin keeps working where the runtime can name the plugin root (`${CLAUDE_PLUGIN_ROOT}`, `${extensionPath}` or `${PLUGIN_ROOT}`); Cursor, VS Code and opencode cannot, so `check` reports `mcp_servers_not_portable` for them and leaves the server out. A server with a working directory or `${PLUGIN_DATA}` travels only to `agent-plugins`. Gemini CLI reaches an MCP server only with the variables its manifest declares, so the generated `gemini-extension.json` lists each one in `settings`.

`package` also writes `hol.provenance.json`: the generator version, the plugin name and version, a SHA-256 digest of the source files it read, and the digest of every file it wrote. It has no timestamps, so the same Kit version packaging the same source for the same runtimes writes the same files; a different Kit version or runtime selection may not.

## hol.json

`hol-guard plugin init` writes a `hol.json` that `package` reads when no flags are given:

```json
{
  "schema": "hol.plugin-kit.config.v1",
  "out": "dist/hol-plugin",
  "runtimes": ["claude-code", "codex", "cursor"]
}
```

`out` is relative to the repository and cannot leave it. The Kit skips `dist/` and any folder holding `hol.provenance.json`, so a package is never read back as source.

## Agent Plugins 1.0

`hol-guard plugin convert --to agent-plugins` writes `plugin.json` and `mcp.json` in the Agent Plugins 1.0.0 layout. Each server gets its `type`, and runtime root placeholders such as `${CLAUDE_PLUGIN_ROOT}` become `${PLUGIN_ROOT}`. Environment variables, headers and servers that the spec cannot express portably are left out, and the output says which. `hol-guard plugin check --spec agent-plugins-1.0` then confirms the result, or checks a package you wrote by hand.

## List the plugin

`hol-guard plugin links` prints the install commands that work today and the steps still open, such as adding a Codex marketplace file or publishing to the MCP Registry. For a GitHub repository it also prints the HOL link that verifies ownership and claims the plugin's listing on HOL.

HOL links carry `utm_source=hol-guard` campaign parameters, so HOL can count visits that came from the Kit. The Kit itself sends nothing.

After the first successful `check` or `package` in text mode, the Kit prints a one-line tip showing how to turn on Guard for the agents you test with. It prints once per Guard home and never in `--json` output, and it only prints a command.

## Publish a plugin card

`hol-guard plugin card` prints a JSON card with the draft schema `hol.plugin-card.v0-draft`. Commit it at `.well-known/hol-plugin-card.json` so directories and runtimes can read what the plugin declares without loading it. The card lists skills, MCP servers and their transports, the programs local servers start, the hosts remote servers connect to and the environment variables the plugin reads. Variable values never appear in it.

The card describes what the repository claims, so `identity.verified` is always `false`. The HOL listing serves the same card at `links.holCard` with the verified owner and release attestations added. The schema id changes whenever the shape changes, until a `.well-known` card format is standardized.

## Runtime compatibility

The `Plugin Kit loader smoke` workflow packages the Claude Code fixture and loads the output with pinned releases of each runtime: `claude plugin validate`, `gemini extensions validate`, and a Codex install from a local marketplace. It also checks that each validator rejects a broken manifest. It runs on changes to the Kit and weekly, so a runtime that changes its manifest format shows up as a failed run. The pinned versions live in `.github/tools/plugin-kit-validators`.

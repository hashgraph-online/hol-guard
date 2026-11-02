# Custom extensions

Extensions already cover built-in tools such as Git, npm, and cloud CLIs. Agents also run tools that are not in that catalog: a local binary, or an interpreter launching a specific script.

On the Extensions page, choose **Add custom extension**. Guard scans remembered project `package.json` files and MCP servers already configured in your apps, then lists them. You can still paste a command. For a local script or binary, paste something like `python3 <skill-root>/scripts/cwv.py --by url`. Guard binds to that exact file, runs `--help`, and lists the commands it finds.

For package scripts, paste `npm run`, `pnpm run`, `yarn run`, `bun run`, a project folder, or `package.json`. Guard reads that file's `scripts` and lists nested names such as `guard:reddit-targeting:audit` as separate commands. `npm --prefix <dir> run` and a path to a directory with `package.json` both work. Lifecycle hooks such as `preinstall` stay hidden. Package launchers used as whole install/execute commands still stay in All tools.

For an MCP server, paste the same stdio launch command the harness uses, for example `npx -y @modelcontextprotocol/server-github` or `uvx mcp-server-git`. Guard also lists stdio MCP servers already configured in your apps under **From your apps**. Choosing one starts that command as a stdio MCP client, lists the tools, then stops the process. You then set **Recommended**, **Allow**, or **Block** on each command or tool, the same way built-in tools work. Guard does not allow tools or start servers until you choose one. A pasted script is started as an MCP server only when its source imports the server side of an MCP library, such as the MCP SDK's server modules, `mcp.server` or `fastmcp`, or handles `tools/list`. A script that only uses an MCP client does not count. A command you installed with pip, pipx or `uv tool install`, such as `mcp-server-git`, is started only when the installed module it runs, or a module of its package that it imports, shows the same evidence. Any other script is read for its commands like any script, and is never started with the arguments you pasted.

Shell utilities such as `ls` and `grep` are not custom extensions. Everyday search, identity, and terminal-recorder commands such as `rg`, `whoami`, and `script` are not custom extensions either. Test runners such as `vitest` are not suggested. Built-in catalog tools such as Git stay in All tools.

**From your apps** lists MCP servers Guard found in harness configs. **Seen on this device** lists your own scripts and binaries that agents have actually run. Guard ranks those by how much they look like a product tool, not by whichever command ran last.

A tool Guard has only seen in use lists no commands until you choose **Load commands** on its extension page. You do not enter a path. When an agent runs a script such as `deploy.sh`, Guard keeps the file it launched, on this device only, and reads that file's help. For a tool recorded before Guard kept that path, it uses the file named by a paused approval for that tool, or finds a program on its own `PATH` by name. Guard runs a file only if it is the same file it recorded. The page asks for a full path only when Guard has never seen where the tool is saved, or the file there changed. For a script such as `.mjs`, `.js`, `.ts`, `.py`, `.rb` or `.sh`, Guard first reads the file, and up to four local modules it imports from its own folder, without running anything, and lists the subcommands and options its code checks for. It runs the script with `--help` from an empty temporary folder only when that code handles `--help`, and asks each subcommand for its own help only when a parser library such as argparse, Click or Commander answers it. A script in a language Guard cannot read this way, such as Perl or PHP, is not run at all, because Guard cannot tell whether it handles `--help`. A compiled program is run with `--help` from an empty temporary folder, as in the add flow. Code that only looks like a help check, or a program that ignores `--help`, may do its normal work instead, so load commands only for tools you trust.

Remote MCP servers (a `url`, `httpUrl`, or `serverUrl` entry instead of a launch command) are listed too. Guard never connects to one to list its tools. It records the server's origin (scheme, host, and path; the query string and any credentials are dropped, and a path segment that looks like a key is shown as `[masked]`) and fills in tools as agents call them. A configured remote server and the tools an agent calls on it are one connector, so it shows up once.

## From the command line

`hol-guard mcp list` prints the same MCP servers as the Protect page, grouped as needing setup, allowed, or blocked. `hol-guard status` and `hol-guard doctor` add one line when any connector needs setup:

```text
Connectors needing setup: 3 (2 MCP servers, 1 local CLI) → http://127.0.0.1:<port>/extensions
```

The link appears when the local dashboard is running. Otherwise the line points at `hol-guard dashboard`. `hol-guard install` and `hol-guard apps` record configured MCP servers, so they show up before an agent first uses them.

## Local boundary

A custom extension is a this-device setting. It does not require Guard Cloud and does not sync to other machines.

A CLI extension binds to the tool's verified file identity. If that file changes, the previous grant no longer matches and those commands go back to Guard's normal review path. The Inbox card and the extension page then say the file changed since you allowed it, rather than calling the tool new, and offer **Allow this version**. Allowing it keeps your command choices, binds the grant to the current file, and approves the calls held on it once. A block is not carried forward the same way: a blocked file that changes goes back to the normal review. An MCP extension binds to the server identity Guard uses at runtime: launch command, arguments, stdio transport, and configured environment. If that identity changes, tool grants stop matching.

Guard identifies the tool behind an agent's command the same way wherever the review is answered. A script that starts with `#!/usr/bin/env bash` resolves `bash` on the `PATH` of the Guard daemon that recorded it, so an allow keeps applying however the harness reaches Guard.

An allowed tool outside the workspace runs as allowed, with the network and home access it normally has, on every harness. That matches what **Always allow** on its review card would do. The tool is resolved against the daemon's own home and `PATH` wherever the review is answered: the daemon publishes those with its policy, and a resident that does not hold them yet hands the review back to the daemon instead of resolving the tool against its own. The answer is the same either way; only the hop changes. Guard runs a tool in the workspace sandbox only when Guard would have sandboxed the command anyway, such as a project's own build. The allow then widens that sandbox only by the access you turn on under **Access on this device**.

Compound commands, wrappers, redirects, and environment overrides are not covered. An allow grant does not override Guard's built-in blocks for destructive or wrapped commands.

**Recommended** keeps Guard's usual review for that command or tool. **Allow** and **Block** apply only to the matched subcommand from this file, or the named tool from this MCP server. Commands that `--help` did not list use **Other commands**. Tools the server did not list use **Other tools**.

Package launchers such as `npx` and `uvx` stay in All tools as whole commands. Pasting an MCP package launch still lets Guard list that server's tools. A bare `npx` command is not a custom extension. `npm run` in a project is a custom extension for that `package.json`, not a duplicate of the built-in npm install/execute extension.

Interpreters themselves are never added as a whole. `python3 <skill-root>/scripts/cwv.py --by url` becomes a `cwv.py` custom extension, not every Python command.

## Detected records

Each detected tool or connection shows when Guard last saw it. A change to the launch command, including an added runtime flag such as `node --experimental-strip-types`, is a different identity, so Guard lists it separately. Flags like `--require` or `--import` change what runs, so Guard does not merge them.

Guard drops detected records you never added once they go unused for 30 days. It checks for expired records at most once a day. Guard also rebuilds detected records from recent approval and receipt history, using the time each entry was last recorded, so history alone does not keep a record fresh. A record that aged out comes back if newer history still mentions it.

To clear one sooner, open it and choose **Forget this connection**. **Remove custom extension** clears the grant and returns the record to detected, where you can then forget it. Older history does not bring a forgotten record back. If an agent uses it again or an app still configures it, Guard lists it again. While another added connection shares the same MCP server, Guard keeps its sibling records so that grant stays scoped to the right connection, and the dashboard does not offer to forget them.

## Guard Cloud

Keeping the same custom extension on other devices, teams, or organizations is a Cloud continuity feature. Adding the extension locally does not invent a free sync path.

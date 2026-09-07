# Custom extensions

Extensions already cover built-in tools such as Git, npm, and cloud CLIs. Agents also run tools that are not in that catalog: a local binary, or an interpreter launching a specific script.

On the Extensions page, choose **Add custom extension**. Guard scans remembered project `package.json` files and stdio MCP servers already configured in your apps, then lists them. You can still paste a command. For a local script or binary, paste something like `python3 <skill-root>/scripts/cwv.py --by url`. Guard binds to that exact file, runs `--help`, and lists the commands it finds.

For package scripts, paste `npm run`, `pnpm run`, `yarn run`, `bun run`, a project folder, or `package.json`. Guard reads that file's `scripts` and lists nested names such as `guard:reddit-targeting:audit` as separate commands. `npm --prefix <dir> run` and a path to a directory with `package.json` both work. Lifecycle hooks such as `preinstall` stay hidden. Package launchers used as whole install/execute commands still stay in All tools.

For an MCP server, paste the same stdio launch command the harness uses, for example `npx -y @modelcontextprotocol/server-github` or `uvx mcp-server-git`. Guard also lists stdio MCP servers already configured in your apps under **From your apps**. Choosing one starts that command as a stdio MCP client, lists the tools, then stops the process. You then set **Recommended**, **Allow**, or **Block** on each command or tool, the same way built-in tools work. Guard does not allow tools or start servers until you choose one.

Shell utilities such as `ls` and `grep` are not custom extensions. Everyday search, identity, and terminal-recorder commands such as `rg`, `whoami`, and `script` are not custom extensions either. Test runners such as `vitest` are not suggested. Built-in catalog tools such as Git stay in All tools.

**From your apps** lists stdio MCP servers Guard found in harness configs. **Seen on this device** lists your own scripts and binaries that agents have actually run. Guard ranks those by how much they look like a product tool, not by whichever command ran last.

## Local boundary

A custom extension is a this-device setting. It does not require Guard Cloud and does not sync to other machines.

A CLI extension binds to the tool's verified file identity. If that file changes, the previous grant no longer matches and those commands go back to Guard's normal review path. An MCP extension binds to the server identity Guard uses at runtime: launch command, arguments, stdio transport, and configured environment. If that identity changes, tool grants stop matching.

Compound commands, wrappers, redirects, and environment overrides are not covered. An allow grant does not override Guard's built-in blocks for destructive or wrapped commands.

**Recommended** keeps Guard's usual review for that command or tool. **Allow** and **Block** apply only to the matched subcommand from this file, or the named tool from this MCP server. Commands that `--help` did not list use **Other commands**. Tools the server did not list use **Other tools**.

Package launchers such as `npx` and `uvx` stay in All tools as whole commands. Pasting an MCP package launch still lets Guard list that server's tools. A bare `npx` command is not a custom extension. `npm run` in a project is a custom extension for that `package.json`, not a duplicate of the built-in npm install/execute extension.

Interpreters themselves are never added as a whole. `python3 <skill-root>/scripts/cwv.py --by url` becomes a `cwv.py` custom extension, not every Python command.

## Guard Cloud

Keeping the same custom extension on other devices, teams, or organizations is a Cloud continuity feature. Adding the extension locally does not invent a free sync path.

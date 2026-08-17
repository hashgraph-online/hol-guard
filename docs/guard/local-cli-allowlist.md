# Custom extensions

Extensions already cover built-in tools such as Git, npm, and cloud CLIs. Agents also run tools that are not in that catalog: a local binary, or an interpreter launching a specific script.

On the Extensions page, choose **Add custom extension** and paste the command for your tool. For a local script or binary, paste something like `python3 <skill-root>/scripts/cwv.py --by url`. Guard binds to that exact file, runs `--help`, and lists the commands it finds.

For an MCP server, paste the same stdio launch command the harness uses, for example `npx -y @modelcontextprotocol/server-github` or `uvx mcp-server-git`. Guard starts that command as a stdio MCP client, lists the tools, then stops the process. You then set **Recommended**, **Allow**, or **Block** on each command or tool, the same way built-in tools work.

Shell utilities such as `ls` and `grep` are not custom extensions. Built-in catalog tools such as Git stay in All tools.

## Local boundary

A custom extension is a this-device setting. It does not require Guard Cloud and does not sync to other machines.

A CLI extension binds to the tool's verified file identity. If that file changes, the previous grant no longer matches and those commands go back to Guard's normal review path. An MCP extension binds to the server identity Guard uses at runtime: launch command, arguments, stdio transport, and configured environment. If that identity changes, tool grants stop matching.

Compound commands, wrappers, redirects, and environment overrides are not covered. An allow grant does not override Guard's built-in blocks for destructive or wrapped commands.

**Recommended** keeps Guard's usual review for that command or tool. **Allow** and **Block** apply only to the matched subcommand from this file, or the named tool from this MCP server. Commands that `--help` did not list use **Other commands**. Tools the server did not list use **Other tools**.

Package launchers such as `npx` and `uvx` stay in All tools as whole commands. Pasting an MCP package launch still lets Guard list that server's tools. A bare `npx` command is not a custom extension.

Interpreters themselves are never added as a whole. `python3 <skill-root>/scripts/cwv.py --by url` becomes a `cwv.py` custom extension, not every Python command.

## Guard Cloud

Keeping the same custom extension on other devices, teams, or organizations is a Cloud continuity feature. Adding the extension locally does not invent a free sync path.

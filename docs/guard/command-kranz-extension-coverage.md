# Kranz command extension coverage

This external, opt-in extension reviews commands from the Kranz CLI. Its command
shapes follow the [Kranz CLI reference](https://kranz-org.github.io/kranz/reference/cli)
as of v0.16.3. It recognizes command text presented to supported Guard command
hooks; it does not install Kranz, invoke Kranz, or inspect a live Kranz runtime.

| Command | Why it is reviewed |
| --- | --- |
| `actions run OWNER/ACTION` | Executes a configured command, possibly with typed parameters. |
| `up`, `start`, `stop`, `restart`, `reload`, `down` | Creates a runtime or changes the running service graph. `down` also ends the runtime and its retained in-memory state. |
| `logs clear` | Discards retained output for a target or, with `--force`, every stream. |
| `runs delete TARGET --confirm` | Permanently deletes one completed run and its buffered output. Without `--confirm`, the CLI rejects deletion before runtime access. |
| `init --force` | Permits non-interactive replacement of an existing configuration file. |

Read-only inspection through `status`, `plan`, `clients`, `logs`, `runs`, and
`actions info` is outside this extension's review rules. Command help and version
flags are safe variants of the mutating rules. Other Guard rules can still
review a command independently.

Guard review is separate from Kranz's plan-bound `--confirm` flow. An external
extension is inactive until enabled by the local Guard administrator. The
portable fixture checks matching and policy effects using synthetic command
strings; it never executes the target CLI.

The canonical JSON source repeats complete native matcher objects because the
source contract has no include or template mechanism. The portable fixture
embeds the exact Kranz source in an addition build envelope against the packaged
baseline; the preparation flow verifies that binding before compiling. Explicitly disabling a permission creates a
blocking control for that capability, so its matched segment stays effective.

# Starter policies

`hol-guard policy init --starter <name>` writes a starter policy to `guard-policy.yaml`. Each starter
carries the editor modeline and two example tests, so `hol-guard policy test guard-policy.yaml` passes on
a fresh file.

The starters match the starter gallery in Policy Studio, so a policy you begin in the browser and one you
begin on the command line read the same. Names are the same in both places.

| Starter | What it does |
| --- | --- |
| `safe-defaults` | Blocks agents from reading environment variables; unknown publishers default to block. This is the default. |
| `package-firewall` | Blocks known compromised packages and sets new publishers to review in the defaults. |
| `secrets-guard` | Blocks agents from reading environment variables or files into a prompt. |
| `mcp-guard` | Blocks agents from starting MCP servers until you narrow or remove the rule. |
| `team-baseline` | A shared floor for every device: compromised packages and secret reads are blocked outright. |
| `blank` | No rules. Guard asks at the device and you add rules as you learn what your agents do. |

Every rule in a starter is a `block` rule that local import enforces. The `defaults` section
(`defaultAction`, `unknownPublisherAction`) records bundle defaults for Guard Cloud; a local import does not
turn a default into a rule, so a starter's example tests for an unlisted package or tool expect `default`.

List them any time with `hol-guard policy init --list`.

## Keeping the two in step

The CLI starters live in `src/codex_plugin_scanner/guard/policy_starters.py`. When a starter is added,
renamed or changed in Policy Studio, change the matching entry there and update the table above. The
parity tests render every starter and run its example tests, so a starter whose examples drift from its
rules fails the build.

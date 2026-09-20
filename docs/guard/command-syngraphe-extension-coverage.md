# Syngraphe command extension coverage

This optional, external extension reviews changes to repository context shared by humans and coding agents.
Enable it through Guard's local extension controls. It is inert until opted in; Syngraphe does not require or
depend on HOL Guard. Both `syngraphe` and `syg` use the same rules and option contract.

The command surface is verified against the Syngraphe CLI source and its published CLI reference.

| Commands | Syngraphe rule behavior when enabled |
| --- | --- |
| `-v`, `--version`, `-h`, `--help`, command/subcommand help | Automatic |
| `status`, with optional `--all` | Automatic |
| `check`, with any combination of `--all`, `--json`, `--strict` | Automatic |
| `stats`, with any combination of `--all`, `--json`, `--budget <tokens>` | Automatic |
| `truth list`, `decision list`, `state list`, `history list` | Automatic |
| `policy` with no subcommand, which only prints help | Automatic |
| `init`, including `init --policy` | Review: `command.syngraphe.init` |
| `truth new`, `decision new`, `state new`, `history new` | Review: `command.syngraphe.document-new` |
| `state archive` | Review: `command.syngraphe.state-archive` |
| `policy add`, with or without `--force` | Review: `command.syngraphe.policy-add` |
| Any mutation with a verified `--dry-run`, optionally with `--json` in either order | Automatic |

`--scope <path>` does not change classification and may precede or follow the command where the CLI permits it.
Syngraphe rejects combining `--scope` and `--all`, and rejects `--scope` for `policy add` because one policy
governs the whole Git root; a scoped policy write stays in the mutating family rather than being treated as safe
because the CLI happens to reject it. Creation accepts `--title <title>`; `--policy` belongs to `init` and
`--force` to `policy add`. Any other option is unknown and keeps the command reviewable. Scope and title values
are consumed as values, even when spelled `--dry-run` or `--help`. `--json` alone does not establish a safe
mutation preview: the CLI rejects `policy add --json` without `--dry-run` as a usage error.

Initialization creates `.context/`, inserts managed blocks in agent bootstrap files, and replaces a managed body
an earlier Syngraphe version published. Only text between Syngraphe's own markers is replaced, and only when it
matches a body Syngraphe itself published; a hand-edited block is reported and never overwritten. `init --policy`
adds one created file and is classified exactly like `init`; it leaves an existing policy file untouched.
Creation writes shared Markdown. State archiving creates a history document and resets `.context/state/current.md`.
These are normal context mutations, not inherently destructive operations. The rules use Guard's existing
`destructive_shell` class for workspace mutations, medium severity, and review mode. Each recommends inspecting
the same command with `--dry-run` before writing.

## Why `policy add --force` is reviewed

`policy add` writes `AGENT-POLICY.md` at the repository root: a starting point for agent operating rules that the
repository owns, and that Syngraphe never manages, compares, or checks afterwards. It is not destructive in
general — on a repository without that file it only creates one, and without `--force` it refuses and exits
non-zero rather than replacing anything.

`--force` is the one Syngraphe operation that can replace content a person wrote. Its safer alternative therefore
points at the file as well as the flag: read the existing `AGENT-POLICY.md` first, then run the same command with
`--dry-run`, which renders the exact plan and writes nothing. Upstream guarantees that preview and covers it with
tests that compare working tree and Git state around `init --policy` and `policy add`, and that assert
`policy add --force --dry-run` leaves an existing file byte-identical.

Detection consumes Guard's canonical parsed segments and existing structured path/flag matchers. It covers
portable executable basenames (including `.cmd` and `.exe`), paths to executables, canonical transparent wrappers
such as `env`, `sudo`, `nice`, and `sh -c`, and explicit `exec`, `xargs`, and `command` invocations. Wrapper behavior
is bounded by Guard's existing parser and option model; unsupported or ambiguous shapes do not establish a
verified safe flag. This extension does not add another shell parser or promise additional shell dialect support.

Safe variants require exact parsing and documented flag spellings. Malformed quoting, ambiguous option values,
flags after the CLI option terminator, and unsupported boolean assignments such as `--dry-run=true` do not prove
a safe preview. Unknown syntax is handled conservatively by existing Guard parsing/matching conventions.
Recognized mutations with active parameter, command, or pathname expansion or `xargs` replacement stay
reviewable: expansion can introduce a value-taking option, and replacement can rewrite the preview flag itself.
Supply literal arguments directly to verify the dry run.

Safety is local to the matching rule and segment. For example, `syg policy add --force --dry-run && rm -rf build`
retains the filesystem rule, and a second Syngraphe mutation still requires review. Other Guard protections and final policy
remain authoritative. Detection does not execute commands, persist arguments, or disclose titles, document names,
scope paths, or repository contents in extension evidence or catalog metadata.

## References

- [Syngraphe project and CLI source](https://github.com/suffro/syngraphe)
- [Official Syngraphe documentation](https://syngraphe.dev/)

# Syngraphe command extension coverage

This optional, external extension reviews changes to repository context shared by humans and coding agents.
Enable it through Guard's local extension controls. It is inert until opted in; Syngraphe does not require or
depend on HOL Guard. Both `syngraphe` and `syg` use the same rules and option contract.

The command surface is verified against Syngraphe 0.4.0.

| Commands | Syngraphe rule behavior when enabled |
| --- | --- |
| `-v`, `--version`, `-h`, `--help`, command/subcommand help | Automatic |
| `status`, with optional `--all` | Automatic |
| `check`, with any combination of `--all`, `--json`, `--strict` | Automatic |
| `stats`, with any combination of `--all`, `--json`, `--budget <tokens>` | Automatic |
| `truth list`, `decision list`, `state list`, `history list` | Automatic |
| `init` | Review: `command.syngraphe.init` |
| `truth new`, `decision new`, `state new`, `history new` | Review: `command.syngraphe.document-new` |
| `state archive` | Review: `command.syngraphe.state-archive` |
| Any mutation with a verified `--dry-run`, optionally with `--json` in either order | Automatic |

`--scope <path>` does not change classification and may precede or follow the command where the CLI permits it.
Syngraphe rejects combining `--scope` and `--all`. Creation accepts `--title <title>`; initialization and state
archiving do not. Scope and title values are consumed as values, even when spelled `--dry-run` or `--help`.
`--json` alone does not establish a safe mutation preview.

Initialization creates `.context/` and may create or patch agent bootstrap files. Creation writes shared Markdown.
State archiving creates a history document and resets `.context/state/current.md`. These are normal context
mutations, not inherently destructive operations. The rules use Guard's existing `destructive_shell` class for
workspace mutations, medium severity, and review mode. Each recommends inspecting the same command with
`--dry-run` before writing.

Detection consumes Guard's canonical parsed segments and existing structured path/flag matchers. It covers
portable executable basenames (including `.cmd` and `.exe`), paths to executables, canonical transparent wrappers
such as `env`, `sudo`, `nice`, and `sh -c`, and explicit `exec`, `xargs`, and `command` invocations. Wrapper behavior
is bounded by Guard's existing parser and option model; unsupported or ambiguous shapes do not establish a
verified safe flag. This extension does not add another shell parser or promise additional shell dialect support.

Safe variants require exact parsing and documented flag spellings. Malformed quoting, ambiguous option values,
flags after the CLI option terminator, and unsupported boolean assignments such as `--dry-run=true` do not prove
a safe preview. Unknown syntax is handled conservatively by existing Guard parsing/matching conventions.
Recognized mutations with unresolved shell expansions or `xargs` replacement also stay reviewable: expansion
can introduce a value-taking option, and replacement can rewrite the preview flag itself. Supply literal
arguments directly to verify the dry run.

Safety is local to the matching rule and segment. For example, `syg init --dry-run && rm -rf build` retains the
filesystem rule, and a second Syngraphe mutation still requires review. Other Guard protections and final policy
remain authoritative. Detection does not execute commands, persist arguments, or disclose titles, document names,
scope paths, or repository contents in extension evidence or catalog metadata.

## References

- [Syngraphe project and CLI source](https://github.com/suffro/syngraphe)
- [Official Syngraphe documentation](https://syngraphe.dev/)

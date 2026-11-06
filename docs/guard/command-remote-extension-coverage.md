# Remote Command Extension Coverage

Guard's built-in remote administration extensions use parsed executables, leading options, operands, and flags. Quoted examples and unrelated command arguments do not trigger these rules.

## Covered Operations

- Explicit commands executed through SSH after a destination
- Active command-bearing SSH configuration options supplied with `-o`
- SCP transfers that can overwrite local or remote destinations
- Rsync destination deletions and synchronized source-file removal
- Rsync remote command overrides supplied with `-e`, `--rsh`, `--rsync-path`, or `RSYNC_RSH`
- Portable `.cmd` and `.exe` launcher names
- Rsync `--dry-run` and `-n` safe variants, including bundled short flags
- SSH inspection, query, control, and no-command modes
- essh command execution fanned out across an entire host group
- essh removal of cached hosts, cached keys, and saved workspaces

Interactive SSH connections remain outside the explicit remote-execution rule. Ordinary rsync copies without deletion flags also remain outside the destructive synchronization rule. essh read verbs — `connect`, `why`, and the `list` and `show` forms of hosts, keys, and workspaces — also remain outside these rules.

`essh run` is treated as a whole-subcommand match rather than an operand count. Unlike `ssh`, which opens an interactive session when no command follows the destination, `essh run` has no interactive form: the subcommand exists only to execute a command across a host group, so every invocation is remote execution. Its blast radius is the group membership rather than a single destination, which is why it carries a higher severity than the single-host SSH execution rule.

## References

- [OpenSSH client](https://man.openbsd.org/ssh)
- [OpenSSH client configuration](https://man.openbsd.org/ssh_config)
- [OpenSSH secure copy client](https://man.openbsd.org/scp)
- [Rsync manual](https://rsync.samba.org/ftp/rsync/rsync.1.html)
- [essh CLI parser](https://github.com/matthart1983/essh/blob/209d946e64ea8ded976eab5b8a42418b58e15f67/src/cli/mod.rs)

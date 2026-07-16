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

Interactive SSH connections remain outside the explicit remote-execution rule. Ordinary rsync copies without deletion flags also remain outside the destructive synchronization rule.

## References

- [OpenSSH client](https://man.openbsd.org/ssh)
- [OpenSSH client configuration](https://man.openbsd.org/ssh_config)
- [OpenSSH secure copy client](https://man.openbsd.org/scp)
- [Rsync manual](https://rsync.samba.org/ftp/rsync/rsync.1.html)

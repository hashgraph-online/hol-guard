# Remote Command Extension Coverage

Guard's built-in remote administration extensions use parsed executables, leading options, operands, and flags. Quoted examples and unrelated command arguments do not trigger these rules.

## Covered Operations

- Explicit commands executed through SSH after a destination
- SCP transfers that can overwrite local or remote destinations
- Rsync destination deletions and synchronized source-file removal
- Portable `.cmd` and `.exe` launcher names
- Rsync `--dry-run` and `-n` safe variants, including bundled short flags
- SSH configuration inspection with `ssh -G`

Interactive SSH connections remain outside the explicit remote-execution rule. Ordinary rsync copies without deletion flags also remain outside the destructive synchronization rule.

## References

- [OpenSSH client](https://man.openbsd.org/ssh)
- [OpenSSH secure copy client](https://man.openbsd.org/scp)
- [Rsync manual](https://rsync.samba.org/ftp/rsync/rsync.1.html)

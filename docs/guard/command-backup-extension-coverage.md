# Backup Command Extension Coverage

Guard reviews backup operations that can remove snapshots, archives, source data, or destination data. Preview flags suppress review only where the command family documents them as side-effect-free.

| Extension | Reviewed operations | Safe counterparts |
| --- | --- | --- |
| `command.backup.rclone` | Delete, purge, move, sync, and bidirectional sync | Help, `--dry-run`, and `-n` |
| `command.backup.restic` | Forget, prune, and rewrite with original removal | Help and `--dry-run` |
| `command.backup.borg` | Delete, prune, and recreate | Help; prune/recreate dry run |
| `command.backup.velero` | Backup, schedule, and restore deletion | Help and describe operations |

Interactive confirmation is not a dry run and remains reviewable.

## References

- [Rclone commands](https://rclone.org/commands/)
- [Rclone delete](https://rclone.org/commands/rclone_delete/)
- [Restic removing snapshots](https://restic.readthedocs.io/en/stable/060_forget.html)
- [Restic repository rewrite](https://restic.readthedocs.io/en/stable/045_working_with_repos.html)
- [Borg prune](https://borgbackup.readthedocs.io/en/stable/usage/prune.html)
- [Velero backup reference](https://velero.io/docs/main/backup-reference/)

# Framework Command Extension Coverage

Guard's built-in framework extensions match parsed executables, exact Artisan subcommands, flags, and bounded argument positions. They do not scan quoted documentation or arbitrary shell text for framework keywords.

## Covered Operations

- Laravel `db:wipe` dropping all database tables, views, and types
- `migrate:fresh` dropping every table and re-running all migrations
- `migrate:reset` and `migrate:refresh` rolling back every migration
- `migrate:rollback` reverting the last migration batch (including `--batch=`/`--step=` selection)
- `queue:clear` and `queue:flush` deleting queued or failed jobs
- Direct `artisan` and interpreter-wrapped `php artisan` launch forms plus portable `.cmd`/`.exe` launcher names
- Documented `--help`/`-h` and migration `--pretend` dry-run variants

Framework dev-server and code-generation commands are intentionally deferred until Guard has a bounded matcher for interactive Artisan workflows.

## References

- [Laravel migrations](https://laravel.com/docs/13.x/migrations)
- [Laravel queues](https://laravel.com/docs/13.x/queues)
- [Laravel Artisan](https://laravel.com/docs/13.x/artisan)

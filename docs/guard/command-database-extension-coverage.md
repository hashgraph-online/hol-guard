# Database Command Extension Coverage

Guard's built-in database extensions match parsed executables, leading options, exact subcommands, flags, and bounded argument positions. They do not scan quoted documentation or arbitrary shell text for database keywords.

## Covered Operations

- PostgreSQL database removal through `dropdb`
- MySQL database removal in `mysqladmin` multi-command sequences and documented abbreviations
- MongoDB collection replacement through `mongorestore --drop`
- Redis `FLUSHALL`, `FLUSHDB`, `DEL`, and `UNLINK`
- SQLite `.restore` command arguments with a backup payload
- Supabase database reset and migration rollback through direct and package-runner launch forms
- Portable `.cmd` and `.exe` launcher names
- MongoDB documented dry-run variants

Free-form SQL passed to interactive clients is intentionally deferred until Guard has a bounded, dialect-aware statement matcher.

## References

- [PostgreSQL dropdb](https://www.postgresql.org/docs/current/app-dropdb.html)
- [MySQL mysqladmin](https://dev.mysql.com/doc/refman/8.4/en/mysqladmin.html)
- [MongoDB mongorestore](https://www.mongodb.com/docs/database-tools/mongorestore/)
- [Redis commands](https://redis.io/docs/latest/commands/)
- [SQLite command-line shell](https://www.sqlite.org/cli.html)
- [Supabase database reset](https://supabase.com/docs/reference/cli/supabase-db-reset)

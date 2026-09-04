# Laravel Artisan command extension coverage

HOL Guard includes a built-in `command.laravel-artisan` extension for destructive Laravel database-reset commands that AI coding agents and developers may invoke through Artisan.

The first release is intentionally narrow and follows current Laravel framework behavior rather than treating every Artisan mutation as dangerous.

## Covered operations

| Command | Rule | Severity | Why it is reviewed |
| --- | --- | --- | --- |
| `php artisan migrate:fresh` | `command.laravel-artisan.migrate-fresh` | critical | Laravel drops every table on the selected database before running migrations again. |
| `php artisan db:wipe` | `command.laravel-artisan.db-wipe` | critical | Laravel drops all tables and can also drop views or database types. |

The extension also recognizes direct `artisan` invocation and Laravel Sail's `sail artisan ...` forwarding for the same operations.

## Safe and unrelated operations

Normal migrations and inspection commands remain outside this extension's destructive rules. Examples include:

```bash
php artisan migrate
php artisan migrate:status
php artisan migrate --pretend
```

Command help is also a declared safe variant:

```bash
php artisan migrate:fresh --help
php artisan db:wipe --help
```

## Why this matters for AI-assisted Laravel development

Laravel Boost provides AI coding agents with Laravel-specific application context and tooling. When an agent can work directly inside a Laravel project, destructive framework-native commands deserve the same structured review boundary as destructive Git, database, cloud, package, and infrastructure commands already covered by HOL Guard.

Extensions only contribute structured evidence. Guard policy, approvals, remembered decisions, and receipts remain the authority that determines the final action.

## References

- [Laravel `migrate:fresh` implementation](https://github.com/laravel/framework/blob/13.x/src/Illuminate/Database/Console/Migrations/FreshCommand.php)
- [Laravel `db:wipe` implementation](https://github.com/laravel/framework/blob/13.x/src/Illuminate/Database/Console/WipeCommand.php)
- [Laravel Boost](https://laravel.com/ai/boost)

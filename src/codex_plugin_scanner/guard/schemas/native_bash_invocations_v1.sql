CREATE TABLE IF NOT EXISTS guard_bash_invocations (
    base_id TEXT PRIMARY KEY NOT NULL,
    payload TEXT NOT NULL,
    integrity TEXT NOT NULL
)

CREATE TABLE IF NOT EXISTS guard_bash_operations (
    operation_id TEXT PRIMARY KEY NOT NULL,
    payload TEXT NOT NULL CHECK(length(payload)<=16384),
    integrity TEXT NOT NULL CHECK(length(integrity)<=4096)
)

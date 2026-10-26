//! The one SQL statement a read-only `psql -c` may carry.
//!
//! Admitted: a single `SELECT`, or a `SHOW` of one setting on a short list,
//! optionally ending in one `;`. The text is scanned, not parsed. A word
//! directly before `(` must be a keyword that opens a subquery, list or
//! window, or a built-in that only computes or reads a value. Every other call keeps its review: file and large-object
//! access (`pg_read_file`, `pg_ls_dir`, `lo_import`, `lo_export`), remote
//! links (`dblink`), settings and sequences (`set_config`, `nextval`),
//! schema-qualified or quoted function names, and any user function. Server
//! settings are not read through a query either: `current_setting` and the
//! `pg_settings` and `pg_file_settings` views keep their review.
//!
//! Also reviewed: a second statement, backslash meta-commands, comments,
//! dollar quoting, `SELECT … INTO` (creates a table), row locks
//! (`FOR UPDATE`, `FOR SHARE`) and any character outside plain SQL.
//!
//! This bounds the text the agent wrote. Views, operators and functions the
//! database already defines are the database owner's, as with any read.

const MAX_STATEMENT_BYTES: usize = 4096;

/// Words that may stand before `(` without calling an unvetted function.
const PAREN_WORDS: &[&str] = &[
    // Keywords that open a subquery, a value list, a cast or a window.
    "all",
    "and",
    "any",
    "array",
    "as",
    "between",
    "by",
    "cast",
    "distinct",
    "else",
    "except",
    "exists",
    "extract",
    "filter",
    "from",
    "group",
    "having",
    "ilike",
    "in",
    "intersect",
    "is",
    "join",
    "lateral",
    "like",
    "not",
    "on",
    "or",
    "over",
    "row",
    "select",
    "some",
    "then",
    "union",
    "using",
    "when",
    "where",
    // Built-ins that compute or read a value and change nothing.
    "abs",
    "age",
    "array_agg",
    "array_length",
    "avg",
    "bool_and",
    "bool_or",
    "ceil",
    "char_length",
    "coalesce",
    "concat",
    "count",
    "current_database",
    "current_schema",
    "current_schemas",
    "date_part",
    "date_trunc",
    "floor",
    "generate_series",
    "greatest",
    "inet_server_addr",
    "inet_server_port",
    "json_agg",
    "json_build_object",
    "jsonb_agg",
    "jsonb_build_object",
    "jsonb_pretty",
    "least",
    "length",
    "lower",
    "max",
    "min",
    "now",
    "nullif",
    "numeric",
    "pg_backend_pid",
    "pg_database_size",
    "pg_indexes_size",
    "pg_is_in_recovery",
    "pg_postmaster_start_time",
    "pg_relation_size",
    "pg_size_pretty",
    "pg_table_size",
    "pg_total_relation_size",
    "round",
    "row_to_json",
    "string_agg",
    "sum",
    "to_char",
    "to_json",
    "to_jsonb",
    "to_timestamp",
    "unnest",
    "upper",
    "varchar",
    "version",
];

/// Settings a `SHOW` may name. File locations, `SHOW ALL` and every other
/// setting keep their review, as `current_setting` does.
const SHOWN_SETTINGS: &[&str] = &[
    "client_encoding",
    "datestyle",
    "intervalstyle",
    "is_superuser",
    "max_connections",
    "port",
    "search_path",
    "server_encoding",
    "server_version",
    "server_version_num",
    "standard_conforming_strings",
    "statement_timeout",
    "timezone",
    "transaction_isolation",
    "transaction_read_only",
];

/// The setting a `SHOW name` statement names, or `None` for any other text.
/// A `SHOW` that is not one plain name still answers `Some("")`.
fn shown_setting(statement: &str) -> Option<&str> {
    let (verb, rest) = statement.split_once(|c: char| c.is_ascii_whitespace())?;
    if !verb.eq_ignore_ascii_case("show") {
        return None;
    }
    let name = rest.trim();
    let plain = !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_');
    Some(if plain { name } else { "" })
}

#[derive(Clone, Copy)]
enum Previous {
    Start,
    Word { word: &'static str, qualified: bool },
    QuotedName,
    Other,
}

pub(super) fn read_only_statement(statement: &str) -> bool {
    let statement = statement.trim();
    let statement = statement.strip_suffix(';').unwrap_or(statement).trim_end();
    if statement.is_empty()
        || statement.len() > MAX_STATEMENT_BYTES
        || !statement.is_ascii()
        || statement.contains([';', '\\', '$', '`', '\0'])
        || statement.contains("--")
        || statement.contains("/*")
        || ["pg_settings", "pg_file_settings"]
            .iter()
            .any(|view| statement.to_ascii_lowercase().contains(view))
    {
        return false;
    }
    if let Some(name) = shown_setting(statement) {
        return SHOWN_SETTINGS.contains(&name.to_ascii_lowercase().as_str());
    }
    let bytes = statement.as_bytes();
    let mut previous = Previous::Start;
    let mut after_dot = false;
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte.is_ascii_whitespace() {
            index += 1;
            continue;
        }
        if matches!(previous, Previous::Start) && !byte.is_ascii_alphabetic() {
            return false;
        }
        match byte {
            b'\'' | b'"' => {
                let Some(end) = quoted_end(bytes, index) else {
                    return false;
                };
                index = end;
                previous = if byte == b'"' {
                    Previous::QuotedName
                } else {
                    Previous::Other
                };
                after_dot = false;
                continue;
            }
            b'(' => {
                let call_allowed = match previous {
                    Previous::Word { word, qualified } => !qualified && PAREN_WORDS.contains(&word),
                    Previous::QuotedName => false,
                    Previous::Start | Previous::Other => true,
                };
                if !call_allowed {
                    return false;
                }
            }
            b'.' => {
                after_dot = true;
                previous = Previous::Other;
                index += 1;
                continue;
            }
            _ if byte.is_ascii_alphabetic() || byte == b'_' => {
                let start = index;
                while index < bytes.len()
                    && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
                {
                    index += 1;
                }
                let word = &statement[start..index];
                let lowered = word.to_ascii_lowercase();
                if matches!(previous, Previous::Start)
                    && !matches!(lowered.as_str(), "select" | "show")
                {
                    return false;
                }
                // `SELECT … INTO` creates a table; `FOR UPDATE`/`FOR SHARE` lock rows.
                if matches!(lowered.as_str(), "into" | "for") {
                    return false;
                }
                previous = Previous::Word {
                    word: PAREN_WORDS
                        .iter()
                        .find(|known| **known == lowered)
                        .copied()
                        .unwrap_or(""),
                    qualified: after_dot,
                };
                after_dot = false;
                continue;
            }
            _ if byte.is_ascii_digit() => {
                // Older servers split `1into` into `1 into`, so a word glued
                // to a number must not hide from the keyword checks.
                while index < bytes.len() && (bytes[index].is_ascii_digit() || bytes[index] == b'.')
                {
                    index += 1;
                }
                if index < bytes.len() && matches!(bytes[index], b'e' | b'E') {
                    index += 1;
                    if index < bytes.len() && matches!(bytes[index], b'+' | b'-') {
                        index += 1;
                    }
                    while index < bytes.len() && bytes[index].is_ascii_digit() {
                        index += 1;
                    }
                }
                if index < bytes.len()
                    && (bytes[index].is_ascii_alphabetic() || bytes[index] == b'_')
                {
                    return false;
                }
                previous = Previous::Other;
                after_dot = false;
                continue;
            }
            b'*' | b',' | b')' | b'=' | b'<' | b'>' | b'!' | b'+' | b'-' | b'/' | b'%' | b':'
            | b'[' | b']' | b'|' | b'~' => {}
            _ => return false,
        }
        previous = Previous::Other;
        after_dot = false;
        index += 1;
    }
    true
}

/// The index just past a `'…'` literal or `"…"` name that starts at `start`.
/// A doubled quote inside stays part of the text.
fn quoted_end(bytes: &[u8], start: usize) -> Option<usize> {
    let quote = bytes[start];
    let mut index = start + 1;
    while index < bytes.len() {
        if bytes[index] == quote {
            if bytes.get(index + 1) == Some(&quote) {
                index += 2;
                continue;
            }
            return Some(index + 1);
        }
        index += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::read_only_statement;

    #[test]
    fn plain_selects_and_shows_are_read_only() {
        for statement in [
            "select current_user",
            "SELECT current_user;",
            "select 1",
            "select version()",
            "select current_database(), now()",
            "select count(*) from users where created_at > now() - interval '1 day'",
            "select id, \"displayName\" from \"User\" order by id desc limit 5",
            "select pg_size_pretty(pg_database_size('hol'))",
            "select exists(select 1 from pg_tables where tablename = 'items')",
            "select relname from pg_catalog.pg_class where relkind = 'r'",
            "select name from items where id in (select item_id from orders)",
            "select 'it''s fine'::text",
            "select count(*) filter (where done) over (partition by owner) from tasks",
            "show server_version",
            "SHOW search_path",
            "show TimeZone",
            "select 1.5e3, 2e-1, 0.25",
        ] {
            assert!(read_only_statement(statement), "{statement}");
        }
    }

    #[test]
    fn writes_side_effects_and_second_statements_are_refused() {
        for statement in [
            "",
            ";",
            "drop table x",
            "delete from items",
            "update items set done = true",
            "insert into items values (1)",
            "copy items to program 'id'",
            "copy (select 1) to '/tmp/out'",
            "with gone as (delete from items returning *) select * from gone",
            "explain analyze delete from items",
            "select 1; drop table x",
            "select 1;; ",
            "select 1 \\g /tmp/out",
            "\\! id",
            "select pg_read_file('/etc/passwd')",
            "select * from pg_ls_dir('.')",
            "select pg_read_binary_file('/etc/hosts')",
            "select lo_import('/etc/passwd')",
            "select lo_export(1, '/tmp/out')",
            "select * from dblink('host=db.example.com', 'select 1') as t(x int)",
            "select set_config('log_statement', 'all', false)",
            "select nextval('items_id_seq')",
            "select pg_catalog.pg_read_file('x')",
            "select pg_catalog.count(*) from items",
            "select \"pg_read_file\"('x')",
            "select * into copy_of_items from items",
            "select * from items for update",
            "select $$x$$",
            "select 1 -- comment",
            "select /* c */ 1",
            "select 'unterminated",
            "select pg_terminate_backend(123)",
            "select pg_reload_conf()",
            "select 1 & 2",
            "select current_setting('data_directory')",
            "SELECT Current_Setting('config_file', true)",
            "select name, setting from pg_settings",
            "select * from pg_catalog.pg_settings where name = 'port'",
            "select * from \"PG_SETTINGS\"",
            "select sourcefile from pg_file_settings",
            "select 1into scratch_copy",
            "select * from items where id=1for update",
            "select 1e5into x",
            "select 0x1f",
            "show all",
            "show data_directory",
            "SHOW config_file",
            "show hba_file",
            "show search_path, port",
        ] {
            assert!(!read_only_statement(statement), "{statement}");
        }
    }
}

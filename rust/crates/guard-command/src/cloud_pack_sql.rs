//! Statement classification for actions that carry SQL.
//!
//! A pack names the string argument that holds the SQL text. Each statement is
//! read without a full grammar: comments and quoted text are skipped, the text
//! is split on top-level semicolons, and each statement is classified by its
//! leading keyword and a few structural checks. The result can only raise the
//! action's declared class, never lower it:
//!
//! * read: `SELECT`, `WITH ... SELECT`, `SHOW`, `EXPLAIN` without `ANALYZE`,
//!   transaction control;
//! * write: `INSERT`, `UPDATE` or `DELETE` with a top-level `WHERE`, `CREATE`,
//!   `ALTER` that drops nothing;
//! * destructive: `DROP`, `TRUNCATE`, `UPDATE` or `DELETE` with no `WHERE` or a
//!   constant-true one, `ALTER ... DROP`, and anything that runs code the text
//!   does not show (`CALL`, `DO`, `EXECUTE`, `COPY`, a side-effecting function);
//! * admin: `GRANT`, `REVOKE`, and role or user changes.
//!
//! Text the reader cannot follow (an unclosed quote or comment, a backslash in
//! a string, an unknown leading keyword, no statement at all) is destructive.

use crate::cloud_pack::ArgumentSpec;
use crate::cloud_pack_sql_lex::{tokenize, Token};
use guard_contracts::{ActionClassV2, ActionFactsV2, Fact, ObjectKindV2, ReversibilityV2, ScopeV2};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

/// Where the SQL text is: a string or string-array argument, or one field of a
/// `json` argument holding a string or an array of strings. Every string in an
/// array is classified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SqlSpec {
    pub argument: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
}

/// What one piece of SQL does, from least to most strict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SqlKind {
    Read,
    Write,
    Destructive,
    Admin,
}

/// The classification of a whole text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SqlClass {
    pub kind: SqlKind,
    /// Some statement changes every row of its target.
    pub unscoped: bool,
    /// Some statement drops a whole database or schema.
    pub drops_database: bool,
}

impl SqlClass {
    const UNREADABLE: Self = Self {
        kind: SqlKind::Destructive,
        unscoped: true,
        drops_database: false,
    };

    pub const fn action_class(self) -> ActionClassV2 {
        match self.kind {
            SqlKind::Read => ActionClassV2::Read,
            SqlKind::Write => ActionClassV2::Update,
            SqlKind::Destructive => ActionClassV2::Delete,
            SqlKind::Admin => ActionClassV2::Admin,
        }
    }
}

const MAX_STATEMENTS: usize = 64;

/// Functions that change state or reach outside the database when selected.
const SIDE_EFFECT_FUNCTIONS: &[&str] = &[
    "DBLINK",
    "DBLINK_EXEC",
    "LO_EXPORT",
    "LO_IMPORT",
    "LO_UNLINK",
    "PG_CANCEL_BACKEND",
    "PG_DROP_REPLICATION_SLOT",
    "PG_FILE_WRITE",
    "PG_READ_BINARY_FILE",
    "PG_READ_FILE",
    "PG_RELOAD_CONF",
    "PG_TERMINATE_BACKEND",
    "SYSTEM$CANCEL_ALL_QUERIES",
    "SYSTEM$CANCEL_QUERY",
];
const WRITE_FUNCTIONS: &[&str] = &["NEXTVAL", "SETVAL", "SET_CONFIG"];
const WRITE_LEADS: &[&str] = &[
    "INSERT", "MERGE", "UPSERT", "REPLACE", "COMMENT", "ANALYZE", "VACUUM", "REINDEX", "CLUSTER",
    "REFRESH", "LOCK",
];
const ROLE_OBJECTS: &[&str] = &["USER", "ROLE", "GROUP", "LOGIN", "POLICY"];

/// Words that start a statement other than transaction control.
const ACTION_LEADS: &[&str] = &[
    "ALTER", "CALL", "COPY", "CREATE", "DELETE", "DO", "DROP", "EXEC", "EXECUTE", "GRANT",
    "INSERT", "MERGE", "REVOKE", "SELECT", "TRUNCATE", "UPDATE", "VALUES", "WITH",
];
const TRANSACTION_LEADS: &[&str] = &[
    "ABORT",
    "BEGIN",
    "COMMIT",
    "END",
    "RELEASE",
    "ROLLBACK",
    "SAVEPOINT",
    "START",
];

/// Classify a SQL text.
pub fn classify(text: &str) -> SqlClass {
    let Some(tokens) = tokenize(text) else {
        return SqlClass::UNREADABLE;
    };
    let statements: Vec<&[Token]> = tokens
        .split(|token| *token == Token::Semicolon)
        .filter(|statement| !statement.is_empty())
        .collect();
    if statements.is_empty() || statements.len() > MAX_STATEMENTS {
        return SqlClass::UNREADABLE;
    }
    statements
        .into_iter()
        .map(statement_class)
        .fold(SqlClass::plain(SqlKind::Read), SqlClass::max_with)
}

impl SqlClass {
    const fn plain(kind: SqlKind) -> Self {
        Self {
            kind,
            unscoped: false,
            drops_database: false,
        }
    }

    fn max_with(self, other: Self) -> Self {
        Self {
            kind: if other.kind > self.kind {
                other.kind
            } else {
                self.kind
            },
            unscoped: self.unscoped | other.unscoped,
            drops_database: self.drops_database | other.drops_database,
        }
    }
}

fn words_of(tokens: &[Token]) -> Vec<Option<&str>> {
    tokens
        .iter()
        .map(|token| match token {
            Token::Word(word) => Some(word.as_str()),
            _ => None,
        })
        .collect()
}

/// The statement from the first word in `leads` after the lead, or unreadable.
fn from_first(tokens: &[Token], words: &[Option<&str>], leads: &[&str]) -> Option<SqlClass> {
    words
        .iter()
        .skip(1)
        .position(|word| word.is_some_and(|w| leads.contains(&w)))
        .map(|offset| statement_class(&tokens[offset + 1..]))
}

fn statement_class(tokens: &[Token]) -> SqlClass {
    let words = words_of(tokens);
    let Some(Some(lead)) = words.first().copied() else {
        return SqlClass::UNREADABLE;
    };
    let second = words.get(1).copied().flatten();
    let has = |wanted: &[&str]| words.iter().flatten().any(|w| wanted.contains(w));
    match lead {
        "SELECT" | "WITH" | "VALUES" | "TABLE" => embedded(tokens, &words),
        // `EXPLAIN ANALYZE` runs the statement it explains.
        "EXPLAIN" if has(&["ANALYZE", "ANALYSE"]) => from_first(tokens, &words, ACTION_LEADS)
            .unwrap_or(SqlClass::UNREADABLE)
            .max_with(SqlClass::plain(SqlKind::Write)),
        "EXPLAIN" | "SHOW" | "DESCRIBE" | "DESC" | "USE" => SqlClass::plain(SqlKind::Read),
        // A block opened by `BEGIN` can hold any statement.
        _ if TRANSACTION_LEADS.contains(&lead) => {
            from_first(tokens, &words, ACTION_LEADS).unwrap_or(SqlClass::plain(SqlKind::Read))
        }
        "SET" | "RESET" => match second {
            Some("ROLE" | "SESSION" | "GLOBAL" | "PERSIST" | "PERSIST_ONLY") => {
                SqlClass::plain(SqlKind::Admin)
            }
            _ => embedded(tokens, &words),
        },
        "UPDATE" | "DELETE" => scoped_change(tokens),
        "GRANT" | "REVOKE" => SqlClass::plain(SqlKind::Admin),
        "DROP" | "ALTER" if second.is_some_and(|w| ROLE_OBJECTS.contains(&w)) => {
            SqlClass::plain(SqlKind::Admin)
        }
        "CREATE" => create_class(tokens, &words),
        "DROP" if matches!(second, Some("DATABASE" | "SCHEMA")) => SqlClass {
            drops_database: true,
            ..SqlClass::UNREADABLE
        },
        "DROP" | "TRUNCATE" => SqlClass::UNREADABLE,
        // An expiry option makes BigQuery delete the table or its partitions later.
        "ALTER"
            if has(&[
                "DROP",
                "RENAME",
                "EXPIRATION_TIMESTAMP",
                "PARTITION_EXPIRATION_DAYS",
                "DEFAULT_TABLE_EXPIRATION_DAYS",
                "DEFAULT_PARTITION_EXPIRATION_DAYS",
            ]) =>
        {
            SqlClass::plain(SqlKind::Destructive)
        }
        "ALTER" => embedded(tokens, &words).max_with(SqlClass::plain(SqlKind::Write)),
        "INSERT" if second == Some("OVERWRITE") => SqlClass::UNREADABLE,
        _ if WRITE_LEADS.contains(&lead) => {
            embedded(tokens, &words).max_with(SqlClass::plain(SqlKind::Write))
        }
        _ => SqlClass::UNREADABLE,
    }
}

/// `CREATE [OR REPLACE] ...`: a role is admin, replacing an object discards it.
fn create_class(tokens: &[Token], words: &[Option<&str>]) -> SqlClass {
    let replaces = words.get(1..3) == Some(&[Some("OR"), Some("REPLACE")]);
    let object = words.get(if replaces { 3 } else { 1 }).copied().flatten();
    if object.is_some_and(|w| ROLE_OBJECTS.contains(&w)) {
        return SqlClass::plain(SqlKind::Admin);
    }
    let base = SqlClass::plain(if replaces {
        SqlKind::Destructive
    } else {
        SqlKind::Write
    });
    embedded(tokens, words).max_with(base)
}

/// The index after the innermost unclosed `(` before `index`, or `index`.
fn enclosing_start(tokens: &[Token], index: usize) -> usize {
    let mut depth = 0_usize;
    for back in (0..index).rev() {
        match tokens[back] {
            Token::Close => depth += 1,
            Token::Open if depth == 0 => return back + 1,
            Token::Open => depth -= 1,
            _ => {}
        }
    }
    index
}

/// A query or insert can hide changes in common table expressions, `SELECT
/// INTO`, row locks or functions.
fn embedded(tokens: &[Token], words: &[Option<&str>]) -> SqlClass {
    let mut result = SqlClass::plain(SqlKind::Read);
    for (index, word) in words.iter().enumerate() {
        let Some(word) = word else { continue };
        let previous = index.checked_sub(1).and_then(|i| words[i]);
        let opens_call = matches!(tokens.get(index + 1), Some(Token::Open));
        // A quoted function name resolves to the same function.
        let callee = word.strip_prefix('\u{0}').map(str::to_ascii_uppercase);
        let callee = callee.as_deref().unwrap_or(word);
        let kind = match *word {
            // Row locks, upserts and matched merge rows change only the rows they name.
            "UPDATE" if matches!(previous, Some("FOR" | "KEY" | "DO" | "THEN")) => SqlKind::Write,
            // `WHEN NOT MATCHED BY SOURCE THEN DELETE` can remove most of a table.
            "DELETE" if previous == Some("THEN") => SqlKind::Destructive,
            "UPDATE" | "DELETE" if index > 0 => {
                let start = enclosing_start(tokens, index);
                result = result.max_with(scoped_change(&tokens[start..]));
                continue;
            }
            "DROP" | "TRUNCATE" | "OUTFILE" | "DUMPFILE" => SqlKind::Destructive,
            "INSERT" | "MERGE" | "INTO" => SqlKind::Write,
            _ if opens_call && SIDE_EFFECT_FUNCTIONS.contains(&callee) => SqlKind::Destructive,
            _ if opens_call && WRITE_FUNCTIONS.contains(&callee) => SqlKind::Write,
            _ => continue,
        };
        result.kind = result.kind.max(kind);
    }
    result
}

/// An `UPDATE` or `DELETE` that starts `tokens`: a write when its own level
/// has a `WHERE` that is not constant true, destructive and unscoped otherwise.
fn scoped_change(tokens: &[Token]) -> SqlClass {
    let mut depth = 0_usize;
    for (index, token) in tokens.iter().enumerate() {
        match token {
            Token::Open => depth += 1,
            Token::Close if depth == 0 => break,
            Token::Close => depth -= 1,
            Token::Word(word) if depth == 0 && word == "WHERE" => {
                let rest = &tokens[index + 1..];
                if constant_true(rest) {
                    break;
                }
                let head = &tokens[1..index];
                return embedded(head, &words_of(head))
                    .max_with(embedded(rest, &words_of(rest)))
                    .max_with(SqlClass::plain(SqlKind::Write));
            }
            _ => {}
        }
    }
    SqlClass::UNREADABLE
}

/// `WHERE TRUE`, `WHERE 1`, or `WHERE a = a` with nothing else in the clause.
fn constant_true(rest: &[Token]) -> bool {
    let end = rest
        .iter()
        .position(|token| match token {
            Token::Word(word) => matches!(word.as_str(), "RETURNING" | "LIMIT" | "ORDER"),
            Token::Close => true,
            _ => false,
        })
        .unwrap_or(rest.len());
    match &rest[..end] {
        [Token::Word(word)] => word == "TRUE" || word == "1",
        [left, Token::Other('='), right] => left == right && *left != Token::Open,
        _ => false,
    }
}

/// Raise the facts of a call whose SQL argument is stricter than the declared class.
pub(crate) fn apply(spec: Option<&SqlSpec>, args: &Map<String, Value>, facts: &mut ActionFactsV2) {
    let Some(spec) = spec else { return };
    let value = args.get(&spec.argument);
    let value = match &spec.field {
        Some(field) => value.and_then(|value| value.get(field)),
        None => value,
    };
    let class = match value {
        Some(Value::String(text)) => classify(text),
        Some(Value::Array(items)) if !items.is_empty() => items
            .iter()
            .fold(SqlClass::plain(SqlKind::Read), |class, item| {
                class.max_with(item.as_str().map_or(SqlClass::UNREADABLE, classify))
            }),
        _ => SqlClass::UNREADABLE,
    };
    let raised = class.action_class();
    if crate::cloud_action_classifier::rank(raised)
        > crate::cloud_action_classifier::rank(facts.class)
    {
        facts.class = raised;
    }
    if class.kind == SqlKind::Write && !class.unscoped {
        facts.scope = Fact::Known(ScopeV2::QuerySelected);
    }
    if class.kind == SqlKind::Destructive {
        facts.reversibility = Fact::Known(ReversibilityV2::Permanent);
        facts.object = Fact::Known(if class.drops_database {
            ObjectKindV2::Database
        } else {
            ObjectKindV2::Table
        });
    }
    if class.unscoped {
        facts.scope = Fact::Known(ScopeV2::All);
    }
}

pub(crate) fn validate(
    spec: Option<&SqlSpec>,
    args: &BTreeMap<String, ArgumentSpec>,
) -> Result<(), &'static str> {
    let Some(spec) = spec else { return Ok(()) };
    let valid = match (args.get(&spec.argument), &spec.field) {
        (
            Some(ArgumentSpec::String { required, .. } | ArgumentSpec::Array { required, .. }),
            None,
        ) => *required,
        (Some(ArgumentSpec::Json { required, .. }), Some(field)) => {
            *required && !field.is_empty() && field.len() <= 64
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err("cloud_pack_sql_invalid")
    }
}

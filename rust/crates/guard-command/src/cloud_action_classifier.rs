//! A tighten-only class proposal for cloud actions no pack describes.
//!
//! The proposal reads the tool name, and the input schema's property names
//! when one is given. It never reads tool annotations such as
//! `readOnlyHint`, which the tool's own server sets. It never proposes a
//! class below `update`: an unknown tool is at least a write. When several
//! verbs appear, the strictest class wins, so `list_and_delete_rows` is a
//! delete. The proposal only ever raises the review a call gets; it never
//! admits a call.

use guard_contracts::ActionClassV2;
use serde::Serialize;
use serde_json::Value;

/// A proposed class and whether the name reads as destructive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Proposal {
    pub class: ActionClassV2,
    /// True for `delete`, `admin` and `pay`.
    pub destructive: bool,
    /// The name tokens (or schema evidence) that set the class.
    pub evidence: Vec<String>,
}

const MAX_NAME_BYTES: usize = 256;

/// Single-token verbs and nouns, by class.
const VERBS: &[(ActionClassV2, &[&str])] = &[
    (
        ActionClassV2::Admin,
        &[
            "revoke",
            "grant",
            "role",
            "roles",
            "permission",
            "permissions",
            "admin",
            "admins",
            "billing",
            "settings",
            "setting",
            "acl",
            "acls",
            "iam",
            "sso",
            "saml",
            "mfa",
            "ownership",
            "owner",
            "owners",
            "collaborator",
            "collaborators",
            "credential",
            "credentials",
            "impersonate",
            "suspend",
            "deactivate",
            "ban",
        ],
    ),
    (
        ActionClassV2::Delete,
        &[
            "delete",
            "del",
            "remove",
            "rm",
            "drop",
            "purge",
            "truncate",
            "destroy",
            "erase",
            "wipe",
            "trash",
            "unlink",
            "discard",
            "clear",
            "archive",
            "uninstall",
            "terminate",
            "kill",
            "expunge",
            "deprovision",
            "teardown",
            "reset",
            "overwrite",
            "nuke",
        ],
    ),
    (
        ActionClassV2::Pay,
        &[
            "pay",
            "payment",
            "payments",
            "refund",
            "refunds",
            "charge",
            "charges",
            "payout",
            "payouts",
            "withdraw",
            "withdrawal",
            "transfer",
            "transfers",
            "purchase",
            "buy",
            "checkout",
            "disburse",
            "remit",
            "donate",
        ],
    ),
    (
        ActionClassV2::Send,
        &[
            "send",
            "post",
            "email",
            "mail",
            "reply",
            "forward",
            "notify",
            "broadcast",
            "sms",
            "dm",
            "comment",
            "tweet",
            "message",
            "chat",
            "respond",
            "announce",
            "ping",
            "review",
        ],
    ),
    (
        ActionClassV2::Share,
        &[
            "share",
            "shared",
            "publish",
            "invite",
            "expose",
            "unprotect",
            "public",
        ],
    ),
    (
        ActionClassV2::Export,
        &[
            "export", "download", "dump", "backup", "extract", "sync", "clone", "copy",
        ],
    ),
    (
        ActionClassV2::Execute,
        &[
            "execute",
            "exec",
            "run",
            "deploy",
            "deployment",
            "redeploy",
            "promote",
            "invoke",
            "eval",
            "trigger",
            "launch",
            "sql",
            "migrate",
            "migration",
            "rollback",
            "restart",
            "dispatch",
            "rerun",
            "apply",
            "merge",
            "push",
            "rebase",
            "release",
            "build",
            "shell",
            "script",
        ],
    ),
];

/// Word pairs that, both present, read stricter than either word alone.
const PAIRS: &[(&str, &str, ActionClassV2)] = &[
    ("transfer", "ownership", ActionClassV2::Admin),
    ("force", "push", ActionClassV2::Delete),
    ("make", "public", ActionClassV2::Share),
    ("api", "key", ActionClassV2::Admin),
    ("api", "keys", ActionClassV2::Admin),
    ("access", "token", ActionClassV2::Admin),
    ("add", "member", ActionClassV2::Admin),
    ("add", "members", ActionClassV2::Admin),
    ("remove", "member", ActionClassV2::Admin),
    ("remove", "members", ActionClassV2::Admin),
    ("invite", "member", ActionClassV2::Admin),
    ("add", "user", ActionClassV2::Admin),
    ("remove", "user", ActionClassV2::Admin),
];

const AMOUNT_KEYS: &[&str] = &[
    "amount",
    "amountminor",
    "amountcents",
    "amountinminor",
    "price",
    "total",
    "valueminor",
    "unitamount",
];
const CURRENCY_KEYS: &[&str] = &["currency", "currencycode"];

/// Strictness among the classes a name can propose.
pub(crate) const fn rank(class: ActionClassV2) -> u8 {
    match class {
        ActionClassV2::Read | ActionClassV2::Draft => 0,
        ActionClassV2::Update => 1,
        ActionClassV2::Execute => 2,
        ActionClassV2::Export => 3,
        ActionClassV2::Share => 4,
        ActionClassV2::Send => 5,
        ActionClassV2::Pay => 6,
        ActionClassV2::Delete => 7,
        ActionClassV2::Admin => 8,
    }
}

/// Split a tool name on separators, digits and camelCase boundaries.
pub fn tokens(name: &str) -> Vec<String> {
    let name = if name.len() > MAX_NAME_BYTES {
        let mut end = MAX_NAME_BYTES;
        while !name.is_char_boundary(end) {
            end -= 1;
        }
        &name[..end]
    } else {
        name
    };
    let chars: Vec<char> = name.chars().collect();
    let mut out = Vec::new();
    let mut current = String::new();
    for (index, &ch) in chars.iter().enumerate() {
        if !ch.is_ascii_alphabetic() {
            flush(&mut current, &mut out);
            continue;
        }
        let previous = index.checked_sub(1).map(|i| chars[i]);
        let next = chars.get(index + 1).copied();
        let boundary = ch.is_ascii_uppercase()
            && previous.is_some_and(|p| {
                p.is_ascii_lowercase()
                    || (p.is_ascii_uppercase() && next.is_some_and(|n| n.is_ascii_lowercase()))
            });
        if boundary {
            flush(&mut current, &mut out);
        }
        current.push(ch.to_ascii_lowercase());
    }
    flush(&mut current, &mut out);
    out
}

fn flush(current: &mut String, out: &mut Vec<String>) {
    if !current.is_empty() {
        out.push(std::mem::take(current));
    }
}

fn verb_class(token: &str) -> Option<ActionClassV2> {
    VERBS
        .iter()
        .find(|(_, words)| words.contains(&token))
        .map(|(class, _)| *class)
}

/// Propose a class for a tool name and an optional JSON Schema for its input.
pub fn classify(name: &str, input_schema: Option<&Value>) -> Proposal {
    if name.len() > MAX_NAME_BYTES {
        // An unread tail could hold any verb, so take the strictest class.
        return Proposal {
            class: ActionClassV2::Admin,
            destructive: true,
            evidence: vec!["name_too_long".into()],
        };
    }
    let words = tokens(name);
    let mut class = ActionClassV2::Update;
    let mut evidence = Vec::new();
    let mut raise = |candidate: ActionClassV2, why: String, evidence: &mut Vec<String>| {
        if rank(candidate) > rank(class) {
            class = candidate;
            evidence.clear();
        }
        if rank(candidate) == rank(class) && !evidence.contains(&why) {
            evidence.push(why);
        }
    };
    for word in &words {
        if let Some(candidate) = verb_class(word) {
            raise(candidate, word.clone(), &mut evidence);
        }
    }
    let has = |word: &str| words.iter().any(|w| w == word);
    for (first, second, candidate) in PAIRS {
        if has(first) && has(second) {
            raise(*candidate, format!("{first}+{second}"), &mut evidence);
        }
    }
    if input_schema.is_some_and(moves_money) {
        raise(
            ActionClassV2::Pay,
            "schema:amount+currency".into(),
            &mut evidence,
        );
    }
    Proposal {
        class,
        destructive: destructive_class(class),
        evidence,
    }
}

/// Whether a proposed class reads as destructive. A proposal's `destructive`
/// is exactly this, so a stored class-only call recovers it from its class.
pub const fn destructive_class(class: ActionClassV2) -> bool {
    matches!(
        class,
        ActionClassV2::Delete | ActionClassV2::Admin | ActionClassV2::Pay
    )
}

/// A schema whose top-level properties name both an amount and a currency.
fn moves_money(schema: &Value) -> bool {
    let Some(properties) = schema.get("properties").and_then(Value::as_object) else {
        return false;
    };
    let keys: Vec<String> = properties
        .keys()
        .map(|key| key.to_ascii_lowercase().replace(['-', ' ', '_'], ""))
        .collect();
    let has = |names: &[&str]| keys.iter().any(|key| names.contains(&key.as_str()));
    has(AMOUNT_KEYS) && has(CURRENCY_KEYS)
}

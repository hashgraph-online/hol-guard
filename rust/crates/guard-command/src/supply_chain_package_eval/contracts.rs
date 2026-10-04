use super::*;

// ---------------------------------------------------------------------------
// Constants (:114-153)
// ---------------------------------------------------------------------------

pub(super) fn decision_rank_map() -> &'static HashMap<&'static str, u8> {
    static MAP: LazyLock<HashMap<&'static str, u8>> = LazyLock::new(|| {
        HashMap::from([
            ("allow", 0),
            ("monitor", 1),
            ("warn", 2),
            ("ask", 3),
            ("block", 4),
        ])
    });
    &MAP
}

#[allow(dead_code)]
pub(super) fn severity_rank_map() -> &'static HashMap<&'static str, u8> {
    static MAP: LazyLock<HashMap<&'static str, u8>> = LazyLock::new(|| {
        HashMap::from([
            ("unknown", 0),
            ("low", 1),
            ("medium", 2),
            ("high", 3),
            ("critical", 4),
        ])
    });
    &MAP
}

#[allow(dead_code)]
pub(super) const TIMEOUT_SECONDS: u64 = 1;

#[allow(dead_code)]
pub(super) const RETRY_TIMEOUT_SECONDS: u64 = 1;

pub(super) static CLOUD_INBOX_URL_RE: LazyLock<Regex> = LazyLock::new(|| {
    RegexBuilder::new(r"https?://[^\s]+/guard/inbox/?")
        .case_insensitive(true)
        .build()
        .expect("CLOUD_INBOX_URL_RE")
});

pub(super) const LOCAL_REVIEW_INSTRUCTION: &str = "Review this request in HOL Guard, then retry.";

pub(super) static LOCAL_REVIEW_INSTRUCTION_RE: LazyLock<Regex> = LazyLock::new(|| {
    RegexBuilder::new(&regex::escape(LOCAL_REVIEW_INSTRUCTION))
        .case_insensitive(true)
        .build()
        .expect("LOCAL_REVIEW_INSTRUCTION_RE")
});

pub(super) static LOCAL_APPROVAL_INSTRUCTION_RE: LazyLock<Regex> = LazyLock::new(|| {
    RegexBuilder::new(r"approve this request in hol guard, then retry\.?")
        .case_insensitive(true)
        .build()
        .expect("LOCAL_APPROVAL_INSTRUCTION_RE")
});

pub(super) static LOCAL_APPROVAL_REQUEST_URL_RE: LazyLock<Regex> = LazyLock::new(|| {
    RegexBuilder::new(r"https?://[^\s]+/requests(?:/[^\s]*)?")
        .case_insensitive(true)
        .build()
        .expect("LOCAL_APPROVAL_REQUEST_URL_RE")
});

#[allow(dead_code)]
pub(super) static NAMED_SOURCE_SEPARATOR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\s+(?:from|via|using|through)\s+").expect("NAMED_SOURCE_SEPARATOR_RE")
});

#[allow(dead_code)]
pub(super) const LOCKFILE_PARSE_BUDGET_SECONDS: f64 = 0.5;

#[allow(dead_code)]
pub(super) const LOCKFILE_PARSE_BUDGET_PER_MIB_SECONDS: f64 = 0.75;

#[allow(dead_code)]
pub(super) const LOCKFILE_PARSE_MAX_BUDGET_SECONDS: f64 = 1.5;

#[allow(dead_code)]
pub(super) const TRANSITIVE_BLOCK_CONFIDENCE_THRESHOLD: u32 = 900;

#[allow(dead_code)]
pub(super) const NPM_REGISTRY_METADATA_BASE_URL: &str = "https://registry.npmjs.org";

#[allow(dead_code)]
pub(super) const PYPI_REGISTRY_METADATA_BASE_URL: &str = "https://pypi.org/pypi";

#[allow(dead_code)]
pub(super) const TARBALL_SCAN_TIMEOUT_SECONDS: u64 = 2;

#[allow(dead_code)]
pub(super) const TARBALL_SCAN_MAX_BYTES: u64 = 6 * 1024 * 1024;

#[allow(dead_code)]
pub(super) const TARBALL_SCAN_MAX_FILES: usize = 500;

#[allow(dead_code)]
pub(super) const TARBALL_SCAN_MAX_PACKAGE_JSON_BYTES: u64 = 256 * 1024;

#[allow(dead_code)]
pub(super) const EXTERNAL_ARCHIVE_MAX_TARGETS: usize = 4;

#[allow(dead_code)]
pub(super) const EXTERNAL_ARCHIVE_MAX_AGGREGATE_BYTES: u64 = 12 * 1024 * 1024;

#[allow(dead_code)]
pub(super) const EXTERNAL_ARCHIVE_REQUEST_TIMEOUT_SECONDS: f64 = 8.0;

#[allow(dead_code)]
pub(super) const CLOUD_VALIDATION_ERROR_CACHE_TTL_SECONDS: f64 = 15.0 * 60.0;

#[allow(dead_code)]
pub(super) fn registry_default_ranges() -> &'static HashMap<&'static str, &'static str> {
    static MAP: LazyLock<HashMap<&'static str, &'static str>> =
        LazyLock::new(|| HashMap::from([("npm", "latest"), ("pypi", ">=0")]));
    &MAP
}

#[allow(dead_code)]
pub(super) fn dist_tag_range_ecosystems() -> &'static HashSet<&'static str> {
    static SET: LazyLock<HashSet<&'static str>> = LazyLock::new(|| HashSet::from(["npm"]));
    &SET
}

pub(super) fn decision_to_guard_action() -> &'static HashMap<&'static str, &'static str> {
    static MAP: LazyLock<HashMap<&'static str, &'static str>> = LazyLock::new(|| {
        HashMap::from([
            ("allow", "allow"),
            ("monitor", "allow"),
            ("warn", "warn"),
            ("ask", "require-reapproval"),
            ("block", "block"),
        ])
    });
    &MAP
}

// ---------------------------------------------------------------------------
// Small coercion helpers — Python dict/object truthiness shims.
// ---------------------------------------------------------------------------

pub(super) fn optional_string(value: Option<&Value>) -> Option<String> {
    match value {
        Some(Value::String(s)) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        }
        Some(Value::Number(n)) => Some(n.to_string()),
        Some(Value::Bool(b)) => Some(if *b { "True" } else { "False" }.to_string()),
        _ => None,
    }
}

pub(super) fn dict_items(value: Option<&Value>) -> Vec<Map<String, Value>> {
    match value {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|v| v.as_object().cloned())
            .collect(),
        Some(Value::Object(m)) => vec![m.clone()],
        _ => Vec::new(),
    }
}

#[allow(dead_code)]
pub(super) fn string_tuple(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        Some(Value::String(s)) => vec![s.clone()],
        _ => Vec::new(),
    }
}

#[allow(dead_code)]
pub(super) fn map_insert_if_some(map: &mut Map<String, Value>, key: &str, value: Option<String>) {
    if let Some(v) = value {
        map.insert(key.to_string(), Value::String(v));
    }
}

pub(super) fn json_obj(pairs: Vec<(&str, Value)>) -> Value {
    let mut map = Map::new();
    for (k, v) in pairs {
        map.insert(k.to_string(), v);
    }
    Value::Object(map)
}

pub(super) fn value_str<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

#[allow(dead_code)]
pub(super) fn now_seconds(now: &str) -> f64 {
    crate::local_supply_chain::parse_timestamp(now)
        .map(|t| t.unix_seconds() as f64)
        .unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs_f64())
                .unwrap_or(0.0)
        })
}

pub(super) fn ensure_terminal_punctuation(message: &str) -> String {
    let trimmed = message.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if trimmed.ends_with('.') || trimmed.ends_with('!') || trimmed.ends_with('?') {
        trimmed.to_string()
    } else {
        format!("{trimmed}.")
    }
}

// ---------------------------------------------------------------------------
// `SupplyChainUserCopy` / `PackageRequestEvaluation` dataclass mirrors.
// The sibling `PackageRequestEvaluation` is a `Value` mirror; these helpers
// build/consume the exact dict shapes.
// ---------------------------------------------------------------------------

#[allow(dead_code)]
pub(super) fn user_copy_to_dict(copy: &Map<String, Value>) -> Value {
    json_obj(vec![
        ("title", copy.get("title").cloned().unwrap_or(Value::Null)),
        (
            "summary",
            copy.get("summary").cloned().unwrap_or(Value::Null),
        ),
        (
            "next_step",
            copy.get("next_step").cloned().unwrap_or(Value::Null),
        ),
        (
            "dashboard_url",
            copy.get("dashboard_url").cloned().unwrap_or(Value::Null),
        ),
        (
            "harness_message",
            copy.get("harness_message").cloned().unwrap_or(Value::Null),
        ),
    ])
}

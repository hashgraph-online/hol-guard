//! Rust port of `runtime/supply_chain_support.py` — shared ecosystem support
//! labels for Guard local supply-chain coverage.

use serde_json::{json, Map, Value};

/// `_SUPPORT_LEVELS` (:7) — `(display_name, support_level, support_label)`
/// tuples keyed by ecosystem slug.
fn support_level(ecosystem: &str) -> Option<(&'static str, &'static str, &'static str)> {
    match ecosystem {
        "npm" => Some(("npm", "protected", "Protected")),
        "pypi" => Some(("PyPI", "protected", "Protected")),
        "cargo" => Some(("Cargo", "beta", "Beta")),
        "go" => Some(("Go modules", "beta", "Beta")),
        "maven" => Some(("Maven/Gradle", "beta", "Beta")),
        "packagist" => Some(("Composer", "beta", "Beta")),
        "rubygems" => Some(("RubyGems", "beta", "Beta")),
        "homebrew" => Some(("Homebrew formulae", "monitor-only", "Monitor-only")),
        "homebrew-cask" => Some(("Homebrew Casks", "monitor-only", "Monitor-only")),
        "homebrew-tap" => Some(("Homebrew taps", "monitor-only", "Monitor-only")),
        "docker" => Some(("Docker base images", "monitor-only", "Monitor-only")),
        "github-actions" => Some(("GitHub Actions", "monitor-only", "Monitor-only")),
        "system" => Some(("System packages", "monitor-only", "Monitor-only")),
        "unsupported" => Some(("Unsupported managers", "monitor-only", "Monitor-only")),
        _ => None,
    }
}

/// `_SUPPORT_ORDER` (:27).
const SUPPORT_ORDER: &[&str] = &[
    "npm",
    "pypi",
    "cargo",
    "go",
    "maven",
    "packagist",
    "rubygems",
    "homebrew",
    "homebrew-cask",
    "homebrew-tap",
    "docker",
    "github-actions",
    "system",
    "unsupported",
];

/// `ecosystem.replace("-", " ").title()` fallback (:48) — `str.title()`
/// title-cases every word; slugs here are lowercase alnum + separators, so a
/// per-word upper-first/lower-rest pass reproduces it.
fn title_fallback(ecosystem: &str) -> String {
    let mut out = String::with_capacity(ecosystem.len());
    let mut after_separator = true;
    for ch in ecosystem.replace('-', " ").chars() {
        if ch.is_alphanumeric() {
            if after_separator {
                out.extend(ch.to_uppercase());
            } else {
                out.extend(ch.to_lowercase());
            }
            after_separator = false;
        } else {
            out.push(ch);
            after_separator = true;
        }
    }
    out
}

/// `ecosystem_support_metadata(ecosystem)` (:45) — returns the Python dict
/// shape `{"display_name": …, "support_level": …, "support_label": …}`.
pub fn ecosystem_support_metadata(ecosystem: &str) -> Map<String, Value> {
    let (display_name, support_level, support_label) = match support_level(ecosystem) {
        Some((name, level, label)) => (name.to_string(), level.to_string(), label.to_string()),
        None => (
            title_fallback(ecosystem),
            "monitor-only".to_string(),
            "Monitor-only".to_string(),
        ),
    };
    let mut out = Map::new();
    out.insert("display_name".to_string(), json!(display_name));
    out.insert("support_level".to_string(), json!(support_level));
    out.insert("support_label".to_string(), json!(support_label));
    out
}

/// `ecosystem_support_matrix()` (:58) — ordered `{ecosystem, …}` dicts.
pub fn ecosystem_support_matrix() -> Vec<Map<String, Value>> {
    SUPPORT_ORDER
        .iter()
        .map(|ecosystem| {
            let mut entry = Map::new();
            entry.insert("ecosystem".to_string(), json!(ecosystem));
            entry.extend(ecosystem_support_metadata(ecosystem));
            entry
        })
        .collect()
}

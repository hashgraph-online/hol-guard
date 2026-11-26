//! Literal text rules for driver profiles. These mirror the patterns in
//! `contracts/browser-drivers/driver.v1.schema.json` without a regex engine, so a profile is
//! checked the same way whether or not a schema validator ran first.

use guard_contracts::BrowserVerbV1;

/// Names only first-party profiles may claim: generic browser and engine names, the MCP namespace
/// itself, shells and interpreters.
pub(super) const RESERVED_NAMES: &[&str] = &[
    "browser",
    "browsers",
    "chrome",
    "chromium",
    "playwright",
    "puppeteer",
    "firefox",
    "webkit",
    "safari",
    "edge",
    "devtools",
    "chrome-devtools",
    "mcp",
    "bash",
    "sh",
    "zsh",
    "fish",
    "pwsh",
    "powershell",
    "cmd",
    "node",
    "deno",
    "bun",
    "python",
    "python3",
    "ruby",
    "perl",
];

fn is_lower_alnum(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit()
}

/// `^[a-z0-9][a-z0-9._-]{0,63}$`: MCP server names, harness tool names and tool names.
pub(super) fn is_slug(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && is_lower_alnum(bytes[0])
        && bytes[1..]
            .iter()
            .all(|&byte| is_lower_alnum(byte) || matches!(byte, b'.' | b'_' | b'-'))
}

/// `^[a-z0-9][a-z0-9_.-]{0,63}$`: discriminator case values.
pub(super) fn is_case_key(value: &str) -> bool {
    is_slug(value)
}

/// `^browser\.[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$`.
pub(super) fn is_driver_id(value: &str) -> bool {
    let Some(slug) = value.strip_prefix("browser.") else {
        return false;
    };
    let bytes = slug.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && is_lower_alnum(bytes[0])
        && is_lower_alnum(bytes[bytes.len() - 1])
        && bytes
            .iter()
            .all(|&byte| is_lower_alnum(byte) || byte == b'-')
}

/// `^(@[a-z0-9][a-z0-9._-]{0,63}/)?[a-z0-9][a-z0-9._-]{0,63}$`.
pub(super) fn is_package(value: &str) -> bool {
    match split_package(value) {
        Some((Some(scope), name)) => is_slug(scope) && is_slug(name),
        Some((None, name)) => is_slug(name),
        None => false,
    }
}

fn split_package(value: &str) -> Option<(Option<&str>, &str)> {
    match value.strip_prefix('@') {
        Some(scoped) => {
            let (scope, name) = scoped.split_once('/')?;
            Some((Some(scope), name))
        }
        None => Some((None, value)),
    }
}

/// `^[a-z0-9][a-z0-9_-]{0,62}__$`: a tool-name prefix such as `mcp__example-pilot__`.
pub(super) fn is_tool_namespace(value: &str) -> bool {
    let Some(stem) = value.strip_suffix("__") else {
        return false;
    };
    let bytes = stem.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 63
        && is_lower_alnum(bytes[0])
        && bytes[1..]
            .iter()
            .all(|&byte| is_lower_alnum(byte) || matches!(byte, b'_' | b'-'))
}

pub(super) fn is_reserved(value: &str) -> bool {
    RESERVED_NAMES.contains(&value)
}

/// A reserved scope (`@playwright/...`) or a reserved package name, scoped or not.
pub(super) fn package_is_reserved(value: &str) -> bool {
    match split_package(value) {
        Some((scope, name)) => scope.is_some_and(is_reserved) || is_reserved(name),
        None => false,
    }
}

/// `browser__`, `mcp__playwright__` and the like. The MCP prefix is optional.
pub(super) fn namespace_is_reserved(value: &str) -> bool {
    let Some(stem) = value.strip_suffix("__") else {
        return false;
    };
    is_reserved(stem) || stem.strip_prefix("mcp__").is_some_and(is_reserved)
}

/// `^[A-Za-z_][A-Za-z0-9_]{0,63}$`: argument names and volatile fields.
pub(super) fn is_pointer(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && (bytes[0].is_ascii_alphabetic() || bytes[0] == b'_')
        && bytes
            .iter()
            .all(|&byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

/// `^--?[A-Za-z0-9][A-Za-z0-9-]{0,63}$`: a launch flag.
pub(super) fn is_flag(value: &str) -> bool {
    let body = value
        .strip_prefix("--")
        .or_else(|| value.strip_prefix('-'))
        .unwrap_or("");
    let bytes = body.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|&byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

/// `^(none|[A-Z][A-Za-z0-9]{1,63})$`.
pub(super) fn is_icon(value: &str) -> bool {
    let bytes = value.as_bytes();
    value == "none"
        || (bytes.len() >= 2
            && bytes.len() <= 64
            && bytes[0].is_ascii_uppercase()
            && bytes.iter().all(u8::is_ascii_alphanumeric))
}

/// Non-empty display text within `max_chars`, with no control characters.
pub(super) fn is_display_text(value: &str, max_chars: usize) -> bool {
    !value.trim().is_empty()
        && value.chars().count() <= max_chars
        && !value.chars().any(char::is_control)
}

/// An `https://` URL with a lowercase DNS host, no port, userinfo, query or fragment.
pub(super) fn is_https_url(value: &str) -> bool {
    if value.chars().count() > 256 {
        return false;
    }
    let Some(rest) = value.strip_prefix("https://") else {
        return false;
    };
    let (host, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
    let labels: Vec<&str> = host.split('.').collect();
    labels.len() >= 2
        && labels.iter().all(|label| is_dns_label(label))
        && labels
            .last()
            .is_some_and(|tld| tld.as_bytes()[0].is_ascii_lowercase())
        && !path
            .chars()
            .any(|ch| ch.is_whitespace() || ch.is_control() || ch == '?' || ch == '#')
}

fn is_dns_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 63
        && is_lower_alnum(bytes[0])
        && is_lower_alnum(bytes[bytes.len() - 1])
        && bytes
            .iter()
            .all(|&byte| is_lower_alnum(byte) || byte == b'-')
}

/// Manifest verbs are PascalCase, matching the schema enum.
pub(super) fn verb_from_manifest(value: &str) -> Option<BrowserVerbV1> {
    Some(match value {
        "Navigate" => BrowserVerbV1::Navigate,
        "Read" => BrowserVerbV1::Read,
        "Click" => BrowserVerbV1::Click,
        "Type" => BrowserVerbV1::Type,
        "Key" => BrowserVerbV1::Key,
        "Select" => BrowserVerbV1::Select,
        "Scroll" => BrowserVerbV1::Scroll,
        "Screenshot" => BrowserVerbV1::Screenshot,
        "Upload" => BrowserVerbV1::Upload,
        "Download" => BrowserVerbV1::Download,
        "Evaluate" => BrowserVerbV1::Evaluate,
        "CookieRead" => BrowserVerbV1::CookieRead,
        "CookieWrite" => BrowserVerbV1::CookieWrite,
        "StorageRead" => BrowserVerbV1::StorageRead,
        "StorageWrite" => BrowserVerbV1::StorageWrite,
        "Intercept" => BrowserVerbV1::Intercept,
        "Permission" => BrowserVerbV1::Permission,
        "TabControl" => BrowserVerbV1::TabControl,
        "Attach" => BrowserVerbV1::Attach,
        "Other" => BrowserVerbV1::Other,
        _ => return None,
    })
}

//! Names a design system gives its token documents.
//!
//! `color-tokens.json` and `design_tokens.ts` hold spacing, palette and
//! typography values. They share a word with access credentials, so the
//! classifiers in this crate ask here before treating a token name as
//! sensitive.

/// Clear a token marker only when the immediately preceding word names a
/// design value. A design word elsewhere cannot clear an API or vendor token:
/// `brand-github-token` and `style_api_token` stay sensitive. Singular
/// `theme-token` and `brand-token` may be access credentials, so they do not
/// receive the design-document exception.
pub(crate) fn design_system_token(words: &[&str], at: usize) -> bool {
    let Some(previous) = at.checked_sub(1).and_then(|index| words.get(index)) else {
        return false;
    };
    DESIGN_SYSTEM_WORDS.contains(previous)
        && !(words[at] == "token" && matches!(*previous, "brand" | "brands" | "theme" | "themes"))
        && !words
            .iter()
            .any(|word| CREDENTIAL_TOKEN_QUALIFIERS.contains(word))
}

/// Parts of a design system a token file is named for.
const DESIGN_SYSTEM_WORDS: &[&str] = &[
    "brand",
    "brands",
    "color",
    "colors",
    "colour",
    "colours",
    "design",
    "designs",
    "palette",
    "palettes",
    "spacing",
    "style",
    "styles",
    "theme",
    "themes",
    "typography",
    "typographies",
];

/// Explicit credential context overrides an otherwise adjacent design word.
const CREDENTIAL_TOKEN_QUALIFIERS: &[&str] = &[
    "access",
    "api",
    "auth",
    "aws",
    "bearer",
    "credential",
    "credentials",
    "github",
    "gitlab",
    "key",
    "login",
    "npm",
    "oauth",
    "private",
    "refresh",
    "secret",
    "secrets",
    "service",
    "session",
    "shopify",
    "slack",
    "stripe",
];

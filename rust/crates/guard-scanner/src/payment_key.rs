//! Live payment-processor secret keys, shared by the output scan and the
//! pre-tool screens so a key is caught before it is written as well as after
//! it is printed.

use std::sync::LazyLock;

use regex::Regex;

static LIVE_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b").expect("payment key pattern")
});

/// Whether `text` holds a live Stripe secret or restricted key whose body
/// mixes digits with both letter cases, the same test the output scan uses.
#[must_use]
pub fn holds_live_payment_key(text: &str) -> bool {
    LIVE_KEY
        .find_iter(text)
        .any(|matched| mixed_key_body(matched.as_str()))
}

/// Whether a key's body mixes digits with both letter cases. A stand-in such
/// as `sk_live_xxxxxxxx...` does not, so it is not treated as a key.
pub(crate) fn mixed_key_body(key: &str) -> bool {
    let body = key.rsplit('_').next().unwrap_or(key);
    body.bytes().any(|byte| byte.is_ascii_digit())
        && body.bytes().any(|byte| byte.is_ascii_uppercase())
        && body.bytes().any(|byte| byte.is_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::holds_live_payment_key;

    #[test]
    fn a_live_key_is_found_and_a_test_key_or_stand_in_is_not() {
        let body = "dx6YHRDb2BC8G4NQr2TyUskf";
        for live in [
            ["sk_", "live_", body].concat(),
            ["rk_", "live_", body].concat(),
        ] {
            assert!(
                holds_live_payment_key(&format!("{{\"value\": \"{live}\"}}")),
                "{live}"
            );
        }
        for clean in [
            ["sk_", "test_", body].concat(),
            ["sk_", "live_", "xxxxxxxxxxxxxxxxxxxxxxxx"].concat(),
            ["sk_", "live_", "..."].concat(),
        ] {
            assert!(!holds_live_payment_key(&clean), "{clean}");
        }
    }
}

//! A credential-named path segment is not an assignment.
//!
//! Rust, C++, PHP and Ruby join path segments with `::`, so ordinary source
//! and test output name modules such as `crate::token::Claims`,
//! `auth_token::issue(&user)` or `secret::scan::tests::finds_keys ... ok`.
//! The credential assignment rule reads the first `:` of `::` as a key-value
//! separator, which flagged Rust source reads and every `cargo test` run that
//! touched a credential-named module. No assignment syntax spells its
//! separator `::`.

/// Whether the first separator in a credential assignment match is a `::`
/// path separator.
pub(crate) fn is_path_segment(matched: &str) -> bool {
    matched
        .find([':', '='])
        .is_some_and(|index| matched[index..].starts_with("::"))
}

#[cfg(test)]
mod tests {
    use super::is_path_segment;
    use crate::scan_text;
    use guard_rules::MAX_SCAN_BYTES;

    fn credential_assignment(text: &str) -> bool {
        scan_text(text, true, true, MAX_SCAN_BYTES, None)
            .matches
            .iter()
            .any(|matched| matched.classifier == "credential-assignment")
    }

    #[test]
    fn credential_named_modules_are_paths() {
        for text in [
            "use crate::token::Claims;\n",
            "let claims = auth_token::issue(&user)?;\n",
            "test secret::scan::tests::finds_keys ... ok\n",
            "test result_pass::tests::reads_the_name ... ok\n",
            "    password::hash(&input, &salt)\n",
        ] {
            assert!(!credential_assignment(text), "{text}");
        }
    }

    #[test]
    fn single_colon_assignments_stay_flagged() {
        for text in [
            "token: Kq7xY2mN9pL4vR8tW3sZ\n",
            "auth_token=Kq7xY2mN9pL4vR8tW3sZ\n",
            "password: \"Hq3vN8xL2pW6tY9z\"\n",
        ] {
            assert!(credential_assignment(text), "{text}");
        }
        assert!(is_path_segment("token::Claims"));
        assert!(!is_path_segment("token: x"));
        assert!(!is_path_segment("token=::x"));
    }
}

//! A credential-named path segment is not an assignment.
//!
//! Rust, C++, PHP and Ruby join path segments with `::`, so ordinary source
//! and test output name modules such as `crate::token::Claims`,
//! `auth_token::issue(&user)` or `secret::scan::tests::finds_keys ... ok`.
//! The credential assignment rule reads the first `:` of `::` as a key-value
//! separator, which flagged Rust source reads and every `cargo test` run that
//! touched a credential-named module. No assignment syntax spells its
//! separator `::`. A path can still be what is assigned, as in a Ruby
//! constant `Secret::TOKEN = "..."`, so the path is read again as one name
//! (`Secret_TOKEN`) with the rest of its line.

/// Whether the first separator in a credential assignment match is a `::`
/// path separator, and the path read as one name (`Secret_TOKEN`) with
/// `rest_of_line` holds no credential assignment by `flagged`.
pub(crate) fn is_path_segment(
    matched: &str,
    rest_of_line: &str,
    flagged: impl Fn(&str) -> bool,
) -> bool {
    matched
        .find([':', '='])
        .filter(|&index| matched[index..].starts_with("::"))
        .is_some_and(|_| !flagged(&format!("{}{rest_of_line}", matched.replace("::", "_"))))
}

#[cfg(test)]
mod tests {
    use super::is_path_segment;
    use crate::scan_text;
    use guard_rules::MAX_SCAN_BYTES;

    // Built at runtime so secret scanners do not read the test source as a leak.
    const SAMPLE: &str = concat!("Kq7xY2mN", "9pL4vR8tW3sZ");

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
            format!("token: {SAMPLE}\n"),
            format!("auth_token={SAMPLE}\n"),
            format!("password: \"{SAMPLE}\"\n"),
        ] {
            assert!(credential_assignment(&text), "{text}");
        }
        let never = |_: &str| false;
        assert!(is_path_segment("token::Claims", "", never));
        assert!(!is_path_segment("token: x", "", never));
        assert!(!is_path_segment("token=::x", "", never));
        assert!(!is_path_segment("token::Claims", "", |_: &str| true));
    }

    #[test]
    fn an_assignment_after_a_path_stays_flagged() {
        for text in [
            format!("Secret::TOKEN = \"{SAMPLE}\"\n"),
            format!("secret::API_TOKEN={SAMPLE}\n"),
            format!("Auth::Config.password = \"{SAMPLE}\"\n"),
        ] {
            assert!(credential_assignment(&text), "{text}");
        }
    }
}

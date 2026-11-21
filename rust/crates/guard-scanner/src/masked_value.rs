//! Masked credential displays carry no secret.
//!
//! Tools that report on a login print the credential masked, such as
//! `gh auth status` showing `Token: gho_****…`. The assignment shape matches
//! the credential rule, but only a recognizable prefix or suffix is visible,
//! so blocking that output stopped agents from checking their login.

/// Whether an assignment value is a masked display: a run of at least four
/// mask characters and no more than eight visible letters or digits.
pub(crate) fn is_masked(value: &str) -> bool {
    let mut run = 0usize;
    let mut longest = 0usize;
    let mut visible = 0usize;
    for character in value.chars() {
        if matches!(character, '*' | '•' | '●') {
            run += 1;
            longest = longest.max(run);
        } else {
            run = 0;
            if character.is_ascii_alphanumeric() {
                visible += 1;
            }
        }
    }
    longest >= 4 && visible <= 8
}

#[cfg(test)]
mod tests {
    use super::is_masked;
    use crate::scan_text;
    use guard_rules::MAX_SCAN_BYTES;

    fn credential_assignment(text: &str) -> bool {
        scan_text(text, true, true, MAX_SCAN_BYTES, None)
            .matches
            .iter()
            .any(|matched| matched.classifier == "credential-assignment")
    }

    #[test]
    fn masked_values_show_no_secret() {
        assert!(is_masked(&format!("gho_{}", "*".repeat(36))));
        assert!(is_masked("****abcd"));
        assert!(is_masked("••••••••"));
        assert!(!is_masked("gho_***"));
        assert!(!is_masked("abcdefghij****"));
        assert!(!is_masked("****abcdefghijklmnopqrstuvwx"));
    }

    #[test]
    fn a_login_status_report_is_not_a_credential() {
        let report = format!(
            "github.com\n  ✓ Logged in to github.com account octocat (GH_TOKEN)\n  - Active account: true\n  - Git operations protocol: https\n  - Token: gho_{}\n  - Token scopes: 'gist', 'read:org', 'repo'\n",
            "*".repeat(36)
        );
        assert!(!credential_assignment(&report));
    }

    #[test]
    fn a_partly_masked_secret_is_still_a_credential() {
        let visible = "q7Lm2Xv9Rt4Kp8Wz";
        assert!(credential_assignment(&format!("token: {visible}****")));
        assert!(credential_assignment(&format!("password=****{visible}")));
    }
}

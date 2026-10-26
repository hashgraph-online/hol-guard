//! Assignments that copy a credential field from another object.
//!
//! Code that unpacks a parsed connection or settings object copies each
//! field by name, such as `password = admin.password` or
//! `token: session.token`. The assignment shape matches the credential rule,
//! but the value is a member access, not secret material, so reading the
//! script around it stopped agents mid-task.

use regex::Regex;
use std::sync::LazyLock;

/// An unquoted member access: identifiers joined by `.` or `?.`, followed
/// only by statement punctuation.
static MEMBER_ACCESS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*(?:\??\.[A-Za-z_][A-Za-z0-9_]*)+[;,)]*$")
        .expect("member access rule must compile")
});

/// The start of the next field after a `,`: a bare or quoted key followed by
/// `:` or `=`. Anything else after the comma, such as a literal, continues
/// the value as a tuple or argument list.
static NEXT_FIELD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"^(?:"[A-Za-z_][A-Za-z0-9_.-]*"|'[A-Za-z_][A-Za-z0-9_.-]*'|[A-Za-z_][A-Za-z0-9_.-]*)\s*[:=]"#)
        .expect("next field rule must compile")
});

/// Whether `text` holds nothing that continues a value: it is empty, a
/// trailing comment, or closes a bracket.
fn ends_value(text: &str) -> bool {
    let text = text.trim_start_matches(|character: char| {
        character.is_whitespace() || matches!(character, ')' | '}')
    });
    text.is_empty() || text.starts_with('#') || text.starts_with("//")
}

/// Field names that hold a credential, lowercased without `_` or `-`.
const CREDENTIAL_FIELDS: [&str; 6] = [
    "apikey",
    "credential",
    "credentials",
    "password",
    "secret",
    "token",
];

/// Whether a credential assignment's value is an unquoted member access
/// whose last field names a credential and ends its statement. A quoted value
/// is a string literal and is never treated as a copy, and neither is a
/// member access that its own statement or field continues, as in
/// `API_KEY = process.env.API_KEY || "literal"`. A following field or a
/// trailing comment does not continue it.
pub(crate) fn is_field_copy(matched: &str, rest_of_line: &str) -> bool {
    let end = rest_of_line.find([',', ';']).unwrap_or(rest_of_line.len());
    if !ends_value(&rest_of_line[..end]) {
        return false;
    }
    if rest_of_line[end..].starts_with(',') {
        let next = rest_of_line[end + 1..].trim_start();
        if !(ends_value(next) || NEXT_FIELD.is_match(next)) {
            return false;
        }
    }
    let Some(index) = matched.find([':', '=']) else {
        return false;
    };
    let value = matched[index + 1..].trim();
    if !MEMBER_ACCESS.is_match(value) {
        return false;
    }
    let field: String = value
        .trim_end_matches([';', ',', ')'])
        .rsplit('.')
        .next()
        .unwrap_or_default()
        .chars()
        .filter(|character| !matches!(character, '_' | '-'))
        .collect::<String>()
        .to_ascii_lowercase();
    CREDENTIAL_FIELDS.iter().any(|name| field.ends_with(name))
}

#[cfg(test)]
mod tests {
    use super::is_field_copy;
    use crate::scan_text;
    use guard_rules::MAX_SCAN_BYTES;

    fn credential_assignment(text: &str) -> bool {
        scan_text(text, true, true, MAX_SCAN_BYTES, None)
            .matches
            .iter()
            .any(|matched| matched.classifier == "credential-assignment")
    }

    #[test]
    fn member_accesses_that_name_a_credential_are_copies() {
        for matched in [
            "password = admin.password",
            "token: session.token,",
            "api_key=settings.api_key;",
            "client_secret = self._config.client_secret)",
            "password = cfg.Password",
            "token: response?.data?.accessToken",
        ] {
            assert!(is_field_copy(matched, ""), "{matched:?}");
        }
        for matched in [
            "password = \"admin.password\"",
            "password = 'admin.password'",
            "password = admin.username",
            "password = hunter2.production",
            "password = admin",
            "token = build.release",
            "token = session.token+literal",
            "password = admin.password.",
        ] {
            assert!(!is_field_copy(matched, ""), "{matched:?}");
        }
    }

    #[test]
    fn unpacking_a_connection_object_is_not_a_credential() {
        let source = "admin = urlsplit(url)\n\
            hostname = admin.hostname or \"\"\n\
            username = admin.username\n\
            password = admin.password\n\n\
            userinfo = \"\"\n";
        assert!(!credential_assignment(source));
        let javascript = "const client = connect({\n  token: session.token,\n  password: config.db?.password,\n});\n";
        assert!(!credential_assignment(javascript));
        for text in [
            "connect({ token: session.token, user: session.user })",
            "password = admin.password  # from the URL",
            "password: cfg.password, // database",
            "connect(token=session.token, user=session.user)",
            "{ token: session.token, \"user\": session.user }",
        ] {
            assert!(!credential_assignment(text), "{text:?}");
        }
    }

    #[test]
    fn literal_credentials_beside_copies_still_match() {
        for text in [
            "password = admin.password\npassword = hunter2-production-value",
            "token: session.token,\ntoken: \"a1b2c3d4e5f6g7h8\",",
            "password = \"admin.password\"",
            "const API_KEY = process.env.API_KEY || \"hunter2-production-value\";",
            "password = admin.password, \"hunter2-production-value\"",
            "password = admin.password, \"admin:hunter2-production\"",
            concat!("token = session.token, 'aGVsbG8gd29y", "bGQgc2VjcmV0='"),
        ] {
            assert!(credential_assignment(text), "{text:?}");
        }
    }
}

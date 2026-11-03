//! Assignments that copy a credential field from another object.
//!
//! Code that unpacks a parsed connection or settings object copies each
//! field by name, such as `password = admin.password` or
//! `token: session.token`. The assignment shape matches the credential rule,
//! but the value is a member access, not secret material, so reading the
//! script around it stopped agents mid-task.
//!
//! React and other JSX code hands a credential to a component the same way,
//! as `password={password}`, `approvalPassword={approvalPassword}` or
//! `token={session.token}`. The braces hold a variable, never a literal, so
//! CIGAR refused to read ordinary form components.

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
    if let Some((name, variable)) = jsx_prop(matched, rest_of_line) {
        let copy = format!("{name}={variable}");
        return is_field_copy(&copy, "") || crate::self_named_value::is_self_named(&copy, "");
    }
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

/// The prop name and the variable of a JSX attribute such as
/// `password={password}`, with or without spaces around `=`. The credential
/// rule's value stops before `}`, so the match ends at `password={password`
/// and the closing brace opens `rest_of_line`. After the brace only the tag or
/// the next attribute may follow; `Password={value};` in a connection string continues with `;` and
/// stays a literal.
fn jsx_prop<'a>(matched: &'a str, rest_of_line: &str) -> Option<(&'a str, &'a str)> {
    let index = matched.find(['=', ':'])?;
    let name = matched[..index].trim_end();
    let variable = matched[index..]
        .strip_prefix('=')?
        .trim_start()
        .strip_prefix('{')?;
    let after = rest_of_line.strip_prefix('}')?;
    let closes = after.is_empty()
        || after.starts_with(char::is_whitespace)
        || after.starts_with("/>")
        || after.starts_with('>');
    let bare = |text: &str| {
        !text.is_empty()
            && text.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '_' | '-')
            })
    };
    (closes && bare(name)).then_some((name, variable))
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
    fn jsx_props_that_pass_a_credential_variable_are_copies() {
        for text in [
            "<Field password={password} />",
            "              approvalPassword={approvalPassword}\n",
            "<Login token={session.token}>",
            "<Form apiKey={props.apiKey}\n  user={user} />",
            "<Reset password={password2}/>",
            "<Field password = {password} />",
        ] {
            assert!(!credential_assignment(text), "{text:?}");
        }
    }

    #[test]
    fn jsx_braces_around_a_literal_still_match() {
        for text in [
            "<Field password={hunter2production} />",
            "<Field password={\"hunter2-production\"} />",
            "<Field password={'hunter2-production'} />",
            "password={password};",
            "password={password}+tail",
            "<Login token={session.user} />",
            "<Field password = {hunter2production} />",
        ] {
            assert!(credential_assignment(text), "{text:?}");
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

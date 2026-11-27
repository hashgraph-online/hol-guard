use crate::scan_text;
use guard_rules::MAX_SCAN_BYTES;

fn flagged(text: &str) -> bool {
    scan_text(text, true, true, MAX_SCAN_BYTES, None)
        .matches
        .iter()
        .any(|matched| matched.classifier == "credential-assignment")
}

// Built from parts so this file carries no credential-shaped line.
fn value() -> String {
    ["q8Zr4LmT", "2vXn9KpW"].concat()
}

#[test]
fn template_with_empty_credentials_is_clean() {
    let template = "API_BASE_URL=http://127.0.0.1:3000\nAPI_TOKEN=\nNODE_ENV=development\nSESSION_SECRET=\nFEATURE_ROUTE_TIMEOUT_MS=2000\n";
    assert!(!flagged(template));
    let numbered = "1\tAPI_TOKEN=\n2\tNODE_ENV=development\n";
    assert!(!flagged(numbered));
    let spaced = "API_TOKEN=  \nNODE_ENV=development\n";
    assert!(!flagged(spaced));
}

#[test]
fn credential_on_its_own_line_is_still_found() {
    let value = value();
    for text in [
        format!("API_TOKEN={value}\n"),
        format!("API_TOKEN= {value}\n"),
        format!("API_TOKEN=\nSESSION_SECRET={value}\n"),
    ] {
        assert!(flagged(&text), "{text:?}");
    }
}

#[test]
fn quoted_value_wrapped_below_its_name_is_still_found() {
    let value = value();
    for text in [
        format!("const apiToken =\n  \"{value}\";\n"),
        format!("api_token:\n  '{value}'\n"),
    ] {
        assert!(flagged(&text), "{text:?}");
    }
}

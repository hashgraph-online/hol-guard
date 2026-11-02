use super::*;

fn origin(url: &str) -> Option<String> {
    remote_mcp_origin(url)
}

#[test]
fn keeps_scheme_host_and_path_only() {
    assert_eq!(
        origin("HTTPS://user:pw@MCP.Example.Test:8443/v1/mcp?key=secret#frag").as_deref(),
        Some("https://mcp.example.test:8443/v1/mcp")
    );
    assert_eq!(
        origin("https://mcp.example.test/mcp").as_deref(),
        Some("https://mcp.example.test/mcp")
    );
    assert_eq!(
        origin("  http://mcp.example.test  ").as_deref(),
        Some("http://mcp.example.test")
    );
    assert_eq!(
        origin("https://[2001:DB8::1]:443/mcp").as_deref(),
        Some("https://[2001:db8::1]:443/mcp")
    );
    // urlsplit deletes tabs and line breaks anywhere in the URL.
    assert_eq!(
        origin("ht\ttps://mcp.example.test/m\ncp").as_deref(),
        Some("https://mcp.example.test/mcp")
    );
}

#[test]
fn rejects_what_is_not_a_remote_http_server() {
    for rejected in [
        "${MCP_URL}",
        "file:///tmp/sock",
        "ftp://mcp.example.test/",
        "https:///path",
        "",
        "https://mcp.example.test:port/mcp",
        "https://mcp.example.test:70000/mcp",
        "https://[::1/mcp",
        "https://mcp.example.test/a b",
        "https://mcp.example.test/a@b",
        "https://mcp.example.test/a\u{7}b",
        "https://mcp.example.test/a\u{200b}b",
    ] {
        assert_eq!(origin(rejected), None, "{rejected:?}");
    }
}

#[test]
fn an_origin_longer_than_the_cap_is_rejected() {
    let segments = vec!["abc"; 130].join("/");
    let url = format!("https://mcp.example.test/{segments}");
    assert!(url.chars().count() > MAX_ORIGIN_CHARS);
    assert_eq!(origin(&url), None);
    let short = vec!["abc"; 100].join("/");
    assert!(origin(&format!("https://mcp.example.test/{short}")).is_some());
}

#[test]
fn masks_path_segments_that_look_like_keys() {
    assert_eq!(
        origin("https://mcp.example.test/api/mcp/s/a1b2c3d4e5/mcp").as_deref(),
        Some("https://mcp.example.test/api/mcp/s/[masked]/mcp")
    );
    assert_eq!(
        origin(&format!("https://mcp.example.test/v1/{}", "k".repeat(24))).as_deref(),
        Some("https://mcp.example.test/v1/[masked]")
    );
    assert_eq!(
        origin("https://mcp.example.test/2025-06-18/mcp").as_deref(),
        Some("https://mcp.example.test/2025-06-18/mcp")
    );
    // Eight letters with no digit, and seven characters that mix both, stay.
    assert_eq!(
        origin("https://mcp.example.test/abcdefgh/abc1234").as_deref(),
        Some("https://mcp.example.test/abcdefgh/abc1234")
    );
}

#[test]
fn masking_counts_unicode_letters_and_digits_as_python_does() {
    // U+0661 is an Arabic-Indic digit and U+00E9 a letter for str.isdigit and
    // str.isalpha; U+00B2 (superscript two) is a digit too.
    assert_eq!(
        origin("https://mcp.example.test/\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{661}")
            .as_deref(),
        Some("https://mcp.example.test/[masked]")
    );
    assert_eq!(
        origin("https://mcp.example.test/abcdefg\u{b2}").as_deref(),
        Some("https://mcp.example.test/[masked]")
    );
    // Fifteen characters with no digit stay; the length is in code points.
    let accented = "\u{e9}".repeat(15);
    assert_eq!(
        origin(&format!("https://mcp.example.test/{accented}")),
        Some(format!("https://mcp.example.test/{accented}"))
    );
}

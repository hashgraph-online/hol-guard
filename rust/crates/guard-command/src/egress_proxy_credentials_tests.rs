use super::*;

#[test]
fn the_account_is_the_proxy_urls_digest_and_never_the_url() {
    let key = proxy_credential_key("https://proxy.example:8443");
    assert_eq!(key.len(), 64);
    assert!(key.bytes().all(|byte| byte.is_ascii_hexdigit()));
    // sha256("https://proxy.example:8443"), as `proxy_credential_key` computes it.
    assert_eq!(
        key,
        hex::encode(sha2::Sha256::digest(b"https://proxy.example:8443"))
    );
    assert_ne!(key, proxy_credential_key("https://proxy.example:8444"));
}

#[test]
fn a_well_formed_record_is_the_proxys_own_credential() {
    let credentials =
        parse_proxy_credentials(br#"{"username":"svc","password":"secret"}"#).expect("parsed");
    assert_eq!(credentials.username, "svc");
    assert_eq!(credentials.password, "secret");
}

#[test]
fn a_record_that_is_not_a_credential_fails_closed() {
    for raw in [
        // Not JSON, not an object, and an object of the wrong shape.
        &b"not json"[..],
        br#"["svc","secret"]"#,
        br#"{"username":"svc"}"#,
        br#"{"username":"svc","password":"secret","extra":1}"#,
        // Both fields must be present, string-typed and non-empty.
        br#"{"username":"svc","password":1}"#,
        br#"{"username":"","password":"secret"}"#,
        br#"{"username":"svc","password":""}"#,
        // A username with `:` or either field with a newline cannot be spelled
        // into a `Proxy-Authorization` header without changing what it says.
        br#"{"username":"svc:admin","password":"secret"}"#,
        br#"{"username":"svc\nX","password":"secret"}"#,
        br#"{"username":"svc","password":"secret\r\nProxy-Authorization: other"}"#,
    ] {
        assert_eq!(
            parse_proxy_credentials(raw).err(),
            Some("managed_proxy_credentials_invalid"),
            "{}",
            String::from_utf8_lossy(raw)
        );
    }
}

#[test]
fn a_records_trailing_newline_is_not_part_of_it_and_an_empty_record_is_none() {
    assert_eq!(present(b"secret\r\n".to_vec()), Some(b"secret".to_vec()));
    assert_eq!(present(b"\n".to_vec()), None);
    assert_eq!(present(Vec::new()), None);
}

#[test]
fn a_credential_a_uri_authority_cannot_carry_is_refused_by_its_own_code() {
    for raw in [
        // `@`, `/`, `?` and `#` would end the authority the transport parses the
        // credentials back out of, moving or truncating what reaches the proxy.
        &br#"{"username":"svc","password":"pass@word"}"#[..],
        br#"{"username":"svc","password":"pass/word"}"#,
        br#"{"username":"svc","password":"pass?word"}"#,
        br#"{"username":"svc","password":"pass#word"}"#,
        br#"{"username":"svc@corp","password":"secret"}"#,
        // Whitespace, percent escapes (never decoded) and non-ASCII likewise.
        br#"{"username":"svc","password":"pass word"}"#,
        br#"{"username":"svc","password":"pass%40word"}"#,
        br#"{"username":"svc","password":"p\u00e4ssword"}"#,
    ] {
        assert_eq!(
            parse_proxy_credentials(raw).err(),
            Some("managed_proxy_credentials_unsupported"),
            "{}",
            String::from_utf8_lossy(raw)
        );
    }
    // The ordinary shapes a proxy credential takes still pass.
    let credentials =
        parse_proxy_credentials(br#"{"username":"svc-1_x","password":"a:b!$&'()*+,;=~.-_"}"#)
            .expect("parsed");
    assert_eq!(credentials.username, "svc-1_x");
    assert_eq!(credentials.password, "a:b!$&'()*+,;=~.-_");
}

#[test]
fn a_header_caller_keeps_a_credential_a_uri_authority_cannot_carry() {
    let credentials =
        parse_proxy_record(br#"{"username":"svc@corp","password":"p\u00e4ss word%40"}"#)
            .expect("parsed");
    assert_eq!(credentials.username, "svc@corp");
    assert_eq!(credentials.password, "p\u{e4}ss word%40");
    assert_eq!(
        parse_proxy_record(br#"{"username":"svc:admin","password":"secret"}"#).err(),
        Some("managed_proxy_credentials_invalid")
    );
}

#[test]
fn a_credential_manager_blob_reads_as_utf8_or_utf16le_text() {
    let utf16: Vec<u8> = "{\"u\":\"\u{e4}\"}"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    assert_eq!(
        windows_credential_text(br#"{"u":"x"}"#.to_vec()),
        Some(br#"{"u":"x"}"#.to_vec())
    );
    assert_eq!(
        windows_credential_text(utf16),
        Some("{\"u\":\"\u{e4}\"}".as_bytes().to_vec())
    );
    // Empty, an odd UTF-16 length, and a lone surrogate are no record.
    assert_eq!(windows_credential_text(Vec::new()), None);
    assert_eq!(windows_credential_text(vec![0xff, 0xfe, 0x41]), None);
    assert_eq!(windows_credential_text(vec![0x00, 0xd8]), None);
}

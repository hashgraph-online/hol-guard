use super::holds_code_secret;

/// Values are assembled from pieces so this file does not itself hold one.
fn joined(parts: &[&str]) -> String {
    parts.concat()
}

#[test]
fn a_wrapped_mixed_literal_handed_to_a_credential_setter_is_a_secret() {
    for text in [
        format!(
            "    client.setClientSecret(new SecretValue(\"{}\"));\n",
            joined(&["q7Zv", "T2kM", "bR"])
        ),
        format!(
            "cfg.setRefreshToken(new RefreshToken(\"{}\"));\n",
            joined(&["8wPl", "hS3n", "xJgd"])
        ),
        format!(
            "spec.setSecretKey(new SecretKeySpec(\"{}\"));\n",
            joined(&["q7Zv", "T2kM", "bR9x"])
        ),
        format!(
            "cfg.setPasswordValue(new Secret(\"{}\"));\n",
            joined(&["8wPl", "hS3n", "xJgd"])
        ),
    ] {
        assert!(holds_code_secret(&text), "{text}");
    }
}

#[test]
fn placeholder_word_and_digest_literals_in_wrapped_setters_are_not_secrets() {
    for text in [
        "cfg.setPassword(new Password(\"password1\"));\n",
        "cfg.setSecret(new Secret(\"abcdef12\"));\n",
        "cfg.setToken(new Token(\"deadbeef0123\"));\n",
        "cfg.setToken(new Token(\"TOKENVALUE\"));\n",
        "cfg.setToken(new Token(\"test1234\"));\n",
        "cfg.setToken(new Token(System.getenv(\"TOKEN\")));\n",
        "cfg.setName(new Name(\"q7ZvT2kMbR\"));\n",
    ] {
        assert!(!holds_code_secret(text), "{text}");
    }
}

#[test]
fn dashed_random_groups_handed_to_a_credential_setter_are_a_secret() {
    for text in [
        format!(
            "Session.setToken(\"{}\");\n",
            joined(&["qzvt-kmbr", "-wplh-snxj"])
        ),
        format!(
            "auth.setAccessToken(\"{}\");\n",
            joined(&["hjqw-tzrk", "-vnbm-xlp4"])
        ),
    ] {
        assert!(holds_code_secret(&text), "{text}");
    }
}

#[test]
fn dashed_words_runs_and_hex_in_a_setter_are_not_secrets() {
    for text in [
        "Session.setToken(\"abcd-efgh-ijkl-mnop\");\n",
        "Session.setToken(\"test-demo-code-page\");\n",
        "Session.setToken(\"dead-beef-cafe-f00d\");\n",
        "Session.setToken(\"xxxx-xxxx-xxxx-xxxx\");\n",
        "Session.setToken(\"read-only-mode-here\");\n",
        "Session.setToken(\"1234-5678-9012-3456\");\n",
        "Session.setLabel(\"qzvt-kmbr-wplh-snxj\");\n",
    ] {
        assert!(!holds_code_secret(text), "{text}");
    }
}

#[test]
fn an_auth_token_comment_with_sixty_four_hex_characters_is_a_secret() {
    let hex = joined(&[
        "9e107d9d372bb682",
        "6bd81d3542a419d6",
        "4c1b7a2e93f05d18",
        "e7a9c3f1026b84d5",
    ]);
    for text in [
        format!("// Example: Use the auth token {hex}\n"),
        format!("# authentication token {}\n", hex.to_ascii_uppercase()),
        format!("/* auth_token {hex} */\n"),
    ] {
        assert!(holds_code_secret(&text), "{text}");
    }
}

#[test]
fn digests_and_short_values_after_token_words_are_not_secrets() {
    let hex = joined(&[
        "9e107d9d372bb682",
        "6bd81d3542a419d6",
        "4c1b7a2e93f05d18",
        "e7a9c3f1026b84d5",
    ]);
    for text in [
        format!("// sha256 digest {hex}\n"),
        "// auth token abc123\n".to_string(),
        "// read the auth token from the environment\n".to_string(),
        format!("// auth token {}\n", &hex[..40]),
    ] {
        assert!(!holds_code_secret(&text), "{text}");
    }
}

#[test]
fn a_long_array_named_key_spelled_in_hex_is_a_secret() {
    let text = format!(
        "    private static final long[] KEY = {{{}, {}}};\n",
        joined(&["0x9f3c2a7d", "5e1b4c86L"]),
        joined(&["0x41d8e6b2", "07c95fa3L"])
    );
    assert!(holds_code_secret(&text), "{text}");
    let trailing = format!(
        "long[] SIGNING_KEY_WORDS = {{\n    {},\n    {},\n}};\n",
        joined(&["0x9f3c2a7d", "5e1b4c86"]),
        joined(&["-0x41d8e6b2", "07c95fa3L"])
    );
    assert!(holds_code_secret(&trailing), "{trailing}");
}

#[test]
fn filler_decimal_and_repeated_long_keys_are_not_secrets() {
    for text in [
        "long[] KEY = {0x0000000000000000L, 0x0000000000000000L};\n".to_string(),
        "long[] KEY = {0xFFFFFFFFFFFFFFFFL, 0xffffffffffffffffL};\n".to_string(),
        format!("long[] KEY = {{0x{0}L, 0x{0}L}};\n", "deadbeef".repeat(2)),
        "long[] KEY_ROTATION_TIMES = {1700000000000L, 1700086400000L};\n".to_string(),
        "long[] KEY_ROTATION_TIMES = {170000000000000, 170008640000000};\n".to_string(),
        format!(
            "long[] MONKEY_HASHES = {{{}, {}}};\n",
            joined(&["0x9f3c2a7d", "5e1b4c86L"]),
            joined(&["0x41d8e6b2", "07c95fa3L"])
        ),
        format!(
            "long[] KEYBOARD_SCANCODES = {{{}, {}}};\n",
            joined(&["0x9f3c2a7d", "5e1b4c86L"]),
            joined(&["0x41d8e6b2", "07c95fa3L"])
        ),
    ] {
        assert!(!holds_code_secret(&text), "{text}");
    }
}

#[test]
fn long_tables_under_other_names_or_with_small_values_are_not_secrets() {
    for text in [
        "private static final long[] ROUND_CONSTANTS = {0x428a2f98d728ae22L, 0x7137449123ef65cdL};\n",
        "private static final long[] KEY = {1L, 2L, 3L};\n",
        "long[] key = {0x428a2f98d728ae22L, 0x7137449123ef65cdL};\n",
        "long[] KEY = new long[4];\n",
    ] {
        assert!(!holds_code_secret(text), "{text}");
    }
}

#[test]
fn dashed_noise_under_an_api_key_name_is_a_secret() {
    for text in [
        format!(
            "os.environ[\"MAILGUN_API_KEY\"] = \"{}\"\n",
            joined(&["key-", "7302918", "-qzvt-kmbrwp"])
        ),
        format!("  apiKey: '{}',\n", joined(&["wq8-zvtk", "-mbr4-plhs"])),
    ] {
        assert!(holds_code_secret(&text), "{text}");
    }
}

#[test]
fn uuid_word_and_placeholder_api_keys_are_not_secrets() {
    let uuid = joined(&["f47ac10b-58cc", "-4372-a567", "-0e02b2c3d479"]);
    for text in [
        format!("apiKey: '{uuid}',\n"),
        format!("data-api-key=\"key1234567{}\"\n", &uuid[8..]),
        "API_KEY = \"your-api-key-here\"\n".to_string(),
        "API_KEY = \"test-key-1234\"\n".to_string(),
        "api_key: 'v2-read-only-scope'\n".to_string(),
        "API_KEY = \"dead-beef-cafe\"\n".to_string(),
        "api_key: 'sk-proj-placeholder'\n".to_string(),
        format!("API_KEY_ID = \"{}\"\n", joined(&["wq8-zvtk", "-mbr4-plhs"])),
        format!("apiKeyId: '{}',\n", joined(&["wq8-zvtk", "-mbr4-plhs"])),
        format!("apiKeyIds: '{}',\n", joined(&["wq8-zvtk", "-mbr4-plhs"])),
        format!(
            "API_KEY_IDS = \"{}\"\n",
            joined(&["wq8-zvtk", "-mbr4-plhs"])
        ),
    ] {
        assert!(!holds_code_secret(&text), "{text}");
    }
}

#[test]
fn a_secret_name_setter_and_filler_auth_tokens_are_not_secrets() {
    for text in [
        "cfg.setSecretName(new Name(\"q7ZvT2kMbR\"));\n".to_string(),
        "cfg.setTokenEndpoint(new Url(\"q7ZvT2kMbR\"));\n".to_string(),
        format!("// auth token {}\n", "0".repeat(64)),
        format!("// auth token {}\n", "f".repeat(64)),
        format!("// auth token {}\n", "0123456789abcdef".repeat(4)),
        format!("// auth token {}\n", "ab".repeat(32)),
    ] {
        assert!(!holds_code_secret(&text), "{text}");
    }
}

#[test]
fn a_key_list_suffix_that_is_not_an_id_segment_is_still_screened() {
    for name in ["API_KEY_KIDS", "API_KEY_BIDS"] {
        let text = format!("{name} = \"{}\"\n", joined(&["wq8-zvtk", "-mbr4-plhs"]));
        assert!(holds_code_secret(&text), "{text}");
    }
}

#[test]
fn a_key_name_segment_in_a_long_table_is_screened() {
    let text = format!(
        "long[] HMAC_KEYS_V2 = {{{}, {}}};\n",
        joined(&["0x9f3c2a7d", "5e1b4c86L"]),
        joined(&["0x41d8e6b2", "07c95fa3L"])
    );
    assert!(holds_code_secret(&text), "{text}");
}

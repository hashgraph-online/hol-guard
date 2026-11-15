use super::holds_bare_secret;

/// Values are assembled from pieces so this file does not itself hold one.
fn joined(parts: &[&str]) -> String {
    parts.concat()
}

#[test]
fn a_random_token_alone_on_a_list_line_is_a_secret() {
    for text in [
        format!("- {}\n", joined(&["qzvtx", "kmbrw", "plhsn"])),
        format!("secrets:\n  - {}\n", joined(&["hjqwt", "zrkvn", "bmxlp4"])),
        format!("1. {}\n", joined(&["wjtdq", "xgnfk", "rwzvb"])),
        format!("- {}\r\n- next\r\n", joined(&["qzvtx", "kmbrw", "plhsn"])),
    ] {
        assert!(holds_bare_secret(&text), "{text}");
    }
}

#[test]
fn words_digests_and_inline_tokens_on_list_lines_are_not_secrets() {
    for text in [
        "- troubleshooting\n- interoperability\n".to_string(),
        "        - adaptiveavgpool2d\n".to_string(),
        format!("- {}\n", joined(&["9e107d9d372bb682", "6bd81d3542a419d6"])),
        format!("see {} for details\n", joined(&["qzvtx", "kmbrw", "plhsn"])),
        format!("- {} and more\n", joined(&["qzvtx", "kmbrw", "plhsn"])),
        "- xxxxxxxxxxxxxxx\n".to_string(),
    ] {
        assert!(!holds_bare_secret(&text), "{text}");
    }
}

#[test]
fn a_mixed_key_after_an_api_label_is_a_secret() {
    let text = format!("    Pastebin Rest API: {}\n", joined(&["k7Tq2", "xP9w"]));
    assert!(holds_bare_secret(&text), "{text}");
}

#[test]
fn versions_and_words_after_an_api_label_are_not_secrets() {
    for text in [
        "API: v2\n",
        "Public API: version12\n",
        "API: deprecated\n",
        "API: 1234abcd\n",
    ] {
        assert!(!holds_bare_secret(text), "{text}");
    }
}

#[test]
fn a_digit_run_given_to_a_token_secret_or_key_name_is_a_secret() {
    for text in [
        format!("config.access_token = '{}'\n", joined(&["8372", "91046"])),
        format!(
            "config.oauth_token_secret = \"{}\"\n",
            joined(&["58203", "71946"])
        ),
        format!(
            "config.consumer_key = '{}'\n",
            joined(&["730", "418", "295"])
        ),
    ] {
        assert!(holds_bare_secret(&text), "{text}");
    }
}

#[test]
fn counting_runs_and_round_numbers_are_not_secrets() {
    for text in [
        "max_tokens = \"100000000\"\n",
        "api_key = '1234567890'\n",
        "token_ttl = '987654321'\n",
        "key = 837291046\n",
        "token_expires_at = '1739528604'\n",
        "refresh_token = '1704067200'\n",
        "secret_rotation_time = '384029175'\n",
    ] {
        assert!(!holds_bare_secret(text), "{text}");
    }
}

#[test]
fn a_mixed_value_given_to_an_api_id_name_is_a_secret() {
    for text in [
        format!("API_CLIENT_ID = '{}'\n", joined(&["k3jd8", "sl2qp"])),
        format!("  PASTE_API_ID = \"{}\"\n", joined(&["a7q", "w2k", "r9z"])),
    ] {
        assert!(holds_bare_secret(&text), "{text}");
    }
}

#[test]
fn other_ids_and_word_values_are_not_api_secrets() {
    for text in [
        format!(
            "VAPI_DEFAULT_VOICE_ID = \"{}\"\n",
            joined(&["k3jd8", "sl2qp"])
        ),
        "GOOGLE_API_ID = 'project123'\n".to_string(),
        "API_VERSION_ID = 'stable'\n".to_string(),
        format!(
            "API_SCHEMA_ID = '{}'\n",
            joined(&["9e107d9d372bb682", "6bd81d3542a419d6"])
        ),
        "API_CLIENT_ID = 'xxxx1234xxxx'\n".to_string(),
        "API_CLIENT_ID = 'your9api8id'\n".to_string(),
    ] {
        assert!(!holds_bare_secret(&text), "{text}");
    }
}

#[test]
fn an_sql_auth_string_is_a_secret() {
    let text = format!(
        "ALTER USER 'app'@'%' IDENTIFIED WITH 'mysql_native_password' AS '*{}';",
        joined(&["6C8989366EAF75BB", "670AD8EA7A7FC117", "6A95CEF4"])
    );
    assert!(holds_bare_secret(&text), "{text}");
    let short = format!(
        "CREATE USER u IDENTIFIED WITH 'mysql_native_password' AS '*{}';",
        joined(&["qvz", "kt"])
    );
    assert!(holds_bare_secret(&short), "{short}");
}

#[test]
fn placeholder_sql_auth_strings_are_not_secrets() {
    for text in [
        "CREATE USER u IDENTIFIED WITH 'caching_sha2_password' AS 'xxxxxxxx';",
        "ALTER USER u IDENTIFIED AS '<password>';",
        "CREATE USER u IDENTIFIED WITH 'caching_sha2_password' AS '<hash>';",
        "CREATE USER u IDENTIFIED WITH 'mysql_native_password' AS '${PASSWORD_HASH}';",
        "SELECT name AS 'alias' FROM t;",
        "CREATE USER 'app'@'localhost' IDENTIFIED WITH auth_socket AS 'nginx';",
        "CREATE USER app IDENTIFIED WITH 'auth_socket' AS 'deploy';",
        "CREATE USER u IDENTIFIED WITH authentication_ldap_simple AS 'uid=u9x2,ou=people';",
    ] {
        assert!(!holds_bare_secret(text), "{text}");
    }
}

#[test]
fn a_short_random_secret_field_is_a_secret() {
    for text in [
        format!("assert data['secret'] == '{}'\n", joined(&["zqx", "vbk"])),
        format!(
            "[{{\"owner\":\"jroe\",\"secret\":\"{}\"}}]",
            joined(&["wjt", "dqx"])
        ),
    ] {
        assert!(holds_bare_secret(&text), "{text}");
    }
}

#[test]
fn word_and_placeholder_secret_fields_are_not_secrets() {
    for text in [
        "{\"secret\": \"changeme\"}",
        "assert data['secret'] == 'hunter'",
        "{\"secret\": \"letmein\"}",
        "{\"secret\": \"redacted\"}",
    ] {
        assert!(!holds_bare_secret(text), "{text}");
    }
}

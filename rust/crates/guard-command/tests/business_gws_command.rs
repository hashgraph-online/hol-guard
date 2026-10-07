use guard_command::business_gmail_wire::GmailSendWireErrorV1;
use guard_command::business_gws_command::{GwsGmailCommandErrorV1, GwsGmailSendCommandInputV1};
use guard_command::MAX_COMMAND_BYTES;

const PARAMS: &str = r#"{"userId":"me"}"#;
const BODY: &str = r#"{"raw":"Zg"}"#;

fn command(options: &str) -> String {
    format!("gws gmail users messages send {options}")
}

fn normal() -> String {
    command(&format!("--params '{PARAMS}' --json '{BODY}'"))
}

#[test]
fn native_parser_recovers_exact_inline_bytes_and_owns_original_source() {
    let original = normal();
    let input = GwsGmailSendCommandInputV1::from_owned_posix_command(original.clone()).unwrap();
    assert_eq!(input.command_text(), original);
    assert_eq!(input.wire_input().params_bytes(), PARAMS.as_bytes());
    assert_eq!(input.wire_input().body_bytes(), BODY.as_bytes());
    assert_eq!(input.wire_input().mime_bytes(), b"f");
    // Independently computed with Python SHA-256 and unsigned BE length framing.
    assert_eq!(
        input.input_binding(),
        "9e7ab4f8cfefd70f7e1b43f85a72b3095ac3faa9fc65c43eeba109d95a3d46c3"
    );
}

#[test]
fn reordered_and_assignment_options_preserve_payload() {
    for options in [
        format!("--json='{BODY}' --params='{PARAMS}'"),
        format!("--params='{PARAMS}' --json '{BODY}'"),
        r#"--params "{\"userId\":\"me\"}" --json "{\"raw\":\"Zg\"}""#.to_owned(),
    ] {
        let input =
            GwsGmailSendCommandInputV1::from_owned_posix_command(command(&options)).unwrap();
        assert_eq!(input.wire_input().params_bytes(), PARAMS.as_bytes());
        assert_eq!(input.wire_input().body_bytes(), BODY.as_bytes());
    }
}

#[test]
fn preserved_json_escapes_decode_but_invalid_resource_controls_still_fail() {
    let candidate = command(
        r#"--params "{\"userId\":\"\u006de\"}" --json "{\"raw\":\"Zg\",\"threadId\":\"thread-\u0061\"}""#,
    );
    let input = GwsGmailSendCommandInputV1::from_owned_posix_command(candidate).unwrap();
    assert_eq!(
        input.wire_input().params_bytes(),
        br#"{"userId":"\u006de"}"#
    );
    assert_eq!(
        input.wire_input().body_bytes(),
        br#"{"raw":"Zg","threadId":"thread-\u0061"}"#
    );
    assert_eq!(input.wire_input().thread_id(), Some("thread-a"));
    let control = command(
        r#"--params "{\"userId\":\"me\"}" --json "{\"raw\":\"Zg\",\"threadId\":\"line\nfeed\"}""#,
    );
    assert_eq!(
        GwsGmailSendCommandInputV1::from_owned_posix_command(control).err(),
        Some(GwsGmailCommandErrorV1::Wire(GmailSendWireErrorV1::Invalid))
    );
    for escape in [r#"\$THREAD"#, r#"\`value\`"#] {
        let unsupported = command(&format!(
            r#"--params '{PARAMS}' --json "{{\"raw\":\"Zg\",\"threadId\":\"{escape}\"}}""#
        ));
        assert_eq!(
            GwsGmailSendCommandInputV1::from_owned_posix_command(unsupported).err(),
            Some(GwsGmailCommandErrorV1::UnsupportedContext)
        );
    }
}

#[test]
fn ambiguous_missing_and_duplicate_options_fail_with_bounded_errors() {
    for options in [
        "".to_owned(),
        "--params".to_owned(),
        format!("--params '{PARAMS}'"),
        format!("--json '{BODY}'"),
        format!("--params '{PARAMS}' --params='{PARAMS}' --json '{BODY}'"),
        format!("--params '{PARAMS}' --json '{BODY}' --json='{BODY}'"),
        format!("--params --json '{BODY}'"),
    ] {
        assert!(GwsGmailSendCommandInputV1::from_owned_posix_command(command(&options)).is_err());
    }
}

#[test]
fn unsupported_side_effect_flags_and_generic_routes_never_decode() {
    for extra in [
        "--upload message.eml",
        "--upload-content-type message/rfc822",
        "--page-all",
        "--page-limit 5",
        "--output output.json",
        "-o output.json",
        "--sanitize template",
        "--dry-run",
        "--format json",
        "--",
        "extra",
        "--unknown=value",
    ] {
        assert!(
            GwsGmailSendCommandInputV1::from_owned_posix_command(format!("{} {extra}", normal()))
                .is_err()
        );
    }
    for prefix in [
        "./gws",
        "/trusted/gws",
        "gws.exe",
        "gog",
        "gws gmail:v1",
        "gws --api-version v1 gmail",
        "gws gmail users drafts",
        "gws drive files",
        "gws gmail +send",
    ] {
        let candidate = format!("{prefix} users messages send --params '{PARAMS}' --json '{BODY}'");
        assert!(GwsGmailSendCommandInputV1::from_owned_posix_command(candidate).is_err());
    }
}

#[test]
fn wrappers_environment_and_compounds_cannot_change_launch_context() {
    let valid = normal();
    for candidate in [
        format!("PATH=/other {valid}"),
        format!("ACCOUNT=personal {valid}"),
        format!("sudo {valid}"),
        format!("env {valid}"),
        format!("command {valid}"),
        format!("{valid}; true"),
        format!("true && {valid}"),
        format!("{valid} | cat"),
        format!("{valid} > output.json"),
        format!("{valid} 2>/dev/null"),
        format!("{valid} 2>&1"),
        format!("{valid} &"),
        format!("{valid}\ntrue"),
    ] {
        assert_eq!(
            GwsGmailSendCommandInputV1::from_owned_posix_command(candidate).err(),
            Some(GwsGmailCommandErrorV1::UnsupportedContext)
        );
    }
}

#[test]
fn active_expansions_are_rejected_even_when_general_parser_has_exact_tokens() {
    for suffix in [
        "$THREAD",
        "${THREAD}",
        "$(cat file)",
        "`cat file`",
        "*",
        "?",
        "[a]",
        "{a,b}",
        "~",
    ] {
        let candidate = command(&format!(
            "--params '{PARAMS}' --json '{{\"raw\":\"Zg\",\"threadId\":\"'{suffix}'\"}}'"
        ));
        assert_eq!(
            GwsGmailSendCommandInputV1::from_owned_posix_command(candidate).err(),
            Some(GwsGmailCommandErrorV1::UnsupportedContext)
        );
    }
    let double_expansion = command(&format!(
        r#"--params '{PARAMS}' --json "{{\"raw\":\"Zg\",\"threadId\":\"$THREAD\"}}""#
    ));
    assert_eq!(
        GwsGmailSendCommandInputV1::from_owned_posix_command(double_expansion).err(),
        Some(GwsGmailCommandErrorV1::UnsupportedContext)
    );
    let literal = command(&format!(
        "--params '{PARAMS}' --json '{{\"raw\":\"Zg\",\"threadId\":\"$THREAD\"}}'"
    ));
    assert_eq!(
        GwsGmailSendCommandInputV1::from_owned_posix_command(literal)
            .unwrap()
            .wire_input()
            .thread_id(),
        Some("$THREAD")
    );
}

#[test]
fn malformed_private_payloads_are_rejected_without_echoing_values() {
    let private = "private-canary-fixture";
    for body in [
        format!(r#"{{"raw":"{private}"}}"#),
        format!(r#"{{"raw":"Zg","other":"{private}"}}"#),
        r#"{"raw":"Zg","r\u0061w":"Zg"}"#.to_owned(),
        "null".to_owned(),
    ] {
        let error = GwsGmailSendCommandInputV1::from_owned_posix_command(command(&format!(
            "--params '{PARAMS}' --json '{body}'"
        )))
        .err()
        .unwrap();
        assert!(!format!("{error:?}").contains(private));
    }
}

#[test]
fn source_bounds_and_command_substitutions_change_preparation_identity() {
    let valid = normal();
    let max = format!("{}{valid}", " ".repeat(MAX_COMMAND_BYTES - valid.len()));
    let input = GwsGmailSendCommandInputV1::from_owned_posix_command(max.clone()).unwrap();
    assert_eq!(input.command_text().len(), MAX_COMMAND_BYTES);
    assert_eq!(
        GwsGmailSendCommandInputV1::from_owned_posix_command(format!(" {max}")).err(),
        Some(GwsGmailCommandErrorV1::BoundsExceeded)
    );
    let a = GwsGmailSendCommandInputV1::from_owned_posix_command(valid.clone()).unwrap();
    let b = GwsGmailSendCommandInputV1::from_owned_posix_command(format!(" {valid}")).unwrap();
    assert_eq!(
        a.wire_input().input_binding(),
        b.wire_input().input_binding()
    );
    assert_ne!(a.input_binding(), b.input_binding());
}

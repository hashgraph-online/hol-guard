use super::*;

fn env(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
        .collect()
}

#[test]
fn each_runtime_family_resolves_to_its_slug() {
    for (key, slug) in [
        ("CLAUDECODE", "claude-code"),
        ("CLAUDE_CODE_ENTRYPOINT", "claude-code"),
        ("CURSOR_VERSION", "cursor"),
        ("CURSOR_PROJECT_DIR", "cursor"),
        ("CURSOR_TRACE_ID", "cursor"),
        ("CURSOR_SESSION_ID", "cursor"),
        ("CURSOR_TRANSCRIPT_PATH", "cursor"),
        ("CODEX_SANDBOX", "codex"),
        ("CODEX_THREAD_ID", "codex"),
        ("GROK_AGENT", "grok"),
        ("GROK_SESSION_ID", "grok"),
        ("OPENCODE_CONFIG_CONTENT", "opencode"),
        ("DEVIN_PROJECT_DIR", "devin"),
        ("ZCODE_BASE_URL", "zcode"),
        ("ZCODE_APP_VERSION", "zcode"),
        ("ZCODE_ENV", "zcode"),
        ("ZCODE_RUNTIME_ENV", "zcode"),
        ("ZCODE_PROCESS_LABEL", "zcode"),
        ("ZCODE_RG_BINARY", "zcode"),
        ("ZAI_OAUTH_ORIGIN", "zcode"),
        ("ZAI_OAUTH_CLIENT_ID", "zcode"),
    ] {
        assert_eq!(
            resolve_environment_harness_from(&env(&[(key, "set")])).as_deref(),
            Some(slug),
            "{key}"
        );
    }
}

#[test]
fn blank_and_unrelated_env_resolves_to_nothing() {
    assert_eq!(resolve_environment_harness_from(&env(&[])), None);
    assert_eq!(
        resolve_environment_harness_from(&env(&[("PATH", "/usr/bin"), ("TERM", "xterm-256color")])),
        None
    );
    assert_eq!(
        resolve_environment_harness_from(&env(&[("ZCODE_ENV", "  ")])),
        None
    );
    assert_eq!(
        resolve_environment_harness_from(&env(&[("__CFBundleIdentifier", "com.apple.Terminal")])),
        None
    );
}

/// An exported-but-empty marker is not a signal. Key presence alone would
/// attribute every `CURSOR_VERSION=` shell to Cursor.
#[test]
fn an_empty_marker_value_is_not_a_signal() {
    assert_eq!(
        resolve_environment_harness_from(&env(&[("CURSOR_VERSION", "")])),
        None
    );
    assert_eq!(
        resolve_environment_harness_from(&env(&[("CLAUDECODE", "\t \n")])),
        None
    );
}

/// The ZCode app embeds another harness's CLI, so both marker families are
/// present at once. ZCode is the answer, and it is the answer before the
/// bundle identifier is even consulted.
#[test]
fn zcode_wins_over_every_other_marker_family() {
    assert_eq!(
        resolve_environment_harness_from(&env(&[
            ("ZCODE_ENV", "production"),
            ("CLAUDECODE", "1"),
            ("CURSOR_SESSION_ID", "s-1"),
        ]))
        .as_deref(),
        Some("zcode")
    );
}

#[test]
fn the_zcode_bundle_identifier_attributes_zcode() {
    assert_eq!(
        resolve_environment_harness_from(&env(&[("__CFBundleIdentifier", " dev.zcode.app ")]))
            .as_deref(),
        Some("zcode")
    );
    assert_eq!(
        resolve_environment_harness_from(&env(&[("__CFBundleIdentifier", "dev.zcode.app.helper")])),
        None
    );
}

/// Claude Code's hooks also run inside Cursor, which exports both families.
/// Python answers `claude-code` there; the tie-break order is the contract.
#[test]
fn claude_code_outranks_cursor_when_both_families_are_present() {
    assert_eq!(
        resolve_environment_harness_from(&env(&[
            ("CLAUDECODE", "1"),
            ("CURSOR_TRACE_ID", "t-1"),
            ("CODEX_SANDBOX", "seatbelt"),
        ]))
        .as_deref(),
        Some("claude-code")
    );
}

#[test]
fn the_origin_override_outranks_every_marker() {
    assert_eq!(
        resolve_environment_harness_from(&env(&[
            ("HOL_GUARD_ORIGIN_HARNESS", "gemini"),
            ("ZCODE_ENV", "production"),
            ("CLAUDECODE", "1"),
        ]))
        .as_deref(),
        Some("gemini")
    );
}

#[test]
fn the_origin_override_is_normalized_the_way_it_was_stamped() {
    assert_eq!(
        resolve_environment_harness_from(&env(&[("HOL_GUARD_ORIGIN_HARNESS", " Claude_Code ")]))
            .as_deref(),
        Some("claude-code")
    );
}

/// The override names a slug Guard itself stamps. Anything else is somebody
/// else's environment variable, so attribution falls through to the markers
/// rather than echoing an attacker-chosen string into receipts.
#[test]
fn an_unknown_origin_override_falls_through_to_the_markers() {
    assert_eq!(
        resolve_environment_harness_from(&env(&[
            ("HOL_GUARD_ORIGIN_HARNESS", "guard-cli"),
            ("CODEX_SANDBOX", "seatbelt"),
        ]))
        .as_deref(),
        Some("codex")
    );
    assert_eq!(
        resolve_environment_harness_from(&env(&[("HOL_GUARD_ORIGIN_HARNESS", "../../etc/passwd")])),
        None
    );
    assert_eq!(
        resolve_environment_harness_from(&env(&[("HOL_GUARD_ORIGIN_HARNESS", "   ")])),
        None
    );
}

#[test]
fn every_stampable_slug_is_honoured_as_an_override() {
    for &slug in ORIGIN_HARNESS_VALUES {
        assert_eq!(
            resolve_environment_harness_from(&env(&[("HOL_GUARD_ORIGIN_HARNESS", slug)]))
                .as_deref(),
            Some(slug)
        );
    }
}

#[test]
fn executable_names_map_to_their_harness() {
    for (path, slug) in [
        ("/usr/local/bin/codex", "codex"),
        ("/opt/homebrew/bin/claude", "claude-code"),
        ("cursor", "cursor"),
        ("/x/cursor-agent", "cursor"),
        ("/x/zcode", "zcode"),
        ("/x/zcode-cli", "zcode"),
        ("/x/grok", "grok"),
        ("/x/pi", "pi"),
        ("/x/omp", "omp"),
        ("/x/opencode", "opencode"),
        ("/x/devin", "devin"),
    ] {
        assert_eq!(harness_from_executable(path), Some(slug), "{path}");
    }
}

#[test]
fn executable_names_are_matched_case_insensitively_and_without_a_windows_suffix() {
    assert_eq!(harness_from_executable("/x/Cursor.EXE"), Some("cursor"));
    assert_eq!(harness_from_executable("CODEX"), Some("codex"));
}

#[test]
fn an_app_bundle_path_attributes_its_harness() {
    for (path, slug) in [
        ("/Applications/Codex.app/Contents/MacOS/helper", "codex"),
        ("/Applications/Cursor.app/Contents/MacOS/helper", "cursor"),
        ("/Applications/Grok.app/Contents/MacOS/helper", "grok"),
        (
            "/Applications/Claude.app/Contents/MacOS/helper",
            "claude-code",
        ),
        (
            "/Applications/OpenCode.app/Contents/MacOS/helper",
            "opencode",
        ),
        ("/Applications/ZCode.app/Contents/MacOS/helper", "zcode"),
        ("/Applications/Devin.app/Contents/MacOS/helper", "devin"),
    ] {
        assert_eq!(harness_from_executable(path), Some(slug), "{path}");
    }
    assert_eq!(
        harness_from_executable("C:\\Program Files\\Cursor.app\\helper"),
        Some("cursor")
    );
}

#[test]
fn an_unrelated_executable_attributes_nothing() {
    assert_eq!(harness_from_executable("/bin/zsh"), None);
    assert_eq!(harness_from_executable(""), None);
    assert_eq!(harness_from_executable("/x/codexer"), None);
    assert_eq!(harness_from_executable("/x/notcodex"), None);
}

#[test]
fn a_ps_row_splits_into_three_fields() {
    assert_eq!(
        ps_row_fields("  501  1234 cursor-agent"),
        Some(("501", "1234", "cursor-agent"))
    );
}

/// `comm` can carry spaces, and `split(maxsplit=2)` keeps them in the third
/// field rather than dropping the tail.
#[test]
fn a_ps_row_keeps_the_rest_of_the_command_name() {
    assert_eq!(
        ps_row_fields("1 0 Some Helper App"),
        Some(("1", "0", "Some Helper App"))
    );
}

/// One malformed row must not cost the whole walk its process table.
#[test]
fn a_short_or_blank_ps_row_is_skipped() {
    assert_eq!(ps_row_fields(""), None);
    assert_eq!(ps_row_fields("   "), None);
    assert_eq!(ps_row_fields("1234"), None);
    assert_eq!(ps_row_fields("1234 5678"), None);
    assert_eq!(ps_row_fields("1234 5678   "), None);
}

/// The walk is best-effort: it must answer on any host without panicking, and
/// anything it does answer has to be a slug Guard recognises.
#[test]
fn the_parent_walk_answers_a_known_slug_or_nothing() {
    if let Some(harness) = resolve_parent_process_harness() {
        assert!(
            PROCESS_HARNESSES
                .iter()
                .chain(APP_PATH_MARKERS.iter())
                .any(|(_, slug)| *slug == harness.as_str()),
            "unexpected slug {harness}"
        );
    }
}

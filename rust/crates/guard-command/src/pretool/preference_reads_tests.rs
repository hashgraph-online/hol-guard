use super::safe_preference_read;

fn arguments(text: &str) -> Vec<String> {
    text.split_whitespace().map(str::to_string).collect()
}

#[test]
fn a_question_about_one_domain_is_admitted() {
    for text in [
        "read com.apple.dock",
        "read com.apple.dock orientation",
        "read -g AppleInterfaceStyle",
        "read -globalDomain AppleInterfaceStyle",
        "read NSGlobalDomain AppleShowAllExtensions",
        "read-type com.apple.finder ShowPathbar",
        "domains",
        "-currentHost read com.apple.screensaver",
        "-host workstation read com.apple.dock",
    ] {
        assert!(safe_preference_read("defaults", &arguments(text)), "{text}");
    }
}

#[test]
fn a_verb_that_changes_the_store_or_writes_a_file_keeps_its_review() {
    for text in [
        "write com.apple.dock orientation left",
        "delete com.apple.dock orientation",
        "rename com.apple.dock old new",
        "import com.apple.dock settings.plist",
        "export com.apple.dock settings.plist",
        "find token",
    ] {
        assert!(
            !safe_preference_read("defaults", &arguments(text)),
            "{text}"
        );
    }
}

/// Another publisher's domain holds whatever that application stored, which
/// may be an API token or an account identifier, so it is not the machine's
/// settings and keeps its review. A credential-sounding domain or key keeps
/// its review whoever publishes it.
#[test]
fn a_domain_outside_the_machines_own_settings_keeps_its_review() {
    for text in [
        "read com.example.editor",
        "read com.example.editor recentDocuments",
        "read-type com.example.editor token",
        "read org.mozilla.firefox",
        "read com.apple",
        "read com.apple.",
        "read com.apple.dock api_key",
        "read com.apple.passwordmanager",
        "-currentHost read com.example.editor",
    ] {
        assert!(
            !safe_preference_read("defaults", &arguments(text)),
            "{text}"
        );
    }
}

#[test]
fn a_plist_path_or_a_whole_store_dump_keeps_its_review() {
    for text in [
        "read",
        "read-type",
        "read ~/Library/Preferences/com.apple.dock.plist",
        "read /Library/Preferences/com.apple.loginwindow",
        "read ../other/com.apple.dock",
        "domains extra",
    ] {
        assert!(
            !safe_preference_read("defaults", &arguments(text)),
            "{text}"
        );
    }
}

#[test]
fn an_option_this_screen_does_not_know_proves_nothing() {
    for text in [
        "-app Safari read",
        "-host read com.apple.dock",
        "read com.apple.dock -array",
        "read com.apple.dock key extra",
    ] {
        assert!(
            !safe_preference_read("defaults", &arguments(text)),
            "{text}"
        );
    }
}

#[test]
fn only_defaults_is_read_this_way() {
    assert!(!safe_preference_read(
        "plutil",
        &arguments("read com.apple.dock")
    ));
    assert!(!safe_preference_read(
        "defaults.sh",
        &arguments("read com.apple.dock")
    ));
}

/// `$((PATH=1))` assigns while the shell expands the step's own words, before
/// it looks the program up, so a step carrying one decides which `defaults`
/// runs. Coverage screens that on every step, not only on the steps another
/// one follows.
mod coverage {
    fn covered(command: &str) -> Vec<usize> {
        let model = crate::parse_command(&crate::CommandModelRequestV1 {
            command: command.to_owned(),
            dialect: "posix".to_owned(),
            transport: "shell_string".to_owned(),
            extraction_provenance: "guard-shell".to_owned(),
        })
        .unwrap();
        crate::pretool::segments_safe_alone(&model, crate::pretool::PathContext::default(), None)
    }

    #[test]
    fn a_settings_question_is_covered() {
        assert!(covered("defaults read com.apple.dock orientation").contains(&0));
    }

    #[test]
    fn an_arithmetic_assignment_in_the_only_step_is_not_covered() {
        for command in [
            "defaults read $((PATH=1))",
            "defaults read com.apple.dock $((PATH=1))",
        ] {
            assert!(!covered(command).contains(&0), "{command}");
        }
    }
}

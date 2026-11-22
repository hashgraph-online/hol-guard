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

use super::{normal_home, without_home_option, without_own_home};

fn words(text: &str) -> Vec<String> {
    text.split_whitespace().map(str::to_owned).collect()
}

fn account(label: &str) -> std::path::PathBuf {
    let home = std::env::temp_dir().join(format!("guard-own-home-{label}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(&home).unwrap();
    home
}

#[test]
fn only_the_own_home_is_set_aside() {
    let own = "/home/fixture/.hol-guard";
    for (text, expected) in [
        (
            "approvals wait abc --json --home {own}",
            Some("approvals wait abc --json"),
        ),
        (
            "approvals wait abc --home={own}/",
            Some("approvals wait abc"),
        ),
        ("--home {own} approvals list", Some("approvals list")),
        ("approvals wait abc", None),
        ("approvals wait abc --home /home/fixture/other", None),
        ("approvals wait abc --home {own}/../x", None),
        ("approvals wait abc --home ~/.hol-guard", None),
        ("approvals wait abc --home {own} --home {own}", None),
        ("approvals wait abc --home", None),
    ] {
        let text = text.replace("{own}", own);
        assert_eq!(
            without_home_option(&words(&text), own),
            expected.map(words),
            "{text}"
        );
    }
}

/// The launcher resolves to `.hol-guard` only once it exists and no older
/// home sits beside it; until then the override may name a different store.
#[test]
fn the_own_home_must_be_the_one_the_launcher_resolves() {
    let wait = |home: &std::path::Path| {
        let home = home.to_str().unwrap();
        without_own_home(
            &words(&format!("approvals wait abc --home {home}/.hol-guard")),
            Some(home),
        )
    };
    let missing = account("missing");
    assert_eq!(wait(&missing), None);

    let present = account("present");
    std::fs::create_dir_all(present.join(".hol-guard")).unwrap();
    assert_eq!(wait(&present), Some(words("approvals wait abc")));

    for legacy in [
        ".holguard",
        ".ai-plugin-scanner-guard",
        ".config/.ai-plugin-scanner-guard",
    ] {
        let home = account("legacy");
        std::fs::create_dir_all(home.join(".hol-guard")).unwrap();
        std::fs::create_dir_all(home.join(legacy)).unwrap();
        assert_eq!(wait(&home), None, "{legacy}");
        let _ = std::fs::remove_dir_all(&home);
    }
    let _ = std::fs::remove_dir_all(&missing);
    let _ = std::fs::remove_dir_all(&present);
}

/// A Windows home matches with either separator and in any letter case. A
/// backslash in a POSIX path is part of a file name, not a separator.
#[test]
fn windows_drive_homes_compare_as_windows_paths() {
    let own = format!("{}/.hol-guard", normal_home("C:\\Users\\Alice\\").unwrap());
    assert_eq!(own, "C:/Users/Alice/.hol-guard");
    for value in [
        "C:/Users/Alice/.hol-guard",
        "C:\\Users\\Alice\\.hol-guard",
        "c:\\users\\alice\\.hol-guard\\",
    ] {
        assert_eq!(
            without_home_option(&words(&format!("approvals wait abc --home {value}")), &own),
            Some(words("approvals wait abc")),
            "{value}"
        );
    }
    for value in [
        "D:/Users/Alice/.hol-guard",
        "/Users/Alice/.hol-guard",
        "C:/Users/Bob/.hol-guard",
    ] {
        assert_eq!(
            without_home_option(&words(&format!("approvals wait abc --home {value}")), &own),
            None,
            "{value}"
        );
    }
    let posix = "/home/u/.hol-guard";
    assert_eq!(
        without_home_option(
            &words("approvals wait abc --home /home/u\\.hol-guard"),
            posix
        ),
        None
    );
    assert_eq!(normal_home("C:"), None);
    assert_eq!(normal_home("C:\\"), None);
    assert_eq!(normal_home("relative/home"), None);
}

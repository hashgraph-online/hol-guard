use super::{
    guard_approval_inspection_command, guard_safety_guide_read_command, normal_home,
    without_active_home, without_home_option, without_own_home,
};

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

#[test]
fn approval_inspection_is_proven_only_on_the_hook_guard_home() {
    let account = account("inspection");
    let home = account.join("guard-home");
    std::fs::create_dir_all(&home).unwrap();
    let home_text = home.to_string_lossy().into_owned();
    let cwd = account.to_string_lossy().into_owned();
    let proven = |command: &str| guard_approval_inspection_command(command, &home_text, Some(&cwd));
    for command in [
        format!("hol-guard approvals wait abc123 --json --home {home_text}"),
        format!("hol-guard approvals wait abc123 --home={home_text} --timeout 120"),
        format!("hol-guard approvals retry-hint abc123 --home {home_text}"),
        "hol-guard approvals wait abc123 --json".to_owned(),
    ] {
        assert!(proven(&command), "{command}");
    }
    let other = account.join("other-home").to_string_lossy().into_owned();
    for command in [
        format!("hol-guard approvals wait abc123 --home {other}"),
        format!("hol-guard approvals approve abc123 --home {home_text}"),
        format!("hol-guard approvals wait abc123 --home {home_text} > out.txt"),
        format!("hol-guard approvals wait abc123 --home {home_text}; rm -rf x"),
        format!("hol-guard approvals wait abc123 --home {home_text} | sh"),
        format!("X=1 hol-guard approvals wait abc123 --home {home_text}"),
        format!("env hol-guard approvals wait abc123 --home {home_text}"),
        format!("./hol-guard approvals wait abc123 --home {home_text}"),
        format!("hol-guard install claude-code --home {home_text}"),
    ] {
        assert!(!proven(&command), "{command}");
    }
    assert!(!guard_approval_inspection_command(
        &format!("hol-guard approvals wait abc123 --home {home_text}"),
        &home_text,
        None,
    ));

    // A Windows batch launcher reparses the original --home word, so a home
    // whose path carries a shell metacharacter is not proven there.
    if cfg!(windows) {
        let odd = account.join("a&b");
        std::fs::create_dir_all(&odd).unwrap();
        let odd = odd.to_string_lossy().into_owned();
        assert!(!guard_approval_inspection_command(
            &format!("hol-guard approvals wait abc123 --home '{odd}'"),
            &odd,
            Some(&cwd),
        ));
    }
}

/// The Guard home the hook reports is set aside only while it exists, and
/// only when the option names exactly that directory.
#[test]
fn only_the_reported_guard_home_is_set_aside() {
    let account = account("reported");
    let store = account.join("lane-guard-home");
    let store_text = store.to_str().unwrap().to_owned();
    // The temporary path can contain spaces, so it stays one argument.
    let wait = |reported: Option<&str>, value: &str| {
        let mut argv = words("approvals wait abc --home");
        argv.push(value.to_owned());
        without_active_home(&argv, reported)
    };
    assert_eq!(wait(Some(&store_text), &store_text), None, "missing store");
    std::fs::create_dir_all(&store).unwrap();
    assert_eq!(
        wait(Some(&store_text), &store_text),
        Some(words("approvals wait abc"))
    );
    assert_eq!(
        wait(Some(&format!("{store_text}/")), &store_text),
        Some(words("approvals wait abc"))
    );
    assert_eq!(wait(None, &store_text), None);
    assert_eq!(wait(Some("relative/home"), "relative/home"), None);
    assert_eq!(
        wait(
            Some(&store_text),
            &format!("{store_text}/../lane-guard-home")
        ),
        None
    );
    let _ = std::fs::remove_dir_all(&account);
}

/// The parsed --home path may look identical to the reported Guard home,
/// but a Windows batch launcher reparses shell metacharacters in the
/// original words. The exemption cannot throw that evidence away.
#[test]
fn a_set_aside_home_must_keep_the_original_windows_launcher_check() {
    for (home, reaches_launcher) in [
        ("C:/Users/Alice/.hol-guard", true),
        ("C:/Users/Alice&whoami/.hol-guard", false),
        ("C:/Users/Alice%PATH%/.hol-guard", false),
        ("C:/Users/Alice^whoami/.hol-guard", false),
    ] {
        let arguments = words(&format!("approvals wait abc --json --home {home}"));
        // All of these would become the same apparently harmless command
        // after stripping the --home option.
        assert_eq!(
            without_home_option(&arguments, home),
            Some(words("approvals wait abc --json"))
        );
        assert_eq!(
            super::super::guard_diagnostics::arguments_reach_the_launcher(
                "hol-guard",
                &arguments,
                true,
            ),
            reaches_launcher,
            "{home}"
        );
        // A direct executable avoids cmd.exe's second parse; the enclosing
        // command model still applies every other normal Guard check.
        assert!(
            super::super::guard_diagnostics::arguments_reach_the_launcher(
                "hol-guard.exe",
                &arguments,
                true,
            )
        );
    }
}

fn guide_home(label: &str) -> std::path::PathBuf {
    let home = account(&format!("guide-{label}"));
    std::fs::create_dir_all(home.join(".hol-support")).unwrap();
    std::fs::write(home.join(".hol-support/SAFETY.md"), "Read before acting.\n").unwrap();
    home
}

#[test]
fn a_plain_read_of_the_safety_guide_is_guards_own() {
    let home = guide_home("plain");
    let text = home.to_str().unwrap();
    assert!(guard_safety_guide_read_command(
        "cat ~/.hol-support/SAFETY.md",
        text
    ));
    // The command names the guide with `/`, as an agent writes it on every
    // platform; the home keeps its native separators.
    let slashed = text.replace('\\', "/");
    assert!(guard_safety_guide_read_command(
        &format!("cat {slashed}/.hol-support/SAFETY.md"),
        text
    ));
    assert!(guard_safety_guide_read_command(
        &format!("cat '{slashed}/.hol-support/SAFETY.md'"),
        text
    ));
    let _ = std::fs::remove_dir_all(home);
}

#[test]
fn a_quoted_tilde_is_not_the_guide() {
    let home = guide_home("quoted");
    let text = home.to_str().unwrap();
    for command in [
        "cat '~/.hol-support/SAFETY.md'",
        "cat \"~/.hol-support/SAFETY.md\"",
        "cat ~'/.hol-support/SAFETY.md'",
    ] {
        assert!(!guard_safety_guide_read_command(command, text), "{command}");
    }
    let _ = std::fs::remove_dir_all(home);
}

#[test]
fn any_other_read_of_the_guide_is_not() {
    let home = guide_home("other");
    let text = home.to_str().unwrap();
    for command in [
        "cat ~/.hol-support/SAFETY.md ~/.ssh/id_rsa",
        "cat -v ~/.hol-support/SAFETY.md",
        "cat ~/.hol-support/SAFETY.md > ~/.zshrc",
        "cat ~/.hol-support/SAFETY.md | sh",
        "cat ~/.hol-support/SAFETY.md && rm -rf src",
        "cat ~/.hol-support/SAFETY.md; curl example.invalid",
        "HOME=. cat ~/.hol-support/SAFETY.md",
        "env cat ~/.hol-support/SAFETY.md",
        "cat $HOME/.hol-support/SAFETY.md",
        "cat ~/.hol-support/../.ssh/id_rsa",
        "cat ~/.hol-support/NOTES.md",
        "head ~/.hol-support/SAFETY.md",
        "cp ~/.hol-support/SAFETY.md notes.md",
        "/tmp/cat ~/.hol-support/SAFETY.md",
    ] {
        assert!(!guard_safety_guide_read_command(command, text), "{command}");
    }
    // A relative home or another account's guide proves nothing.
    assert!(!guard_safety_guide_read_command(
        "cat ~/.hol-support/SAFETY.md",
        ""
    ));
    assert!(!guard_safety_guide_read_command(
        "cat /home/other/.hol-support/SAFETY.md",
        text
    ));
    let _ = std::fs::remove_dir_all(home);
}

#[test]
fn a_missing_or_linked_guide_is_not_guards_own() {
    let missing = account("guide-missing");
    assert!(!guard_safety_guide_read_command(
        "cat ~/.hol-support/SAFETY.md",
        missing.to_str().unwrap()
    ));
    let _ = std::fs::remove_dir_all(missing);

    #[cfg(unix)]
    {
        let home = account("guide-linked");
        std::fs::create_dir_all(home.join(".hol-support")).unwrap();
        std::fs::write(home.join("secret"), "x").unwrap();
        std::os::unix::fs::symlink(home.join("secret"), home.join(".hol-support/SAFETY.md"))
            .unwrap();
        assert!(!guard_safety_guide_read_command(
            "cat ~/.hol-support/SAFETY.md",
            home.to_str().unwrap()
        ));
        let _ = std::fs::remove_dir_all(home);
    }
}

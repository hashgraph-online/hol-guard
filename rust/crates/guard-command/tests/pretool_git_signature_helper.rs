use crate::git_helper_fixture as fixture;
use fixture::*;
use serde_json::json;

const SIGNATURE_READS: [&str; 3] = [
    "git log -1 --format='%h | %an <%ae> | %cn <%ce> | %G? | %s'",
    "git log -1 --show-signature --format='%h | %G? | %GS'",
    "git show --no-patch --format=%GK HEAD",
];

/// A Git the probe already trusts stands in for a verification program in a
/// trusted install location; the decision never starts it.
fn trusted_program() -> std::path::PathBuf {
    let name = if cfg!(windows) { "git.exe" } else { "git" };
    std::env::split_paths(&std::env::var_os("PATH").unwrap())
        .map(|directory| directory.join(name))
        .find(|candidate| candidate.is_file())
        .map(|candidate| std::fs::canonicalize(candidate).unwrap())
        .unwrap()
}

#[test]
fn a_signature_read_is_admitted_only_when_the_user_chose_the_program() {
    let root = std::env::temp_dir().join(format!("guard-git-signature-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let _cleanup = FixtureCleanup(root.clone());
    let home = root.join("home");
    let repository = root.join("repository");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&repository).unwrap();
    assert!(std::process::Command::new("git")
        .args(["init", "--quiet"])
        .arg(&repository)
        .status()
        .unwrap()
        .success());
    let enabled = github_controls("enabled");
    let program = trusted_program();
    let program = program.to_string_lossy().replace('\\', "/");
    let decide = |harness: &str, command: &str| {
        evaluate_pre_tool_envelope_with_context(
            harness,
            "PreToolUse",
            &json!({"tool_name":"bash", "tool_input":{"command":command}}),
            Some(&enabled),
            None,
            home.to_str(),
            repository.to_str(),
        )
    };
    let user_settings = [
        String::new(),
        format!("[gpg]\n\tformat = ssh\n[gpg \"ssh\"]\n\tprogram = {program}\n"),
        format!("[gpg]\n\tprogram = {program}\n"),
    ];
    for harness in ["omp", "zcode"] {
        for settings in &user_settings {
            std::fs::write(home.join(".gitconfig"), settings).unwrap();
            for command in SIGNATURE_READS {
                let result = decide(harness, command);
                assert_eq!(
                    result.decision, "allow",
                    "{harness}: {settings:?}: {command}"
                );
            }
        }
        // A program in a temporary directory, or one Git looks up from the
        // directory it runs in, is not a program the probe can place.
        for settings in [
            "[gpg]\n\tprogram = /tmp/synthetic-never-execute\n",
            "[gpg \"ssh\"]\n\tprogram = bin/synthetic-signer\n",
        ] {
            std::fs::write(home.join(".gitconfig"), settings).unwrap();
            for command in SIGNATURE_READS {
                let result = decide(harness, command);
                assert_ne!(
                    result.decision, "allow",
                    "{harness}: {settings:?}: {command}"
                );
            }
        }
        std::fs::write(home.join(".gitconfig"), "").unwrap();
        // The command line may not choose the program or its format.
        for command in [
            format!("git -c gpg.program={program} log -1 --show-signature"),
            "git -c gpg.format=ssh log -1 --format=%G?".to_owned(),
        ] {
            let result = decide(harness, &command);
            assert_ne!(result.decision, "allow", "{harness}: {command}");
        }
        // Nor may the repository, even when it names the user's own program.
        for (key, value) in [("gpg.program", program.as_str()), ("gpg.format", "ssh")] {
            assert!(std::process::Command::new("git")
                .arg("-C")
                .arg(&repository)
                .args(["config", key, value])
                .status()
                .unwrap()
                .success());
            for command in SIGNATURE_READS {
                let result = decide(harness, command);
                assert_ne!(result.decision, "allow", "{harness}: {key}: {command}");
            }
            assert!(std::process::Command::new("git")
                .arg("-C")
                .arg(&repository)
                .args(["config", "--unset", key])
                .status()
                .unwrap()
                .success());
        }
        let clean = decide(harness, SIGNATURE_READS[0]);
        assert_eq!(clean.decision, "allow", "{harness}: settings removed");
    }
}

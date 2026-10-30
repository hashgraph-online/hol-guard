use super::*;

fn intent(command: &str) -> Option<PackageIntent> {
    parse_package_intent(command, None, None, None, None)
}

#[test]
fn install_help_is_not_an_install() {
    // `uv pip install --help` was held for review as an install with no
    // named package.
    for command in [
        "uv pip install --help",
        "uv pip install -h",
        "uv add --help",
        "pip install --help",
        "pip3 install -h",
        "npm install --help",
        "npm i -h",
        "pnpm add --help",
        "yarn add --help",
        "bun add --help",
        "go get -h",
    ] {
        assert!(intent(command).is_none(), "{command}");
    }
}

#[test]
fn help_after_a_package_or_runner_is_still_an_install() {
    for command in [
        "uv pip install evil-pkg --help",
        "npm install evil-pkg -h",
        "npx evil-pkg --help",
        "uvx evil-pkg --help",
        "pnpm dlx evil-pkg --help",
    ] {
        let intent = intent(command).unwrap_or_else(|| panic!("{command} must stay an install"));
        assert!(!intent.targets.is_empty(), "{command}");
    }
}

use super::*;

fn target_names(command: &str) -> Vec<String> {
    let intent = parse_package_intent(command, None, None, None, None)
        .expect("uvx must produce a package intent");
    assert!(intent
        .targets
        .iter()
        .all(|target| target.ecosystem == "pypi"));
    intent
        .targets
        .into_iter()
        .map(|target| target.package_name.expect("a named distribution"))
        .collect()
}

#[test]
fn uvx_value_options_do_not_become_distribution_targets() {
    for options in [
        "-p 3.12",
        "-p3.12",
        "-p=3.12",
        "--python=3.12",
        "--index https://example.invalid/simple",
        "--index=https://example.invalid/simple",
        "--index-url https://example.invalid/simple",
        "-ihttps://example.invalid/simple",
        "--extra-index-url https://example.invalid/simple",
        "-f https://example.invalid/wheels",
        "-c constraints.txt",
        "-cconstraints.txt",
        "--constraint=constraints.txt",
        "-b build.txt",
        "--build-constraint build.txt",
        "--override overrides.txt",
        "--env-file vars.env",
        "--config-settings backend=value",
        "-Cbackend=value",
        "--trusted-host example.invalid",
        "--directory /tmp",
    ] {
        let command = format!("uvx {options} --with extra evil-pkg");
        assert_eq!(target_names(&command), ["evil-pkg", "extra"], "{command}");
    }
    assert_eq!(target_names("uvx -p 3.12 evil-pkg"), ["evil-pkg"]);
}

#[test]
fn uvx_dependencies_and_from_respect_the_executable_boundary() {
    for (command, expected) in [
        (
            "uvx -p3.12 --from=evil-pkg -wextra --with second http",
            vec!["evil-pkg", "extra", "second"],
        ),
        (
            "uvx --index-url=https://example.invalid/simple -w=extra --with='second[fast,cli]>=1,<2' evil-pkg",
            vec!["evil-pkg", "extra", "second"],
        ),
        (
            "uvx -c constraints.txt --with extra -- evil-pkg --with ignored --from ignored-too",
            vec!["evil-pkg", "extra"],
        ),
        (
            "uvx -p 3.12 evil-pkg --from ignored --with ignored-too -wignored-three",
            vec!["evil-pkg"],
        ),
        (
            "uvx --from evil-pkg --with extra http --with ignored --from ignored-too",
            vec!["evil-pkg", "extra"],
        ),
    ] {
        assert_eq!(target_names(command), expected, "{command}");
    }
}

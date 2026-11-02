use super::*;

fn target_names(command: &str) -> Vec<String> {
    let intent = parse_package_intent(command, None, None, None, None)
        .expect("the install must produce a package intent");
    intent
        .targets
        .into_iter()
        .map(|target| target.package_name.expect("a named package"))
        .collect()
}

#[test]
fn uv_value_options_do_not_become_package_targets() {
    // `uv pip install --python .venv/bin/python <pkg>` was reviewed as the
    // package `.venv/bin/python@>=0`.
    for options in [
        "--python .venv/bin/python",
        "--python=.venv/bin/python",
        "-p 3.12",
        "-f ./wheels",
        "--find-links ./wheels",
        "--index-strategy unsafe-best-match",
        "-C key=value",
        "--extra cli",
        "--exclude-newer 2026-01-01",
    ] {
        for verb in ["pip install", "add"] {
            let command = format!("uv {verb} {options} evil-pkg");
            assert_eq!(target_names(&command), ["evil-pkg"], "{command}");
        }
    }
    for options in [
        "-c constraints.txt",
        "--constraint constraints.txt",
        "--override overrides.txt",
        "--target ./vendor",
        "--python-version 3.12",
        "--python-platform linux",
        "--no-binary :all:",
        "--only-binary :all:",
    ] {
        let command = format!("uv pip install {options} evil-pkg");
        assert_eq!(target_names(&command), ["evil-pkg"], "{command}");
    }
    for options in [
        "--no-binary-package left-pad",
        "--no-build-package left-pad",
        "--group dev",
        "--branch main",
    ] {
        let command = format!("uv add {options} evil-pkg");
        assert_eq!(target_names(&command), ["evil-pkg"], "{command}");
    }
}

#[test]
fn uv_add_switches_keep_the_package_after_them() {
    // `uv add --no-binary` is a switch; only `uv pip install --no-binary`
    // takes a value.
    for options in ["--no-binary", "--no-build", "--dev", "--frozen"] {
        let command = format!("uv add {options} evil-pkg");
        assert_eq!(target_names(&command), ["evil-pkg"], "{command}");
    }
}

#[test]
fn pip_value_options_do_not_become_package_targets() {
    for options in [
        "-t ./vendor",
        "--target ./vendor",
        "--python .venv/bin/python",
        "--platform manylinux2014_x86_64",
        "--python-version 3.12",
        "--only-binary :all:",
        "--no-binary :all:",
        "-f ./wheels",
        "--find-links ./wheels",
        "--root /tmp/root",
        "--upgrade-strategy eager",
        "--cache-dir /tmp/pip-cache",
    ] {
        let command = format!("pip install {options} evil-pkg");
        assert_eq!(target_names(&command), ["evil-pkg"], "{command}");
    }
}

#[test]
fn editable_installs_still_name_their_package() {
    // `-e` takes a value too, but that value is the package being installed.
    let intent = parse_package_intent("uv pip install -e evil-pkg", None, None, None, None)
        .expect("the install must produce a package intent");
    assert_eq!(intent.targets.len(), 1);
}

fn target_identities(command: &str) -> Vec<(String, Option<String>)> {
    let intent = parse_package_intent(command, None, None, None, None)
        .expect("the install must produce a package intent");
    intent
        .targets
        .into_iter()
        .map(|target| {
            (
                target.package_name.expect("a named package"),
                target.requested_specifier,
            )
        })
        .collect()
}

#[test]
fn a_local_distribution_file_names_its_own_distribution() {
    // `uv pip install <dir>/hol_guard-3.59.0a33-py3-none-macosx_11_0_arm64.whl`
    // asked for the package `hol-guard-3-59-0a33-py3-none-macosx-11-0-arm64`:
    // a name the next build never repeats and no policy entry can hold.
    for (command, distribution, version) in [
        (
            "uv pip install /tmp/dl/hol_guard-3.59.0a33-py3-none-macosx_11_0_arm64.whl",
            "hol_guard",
            "3.59.0a33",
        ),
        (
            "pip install dist/hol_guard-3.59.0-py3-none-any.whl",
            "hol_guard",
            "3.59.0",
        ),
        (
            "pip3 install ./dist/left_pad-1.2.3-5-py3-none-any.whl",
            "left_pad",
            "1.2.3",
        ),
        (
            "uv pip install ../wheels/left_pad-1.2.3.tar.gz",
            "left_pad",
            "1.2.3",
        ),
        (
            "pip install ./dist/left-pad-extras-1.2.3.zip",
            "left-pad-extras",
            "1.2.3",
        ),
    ] {
        assert_eq!(
            target_identities(command),
            [(distribution.to_owned(), Some(version.to_owned()))],
            "{command}"
        );
    }
}

#[test]
fn a_path_that_names_no_distribution_keeps_its_last_component() {
    for (command, package_name) in [
        ("pip install ./vendor/left-pad", "left-pad"),
        ("pip install ./dist/not-a-wheel.whl", "not-a-wheel.whl"),
        (
            "pip install ./dist/left_pad-dev.tar.gz",
            "left_pad-dev.tar.gz",
        ),
    ] {
        assert_eq!(
            target_identities(command),
            [(package_name.to_owned(), None)],
            "{command}"
        );
    }
}

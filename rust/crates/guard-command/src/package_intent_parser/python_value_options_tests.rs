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
        "-c constraints.txt",
        "--constraint constraints.txt",
        "--override overrides.txt",
        "-f ./wheels",
        "--find-links ./wheels",
        "--target ./vendor",
        "--python-version 3.12",
        "--python-platform linux",
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

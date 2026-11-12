use serde_json::json;

use super::{env_command, shebang_interpreter};
use crate::runtime_identity_launch::tests::{env, paths_of, run, spec, targets, text};
#[cfg(unix)]
use crate::runtime_identity_launch::tests::{executable, fifo};

#[cfg(unix)]
#[test]
fn launcher_script_adds_its_shebang_interpreter() {
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("bin");
    let interpreter = executable(&bin, "python3", "binary\n");
    let launcher = executable(&bin, "serve", "#!/usr/bin/env python3\nprint('x')\n");
    let result = run(json!({
        "launches": [spec("serve", dir.path())],
        "environment": env(&[("PATH", text(&bin))]),
    }));

    assert_eq!(
        targets(&result, 0),
        [
            (text(&launcher).to_owned(), "launch".to_owned()),
            (text(&interpreter).to_owned(), "interpreter".to_owned()),
        ]
    );
    assert_eq!(result["observations"].as_array().unwrap().len(), 2);
}

#[cfg(unix)]
#[test]
fn absolute_shebang_program_is_the_interpreter_and_a_missing_one_is_not() {
    let dir = tempfile::tempdir().unwrap();
    let interpreter = executable(dir.path(), "opt/python", "binary\n");
    let found = executable(
        dir.path(),
        "found",
        &format!("#!{}\nprint('x')\n", interpreter.display()),
    );
    let missing = executable(dir.path(), "missing", "#!/nonexistent/python\n");

    assert_eq!(
        shebang_interpreter(text(&found), |_| None).as_deref(),
        Some(text(&interpreter))
    );
    assert_eq!(shebang_interpreter(text(&missing), |_| None), None);
}

#[cfg(unix)]
#[test]
fn env_shebang_options_do_not_hide_the_interpreter() {
    let cases = [
        ("#!/usr/bin/env python3", Some("python3")),
        ("#!/usr/bin/env -u DEBUG python3", Some("python3")),
        ("#!/usr/bin/env --unset=DEBUG python3", Some("python3")),
        ("#!/usr/bin/env -uDEBUG python3", Some("python3")),
        ("#!/usr/bin/env -i FOO=1 python3", Some("python3")),
        ("#!/usr/bin/env -S python3 -u", Some("python3")),
        ("#!/usr/bin/env -- python3", Some("python3")),
        ("#!/usr/bin/env --no-such-option python3", None),
        ("#!/usr/bin/env -S 'python3 -u'", None),
        ("#!/usr/bin/env -u", None),
    ];
    for (shebang, expected) in cases {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bin");
        let python = executable(&bin, "python3", "binary\n");
        executable(&bin, "DEBUG", "binary\n");
        let launcher = executable(&bin, "serve", &format!("{shebang}\nprint('x')\n"));
        let result = run(json!({
            "launches": [spec("serve", dir.path())],
            "environment": env(&[("PATH", text(&bin))]),
        }));

        let mut expected_paths = vec![text(&launcher).to_owned()];
        expected_paths.extend(expected.map(|_| text(&python).to_owned()));
        assert_eq!(paths_of(&result, 0), expected_paths, "{shebang}");
    }
}

#[test]
fn env_command_parses_every_documented_option_form() {
    let split =
        |line: &str| env_command(&line.split_whitespace().collect::<Vec<_>>()).map(str::to_owned);

    assert_eq!(split("python3").as_deref(), Some("python3"));
    assert_eq!(split("-u DEBUG python3").as_deref(), Some("python3"));
    assert_eq!(split("-C /tmp -P /bin python3").as_deref(), Some("python3"));
    assert_eq!(split("--chdir /tmp python3").as_deref(), Some("python3"));
    assert_eq!(split("-iv FOO=1 BAR=2 python3"), None);
    assert_eq!(split("-"), None);
    assert_eq!(split(""), None);
    let long = "x".repeat(65);
    assert_eq!(split(&long), None);
}

#[cfg(unix)]
#[test]
fn fifo_launcher_is_never_read_for_a_shebang() {
    let dir = tempfile::tempdir().unwrap();
    let pipe = fifo(dir.path(), "serve");

    assert_eq!(
        shebang_interpreter(text(&pipe), |_| Some("/bin/sh".to_owned())),
        None
    );
}

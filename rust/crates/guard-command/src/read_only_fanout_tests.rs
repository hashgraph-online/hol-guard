use super::*;

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

#[test]
fn find_exec_accepts_flat_read_only_shape() {
    let a = args(&[
        "src", "-type", "f", "-name", "*.ts", "-exec", "cat", "{}", "+",
    ]);
    let parsed = find_exec(&a).unwrap();
    assert!(parsed.shape.regular_files_only);
    assert_eq!(parsed.child, &a[6..7]);
    assert!(find_exec(&args(&["src", "-exec", "grep", "-n", "x", "{}", ";"])).is_some());
}

#[test]
fn find_exec_rejects_actions_children_and_operators() {
    for case in [
        &["src", "-exec", "rm", "{}", "+"][..],
        &["src", "-exec", "sh", "-c", "cat {}", "+"],
        &["src", "-exec", "cat", "{}", "+", "-delete"],
        &["src", "-execdir", "cat", "{}", "+"],
        &["src", "-ok", "cat", "{}", ";"],
        &[
            "src", "-name", "a", "-o", "-name", "b", "-exec", "cat", "{}", "+",
        ],
        &["src", "-fprint", "out", "-exec", "cat", "{}", "+"],
        &["src", "-exec", "/bin/cat", "{}", "+"],
        &["src", "-exec", "cat", "x{}", "+"],
        &[
            "src", "-exec", "grep", "-e", ";", "-o", "-delete", "-fprintf", "{}", ";",
        ],
        &["-L", "src", "-exec", "cat", "{}", "+"],
        &["-exec", "cat", "{}", "+"],
    ] {
        assert!(find_exec(&args(case)).is_none(), "{case:?}");
    }
}

#[test]
fn xargs_accepts_safe_options_only() {
    assert!(xargs(&args(&["-0", "-r", "-n", "5", "-P4", "cat"])).is_some());
    assert!(
        xargs(&args(&["-0", "grep", "-n", "x"]))
            .unwrap()
            .null_separated
    );
    for case in [
        &["-I{}", "cat", "{}"][..],
        &["-I", "{}", "cat"],
        &["-i", "cat"],
        &["--replace", "cat"],
        &["-0", "sh", "-c", "cat"],
        &["-0", "rm"],
        &["-0"],
        &["-a", "list", "cat"],
        &["-n", "x", "cat"],
    ] {
        assert!(xargs(&args(case)).is_none(), "{case:?}");
    }
}

fn confidence(command: &str) -> String {
    crate::parse_command(&crate::CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    })
    .unwrap()
    .confidence
}

#[test]
fn parser_models_only_the_read_only_shapes() {
    for command in [
        "find src -type f -exec cat {} +",
        "find src -type f -print0 | xargs -0 cat",
        "find src -type f | xargs grep -n x",
        "rg -l TODO src | xargs wc -l",
        "grep -rl TODO src | xargs wc -l",
        "rg -l --null TODO src | xargs -0 cat",
    ] {
        assert_eq!(confidence(command), "exact", "{command}");
    }
    for command in [
        "find src -type f | xargs -I{} sh -c 'cat {}'",
        "find src -type f -print0 | xargs -0 rm",
        "find src -type f -exec rm {} +",
        "find src -type f -delete -exec cat {} +",
        "echo a | xargs cat",
        "xargs cat",
        "find src -type f | sort | xargs cat",
        "rg -l TODO | xargs wc -l",
        "rg -n TODO src | xargs wc -l",
        "rg -l TODO src | xargs rm",
        "rg -l TODO src | sort | xargs wc -l",
    ] {
        assert_eq!(confidence(command), "uncertain", "{command}");
    }
}

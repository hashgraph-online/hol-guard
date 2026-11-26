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

#[test]
fn a_line_window_between_a_producer_and_xargs_keeps_its_reading() {
    for command in [
        "grep -rln TODO src | head -20 | xargs grep -ln FIXME",
        "rg -l TODO src | head | xargs wc -l",
        "rg -ln TODO src | tail -1 | xargs rg -n FIXME",
        "rg -l TODO src | tail -n +2 | xargs wc -l",
        "find src -type f -name '*.rs' | head -n 50 | xargs grep -l x",
        "rg -l TODO src | head --lines=5 | xargs wc -l",
        "fd -t f -e rs . src | head -20 | xargs rg -l x",
    ] {
        assert_eq!(confidence(command), "exact", "{command}");
    }
    for command in [
        // A byte window can start a word in the middle of a name.
        "rg -l TODO src | tail -c 20 | xargs wc -l",
        "rg -l TODO src | head -c20 | xargs wc -l",
        // A file operand prints that file, not the pipe.
        "rg -l TODO src | head -5 names.txt | xargs wc -l",
        // Following and other options are not a line window.
        "rg -l TODO src | tail -f | xargs wc -l",
        "rg -l TODO src | head -n x | xargs wc -l",
        // Two windows, a window with no producer, and a root-less producer.
        "rg -l TODO src | head -5 | head -2 | xargs wc -l",
        "echo a | head -1 | xargs cat",
        "rg -l TODO | head -5 | xargs wc -l",
        // The child is still read: no writer, no interpreter.
        "rg -l TODO src | head -5 | xargs rm",
        "rg -l TODO src | head -5 | xargs sh -c 'cat \"$0\"'",
    ] {
        assert_eq!(confidence(command), "uncertain", "{command}");
    }
}

#[test]
fn a_rooted_fd_walk_piped_to_xargs_is_read_like_its_exec_mode() {
    for command in [
        "fd -t f -e rs . src | xargs rg -l x",
        "fd -t f -e ts -e tsx . src tests | xargs grep -l x",
        "fd -t f . src | xargs wc -l",
        "fd --type f --extension md . docs | xargs cat",
    ] {
        assert_eq!(confidence(command), "exact", "{command}");
    }
    for command in [
        // No root, so fd prints each name bare and `-x.rs` is an option.
        "fd -t f -e rs | xargs rg -l x",
        "fd -t f -e rs main | xargs rg -l x",
        "fd -t f -e rs . -root | xargs rg -l x",
        // A symlink handed to the child as an operand is followed.
        "fd -e rs . src | xargs rg -l x",
        "fd -t f -L -e rs . src | xargs rg -l x",
        // A content reader needs a source extension.
        "fd -t f . src | xargs cat",
        "fd -t f -e env . src | xargs cat",
        // Roots the line places outside the working directory.
        "fd -t f -e rs . ../other | xargs rg -l x",
        "fd -t f -e rs . /etc | xargs rg -l x",
        // A shell glob, an unknown option and an exec mode.
        "fd -t f -e rs . src* | xargs rg -l x",
        "fd -t f -e rs --search-path /etc . src | xargs rg -l x",
        "fd -t f -e rs . src -x cat | xargs wc -l",
    ] {
        assert_eq!(confidence(command), "uncertain", "{command}");
    }
}

use super::*;

fn program(arguments: &[&str]) -> bool {
    let arguments: Vec<String> = arguments.iter().map(|a| (*a).to_owned()).collect();
    stage_lists_environment_names("awk", &arguments)
}

#[test]
fn an_awk_walk_over_environment_keys_lists_names() {
    for text in [
        "'BEGIN { for (name in ENVIRON) print name }'",
        "'BEGIN{for(k in ENVIRON)print k}'",
        "'BEGIN { for (k in ENVIRON) print k; }'",
        "\"BEGIN { for (var_1 in ENVIRON) print var_1 }\"",
        "'BEGIN {\n  for (name in ENVIRON)\n    print name\n}'",
    ] {
        assert!(program(&[text]), "{text}");
    }
}

/// Every program that could print a value, read a file or run a command is
/// refused, along with every shape this proof does not spell out.
#[test]
fn any_other_awk_program_is_refused() {
    for text in [
        "'BEGIN { for (k in ENVIRON) print k, ENVIRON[k] }'",
        "'BEGIN { for (k in ENVIRON) print ENVIRON[k] }'",
        "'BEGIN { for (k in ENVIRON) print j }'",
        "'BEGIN { for (k in ENVIRON) printf k }'",
        "'BEGIN { for (k in ENVIRON) print k > \"/tmp/names\" }'",
        "'BEGIN { for (k in ENVIRON) print k | \"sh\" }'",
        "'BEGIN { for (k in ENVIRON) system(k) }'",
        "'BEGIN { for (ORS in ENVIRON) print ORS }'",
        "'BEGIN { for (k in ENVIRON) print k } { print }'",
        "'BEGIN { for (k in ENVIRON) { print k } }'",
        "'END { for (k in ENVIRON) print k }'",
        "'{ for (k in ENVIRON) print k }'",
        "'BEGIN { for (k in PROCINFO) print k }'",
        "'BEGIN { for (k in ENVIRON) print k }' extra",
        "'BEGIN { for (k in ENVIRON) print $k }'",
        "\"BEGIN { for (k in ENVIRON) print k }$HOME\"",
        "'BEGIN { for (k in ENVIRON) print k }'\"'\"",
    ] {
        assert!(!program(&[text]), "{text}");
    }
    assert!(!program(&[]));
    assert!(!program(&[
        "-v",
        "x=1",
        "'BEGIN { for (k in ENVIRON) print k }'"
    ]));
    assert!(!program(&["-f", "names.awk"]));
    assert!(!program(&[
        "'BEGIN { for (k in ENVIRON) print k }'",
        "/etc/passwd"
    ]));
    assert!(!stage_lists_environment_names(
        "gawk",
        &["'BEGIN { for (k in ENVIRON) print k }'".to_owned()]
    ));
}

#[test]
fn an_argument_this_proof_cannot_read_is_refused() {
    assert_eq!(unquoted("'^A'"), Some("^A".to_owned()));
    assert_eq!(unquoted("\"^A\""), Some("^A".to_owned()));
    assert_eq!(unquoted("^A"), Some("^A".to_owned()));
    assert_eq!(unquoted("'^A'B'"), None);
    assert_eq!(unquoted("-F'='"), None);
    assert!(!stage_only_reorders_lines("sort", &["-é".to_owned()]));
}

#[test]
fn a_trailing_stage_may_only_reorder_count_or_trim() {
    for (command, arguments) in [
        ("sort", vec!["-u"]),
        ("sort", vec!["--unique", "--reverse"]),
        ("uniq", vec!["-c"]),
        ("wc", vec!["-l"]),
        ("head", vec!["-n", "20"]),
        ("head", vec!["-n20"]),
        ("head", vec!["--lines=20"]),
        ("tail", vec!["-5"]),
        ("nl", vec![]),
        ("cat", vec!["-n"]),
    ] {
        let arguments: Vec<String> = arguments.iter().map(|a| (*a).to_owned()).collect();
        assert!(
            stage_only_reorders_lines(command, &arguments),
            "{command} {arguments:?}"
        );
    }
    for (command, arguments) in [
        ("sort", vec!["-o", "/tmp/names"]),
        ("sort", vec!["-o/tmp/names"]),
        ("sort", vec!["--output=/tmp/names"]),
        ("sort", vec!["--compress-program=sh"]),
        ("sort", vec!["--files0-from=list"]),
        ("sort", vec!["--random-source=/dev/urandom"]),
        ("sort", vec!["-T", "/tmp"]),
        ("sort", vec!["names.txt"]),
        ("head", vec!["-n", "names.txt"]),
        ("head", vec!["names.txt"]),
        ("nl", vec!["names.txt"]),
        ("cat", vec!["secrets.txt"]),
        ("tee", vec!["-a"]),
        ("xargs", vec!["-n1"]),
    ] {
        let arguments: Vec<String> = arguments.iter().map(|a| (*a).to_owned()).collect();
        assert!(
            !stage_only_reorders_lines(command, &arguments),
            "{command} {arguments:?}"
        );
    }
}

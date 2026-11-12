//! `head` and `tail` over files: each operand meets the single-file proof
//! `cat` gives its operands.
use super::*;

fn context(root: &str) -> super::super::PathContext<'_> {
    super::super::PathContext {
        home_dir: Some(root),
        cwd: Some(root),
        ..Default::default()
    }
}

fn arguments(line: &str) -> Vec<String> {
    line.split_whitespace().map(str::to_owned).collect()
}

#[test]
fn a_bare_plus_number_is_a_file_operand_not_a_line_count() {
    let root = env!("CARGO_MANIFEST_DIR");
    // `+31` is a file name to GNU `head` and `tail`, so it is proven as one:
    // missing here, it reads nothing, and the operand beside it is still
    // proven on its own.
    assert!(safe_head_tail_arguments(
        &arguments("+31 Cargo.toml"),
        false,
        context(root)
    ));
    assert!(!safe_head_tail_arguments(
        &arguments("+31 .env"),
        false,
        context(root)
    ));
    assert!(safe_head_tail_arguments(
        &arguments("-n +31 Cargo.toml"),
        false,
        context(root)
    ));
}

#[test]
fn every_file_operand_is_proven_on_its_own() {
    let root = env!("CARGO_MANIFEST_DIR");
    for line in [
        "Cargo.toml src/lib.rs",
        "-n 3 Cargo.toml src/lib.rs",
        "-3 Cargo.toml src/lib.rs",
        "-n3 Cargo.toml src/lib.rs",
        "-c 10 -- Cargo.toml src/lib.rs",
    ] {
        assert!(
            safe_head_tail_arguments(&arguments(line), false, context(root)),
            "{line}"
        );
    }
    for line in [
        "Cargo.toml .env",
        "-n 3 Cargo.toml /etc/master.passwd",
        "-n 3 Cargo.toml ~/.ssh/id_rsa",
        "Cargo.toml -",
        "-f Cargo.toml src/lib.rs",
        "-n 3 -- Cargo.toml .env",
    ] {
        assert!(
            !safe_head_tail_arguments(&arguments(line), false, context(root)),
            "{line}"
        );
    }
}

#[test]
fn the_operand_count_has_the_cat_bound() {
    let root = env!("CARGO_MANIFEST_DIR");
    let within = vec!["Cargo.toml"; MAX_PLAIN_FILE_TARGETS].join(" ");
    let past = vec!["Cargo.toml"; MAX_PLAIN_FILE_TARGETS + 1].join(" ");
    assert!(safe_head_tail_arguments(
        &arguments(&within),
        false,
        context(root)
    ));
    assert!(!safe_head_tail_arguments(
        &arguments(&past),
        false,
        context(root)
    ));
    // Reading standard input names no operand at all.
    assert!(!safe_head_tail_stdin_arguments(&arguments("Cargo.toml")));
    assert!(safe_head_tail_stdin_arguments(&arguments("-n 3")));
}

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
fn a_bare_plus_number_is_neither_a_count_nor_a_proven_file() {
    let root = env!("CARGO_MANIFEST_DIR");
    // `head` opens a file named `+31`; GNU `tail +31 FILE` starts at line 31
    // and `tail +31f FILE` follows the file. A second operand cannot make
    // either reading proven.
    for line in [
        "+31 Cargo.toml",
        "+31f Cargo.toml",
        "+31 .env",
        "Cargo.toml +31",
    ] {
        assert!(
            !safe_head_tail_arguments(&arguments(line), false, context(root)),
            "{line}"
        );
    }
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

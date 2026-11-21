//! Compiled adversarial corpus, identity half: case-folding and Unicode
//! collisions, lookalike manifests and suffixes, and reason priority.
#![cfg(unix)]

mod common;

use common::*;

fn collision(first: &str, second: &str) -> Vec<u8> {
    archive(&[file(first, b"a"), file(second, b"b")])
}

#[test]
fn non_ascii_case_folding_collisions() {
    run(vec![
        ("ASCII case", collision("a/Readme", "a/README"), CONFLICT),
        (
            "sharp s vs SS",
            collision("stra\u{df}e", "STRASSE"),
            CONFLICT,
        ),
        ("long s vs s", collision("\u{17f}", "s"), CONFLICT),
        ("Kelvin sign vs k", collision("\u{212a}", "k"), CONFLICT),
        (
            "final sigma vs sigma",
            collision("\u{3c2}", "\u{3c3}"),
            CONFLICT,
        ),
        (
            "capital sigma vs final sigma",
            collision("\u{3a3}", "\u{3c2}"),
            CONFLICT,
        ),
        (
            "fi ligature vs fi",
            collision("\u{fb01}le", "file"),
            CONFLICT,
        ),
        (
            "NFC vs NFD e-acute",
            collision("caf\u{e9}", "cafe\u{301}"),
            CONFLICT,
        ),
        (
            "Angstrom sign vs A-ring",
            collision("\u{212b}", "\u{c5}"),
            CONFLICT,
        ),
        (
            "dotted capital I vs i-dot",
            collision("\u{130}", "i\u{307}"),
            CONFLICT,
        ),
        (
            "file then directory of the same folded name",
            archive(&[file("Dir", b"x"), file("dIR/inner", b"y")]),
            CONFLICT,
        ),
        (
            "dotless i is a different letter",
            collision("\u{131}", "i"),
            CLEAN,
        ),
        ("distinct names stay clean", collision("a", "b"), CLEAN),
        (
            "ASCII fast path and fold path agree on a clean pair",
            collision("abc", "abd"),
            CLEAN,
        ),
    ]);
}

#[test]
fn lookalike_manifests_and_suffixes() {
    let install = br#"{"name":"x","scripts":{"postinstall":"x"}}"#;
    let script = ("blocked", "tarball_install_script");
    let python = ("blocked", "python_build_script_risk");
    let pyproject = ("blocked", "python_build_backend_risk");
    let gyp = ("blocked", "node_gyp_implicit_install_script");
    let link = ("blocked", "external_archive_manifest_link");
    run(vec![
        (
            "package.json",
            archive(&[file("p/package.json", install)]),
            script,
        ),
        (
            "PACKAGE.JSON",
            archive(&[file("p/PACKAGE.JSON", install)]),
            script,
        ),
        (
            "package.j(long s)on",
            archive(&[file("p/package.j\u{17f}on", install)]),
            script,
        ),
        ("setup.py", archive(&[file("p/setup.py", b"x")]), python),
        (
            "(long s)etup.py",
            archive(&[file("p/\u{17f}etup.py", b"x")]),
            python,
        ),
        ("SETUP.PY", archive(&[file("p/SETUP.PY", b"x")]), python),
        (
            "pyproject.toml",
            archive(&[file("p/pyproject.toml", b"x")]),
            pyproject,
        ),
        (
            "PyProject.TOML",
            archive(&[file("p/PyProject.TOML", b"x")]),
            pyproject,
        ),
        ("binding.gyp", archive(&[file("p/binding.gyp", b"{}")]), gyp),
        ("BINDING.GYP", archive(&[file("p/BINDING.GYP", b"{}")]), gyp),
        (
            "binding.gyp as a symlink",
            archive(&[symlink("p/binding.gyp", "x")]),
            link,
        ),
        (
            "(long s)etup.py as a symlink",
            archive(&[symlink("p/\u{17f}etup.py", "x")]),
            link,
        ),
        (
            "package.json as a hardlink",
            archive(&[file("a", b"x"), hardlink("p/package.json", "a")]),
            link,
        ),
        (
            "a name merely containing setup.py",
            archive(&[file("p/mysetup.py", b"x")]),
            CLEAN,
        ),
        (
            "a name merely containing package.json",
            archive(&[file("p/package.json.bak", b"x")]),
            CLEAN,
        ),
        (
            "manifest in a directory named like a manifest",
            archive(&[file("setup.py/readme", b"x")]),
            CLEAN,
        ),
    ]);
}

#[test]
fn nested_archive_suffixes_fold_like_manifests() {
    let mut limit = caps();
    limit.max_nested_archives = 0;
    let nested = ("blocked", "external_archive_nesting_limit");
    for (label, name) in [
        ("tar", "a.tar"),
        ("upper TAR", "a.TAR"),
        ("tgz", "a.tgz"),
        ("zip", "a.zip"),
        ("whl", "a.whl"),
    ] {
        let outcome = inspect_with(&archive(&[file(name, b"x")]), &limit);
        assert_outcome(&outcome, nested.0, nested.1);
        assert!(!label.is_empty());
    }
    let outcome = inspect_with(&archive(&[file("a.t\u{17f}z", b"x")]), &limit);
    assert_outcome(&outcome, "clean", "external_archive_inspection_clean");
    let outcome = inspect_with(&archive(&[file("a.tar.bak", b"x")]), &limit);
    assert_outcome(&outcome, "clean", "external_archive_inspection_clean");
}

#[test]
fn reason_priority_follows_the_fixed_order() {
    let long = "d/".repeat(70) + "f";
    run(vec![
        (
            "unsafe path outranks an unsupported type",
            archive(&[member_with(b"../x", b'V', b"", b"", Magic::Ustar)]),
            SLIP,
        ),
        (
            "unsupported type outranks a path conflict",
            archive(&[
                file("a", b"x"),
                member_with(b"A", b'V', b"", b"", Magic::Ustar),
            ]),
            UNSUPPORTED,
        ),
        (
            "path depth outranks a conflict on the same member",
            archive(&[
                gnu_longname(long.as_bytes()),
                file("a", b"x"),
                gnu_longname(long.to_uppercase().as_bytes()),
                file("a", b"x"),
            ]),
            ("blocked", "external_archive_path_depth_limit"),
        ),
        (
            "conflict outranks member size",
            archive(&[
                file("a", b"x"),
                header(b"A", b'0', 1 << 40, b"", Magic::Ustar).to_vec(),
            ]),
            CONFLICT,
        ),
    ]);
}

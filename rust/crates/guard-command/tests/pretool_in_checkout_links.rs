//! A read of a link inside the working checkout is judged by the file the
//! link reaches. A cloned repository can carry a link such as
//! `src/link.ts -> ~/notes/secret.txt`, so reading the link by its in-repo
//! name must take the same answer as reading the file it points to.
#![cfg(unix)]

use crate::pretool_home_layout_reads::{assert_decision, layout, write};

#[test]
fn a_link_inside_the_checkout_takes_the_answer_of_the_file_it_reaches() {
    let layout = layout("in-checkout-links");
    let cwd = layout.org.join("app-portal");
    write(cwd.join("src/real.ts"), "export const real = 1;\n");
    let secret = layout.home.join("notes/secret.txt");
    write(secret.clone(), "TOKEN=fixture\n");
    std::os::unix::fs::symlink(&secret, cwd.join("src/link.ts")).unwrap();
    std::os::unix::fs::symlink("real.ts", cwd.join("src/alias.ts")).unwrap();

    // Reading the target directly is reviewed, so the link must be too.
    assert_decision(
        &cwd,
        &layout.home,
        &format!("grep -n TOKEN {}", secret.display()),
        false,
    );
    for command in [
        "cat src/link.ts",
        "cat ./src/link.ts",
        "head -5 src/link.ts",
        "grep -n TOKEN src/link.ts",
        "grep -n TOKEN src/*.ts",
        "wc -l src/link.ts",
    ] {
        assert_decision(&cwd, &layout.home, command, false);
    }
    // A link that stays inside the checkout reads like its target.
    for command in [
        "cat src/real.ts",
        "cat src/alias.ts",
        "grep -n real src/alias.ts",
    ] {
        assert_decision(&cwd, &layout.home, command, true);
    }
}

#[test]
fn a_glob_follows_a_directory_link_inside_the_checkout() {
    let layout = layout("in-checkout-dir-links");
    let cwd = layout.org.join("app-portal");
    write(cwd.join("deep/nested/real.ts"), "export const real = 1;\n");
    let secret = layout.home.join("notes/secret.txt");
    write(secret.clone(), "TOKEN=fixture\n");
    std::os::unix::fs::symlink(&secret, cwd.join("deep/nested/evil.ts")).unwrap();
    // `lib` itself stays inside the checkout; the shell's glob walks
    // through it and reaches the outside link one level down.
    std::os::unix::fs::symlink("deep/nested", cwd.join("lib")).unwrap();
    // A link back to the checkout root must not loop the walk.
    std::os::unix::fs::symlink(".", cwd.join("deep/root")).unwrap();

    assert_decision(&cwd, &layout.home, "grep -n TOKEN l*/*.ts", false);
    assert_decision(&cwd, &layout.home, "grep -n TOKEN lib/*.ts", false);
    std::fs::remove_file(cwd.join("deep/nested/evil.ts")).unwrap();
    assert_decision(&cwd, &layout.home, "grep -n real lib/*.ts", true);
}

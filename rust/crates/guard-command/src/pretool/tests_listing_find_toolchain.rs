#![cfg(unix)]

use super::tests_listing_find_probes::{allowed_in, fixture};

/// A Node toolchain's version directories are what an agent lists before it
/// picks a runtime. `-printf` with name directives prints what `-print`
/// does, and a `-path` test inside a conjunction only narrows what `-type d`
/// already bounds, so neither should turn the inventory into a review.
#[test]
fn toolchain_inventory_under_a_home_dot_directory_takes_name_formats() {
    let fixture = fixture();
    let home = std::path::Path::new(&fixture.home);
    for directory in [
        ".nvm/versions/node/v25.2.1/lib/node_modules/inert-pkg",
        ".nvm/versions/node/v24.0.0/bin",
    ] {
        std::fs::create_dir_all(home.join(directory)).unwrap();
    }
    let node = format!("{}/.nvm/versions/node", fixture.home);
    let ws = fixture.workspace.as_str();
    for command in [
        format!("find \"{node}\" -mindepth 1 -maxdepth 1 -type d -printf '%f\\n'"),
        format!("find \"{node}\" -mindepth 1 -maxdepth 1 -type d -printf '%f\\n' | sort -V"),
        format!(
            "find \"{node}\" -path '*/lib/node_modules/*' -mindepth 1 -maxdepth 4 -type d -print"
        ),
        format!("find \"{node}\" -type d -wholename '*/lib/*'"),
    ] {
        assert!(allowed_in(&fixture, ws, &command), "{command}");
    }
    for command in [
        // `-path` bounds nothing on its own: every entry under a matching
        // directory, files included, is printed.
        format!("find \"{node}\" -path '*/lib/*' -print"),
        // A print before the bounding test prints the whole walk.
        format!("find \"{node}\" -printf '%f\\n' -type d"),
        format!("find \"{node}\" -type d -printf '%l\\n'"),
        format!("find \"{node}\" -type d -printf '%u %f\\n'"),
        // Alternation widens the output back to the whole tree.
        format!("find \"{node}\" -path '*/lib' -prune -o -print"),
    ] {
        assert!(!allowed_in(&fixture, ws, &command), "{command}");
    }
}

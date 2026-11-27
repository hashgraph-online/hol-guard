//! A short named struct, enum or interface with no methods inside is shown
//! whole: its fields answer what the type holds.
use super::super::project_tests::{project, prompt_map, ON};

const RUST: &str = "use std::ptr::NonNull;

/// A pre-release or build identifier.
pub(crate) struct Identifier {
    head: NonNull<u8>,
    tail: [u8; 8],
}

impl Identifier {
    pub(crate) fn empty() -> Self {
        todo!()
    }
}
";

const GO: &str = "package route

// Route is one registered path.
type Route struct {
\tPattern string
\tMethods []string
}

func (r *Route) Match(path string) bool {
\treturn r.Pattern == path
}
";

const TS: &str = "export interface ParseOptions {
  loose: boolean;
  includePrerelease?: boolean;
}

export function parse(text: string, options: ParseOptions): string {
  return options.loose ? text.trim() : text;
}
";

/// Asked to make a struct `Send`, the agent needs its fields; named by
/// range alone, it opened the file to read them.
#[test]
fn a_short_named_struct_is_shown_whole() {
    let (home, _project, root) = project(ON, &[("src/identifier.rs", RUST)]);
    let text = prompt_map(home.path(), &root, "Impl Send + Sync for Identifier").unwrap();
    assert!(
        text.contains("    head: NonNull<u8>,\n    tail: [u8; 8],\n}\n```"),
        "{text}"
    );
}

#[test]
fn a_short_go_struct_and_ts_interface_are_shown_whole() {
    let (home, _project, root) = project(ON, &[("route/route.go", GO)]);
    let text = prompt_map(home.path(), &root, "Add a Name field to Route").unwrap();
    assert!(text.contains("\tMethods []string\n}\n```"), "{text}");
    let (home, _project, root) = project(ON, &[("src/parse.ts", TS)]);
    let text = prompt_map(
        home.path(),
        &root,
        "ParseOptions should accept a strict flag",
    )
    .unwrap();
    assert!(
        text.contains("  includePrerelease?: boolean;\n}\n```"),
        "{text}"
    );
}

/// A long struct is mostly fields the request does not touch: it is named
/// by its range only.
#[test]
fn a_long_named_struct_is_not_shown_whole() {
    let fields: String = (0..40)
        .map(|at| format!("    field_{at}: u32,\n"))
        .collect();
    let source = format!("pub struct Settings {{\n{fields}}}\n");
    let (home, _project, root) = project(ON, &[("src/settings.rs", &source)]);
    let text = prompt_map(home.path(), &root, "Add a timeout to Settings").unwrap();
    assert!(text.contains("src/settings.rs:1-42"), "{text}");
    assert!(!text.contains("field_7"), "{text}");
}

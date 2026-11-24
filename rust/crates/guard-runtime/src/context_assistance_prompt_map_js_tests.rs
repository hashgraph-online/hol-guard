//! JavaScript and TypeScript tests are calls, `test("...", () => {...})`,
//! not definitions; the map finds them as it finds `def test_...`.
use super::super::super::sections::test_call;
use super::super::project_tests::{project, prompt_map, ON};

const UTILS: &str = "export function cleanDoubleSlashes(input = \"\"): string {
  return input.split(\"://\").map((part) => part.replace(/\\/{2,}/g, \"/\")).join(\"://\");
}

export function joinURL(base: string, path: string): string {
  return base + \"/\" + path;
}
";

const SLASHES: &str = "import { describe, expect, test } from \"vitest\";
import { cleanDoubleSlashes } from \"../src\";

describe(\"cleanDoubleSlashes\", () => {
  const cases = {
    \"//foo//bar//\": \"/foo/bar/\",
    \"http://foo.com//\": \"http://foo.com/\",
  };

  for (const input in cases) {
    test(input, () => {
      expect(cleanDoubleSlashes(input)).toBe(cases[input]);
    });
  }
});
";

const JOIN: &str = "import { describe, expect, it } from \"vitest\";
import { joinURL } from \"../src\";

describe(\"joinURL\", () => {
  it.each([[\"a\", \"b\", \"a/b\"]])(\"joins %s and %s\", (base, path, out) => {
    expect(joinURL(base, path)).toBe(out);
  });
});
";

/// Asked to add tests for a function, the agent opened the file that tests
/// it to copy its style; that file and its test now come with the note.
#[test]
fn a_vitest_file_is_listed_for_the_function_it_tests() {
    let files = [
        ("src/utils.ts", UTILS),
        ("test/double-slash.test.ts", SLASHES),
        ("test/join.test.ts", JOIN),
    ];
    let (home, _project, root) = project(ON, &files);
    let text = prompt_map(home.path(), &root, "Add tests for cleanDoubleSlashes").unwrap();
    assert!(
        text.contains("test/double-slash.test.ts: 1 related tests, last test input 11-13"),
        "{text}"
    );
    assert!(
        text.contains("expect(cleanDoubleSlashes(input)).toBe(cases[input]);"),
        "{text}"
    );
    assert!(!text.contains("test/join.test.ts"), "{text}");
}

/// The calls that open a test or a group of tests, and lines that only look
/// like them.
#[test]
fn test_calls_are_told_from_other_calls() {
    for (line, called) in [
        ("  it(\"adds\", () => {", Some("it")),
        ("test.each([", Some("test")),
        ("test.each`", Some("test")),
        ("describe.skip(\"slow\", () => {", Some("describe")),
        ("it.concurrent.only(\"x\", async () => {", Some("it")),
        ("suite(\"urls\", () => {", Some("suite")),
        ("iterate(items);", None),
        ("testing(input);", None),
        ("test_helper(input);", None),
        ("it.(x)", None),
        ("items.push(it);", None),
    ] {
        assert_eq!(test_call(line), called, "{line}");
    }
}

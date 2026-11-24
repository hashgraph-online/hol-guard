//! The project helpers a named function calls are listed, the short ones
//! with their code.
use super::super::super::project_tests::{project, prompt_map, ON};

const UTILS: &str = "export function hasProtocol(input: string): boolean {
  return /^[a-z][a-z0-9+.-]*:/i.test(input);
}

export function withoutTrailingSlash(input = \"\"): string {
  return input.endsWith(\"/\") ? input.slice(0, -1) : input;
}

export function isEmptyURL(url: string): boolean {
  return !url || url === \"/\";
}

export function withBase(input: string, base: string): string {
  if (isEmptyURL(base) || hasProtocol(input)) {
    return input;
  }
  const trimmed = withoutTrailingSlash(base);
  return trimmed + input;
}
";

const OTHER: &str = "export function joinURL(base: string, path: string): string {
  return base + \"/\" + path;
}
";

/// Asked to change `withBase`, the agent opened the helpers it calls to see
/// what they return; their code now comes with the note.
#[test]
fn the_helpers_a_named_function_calls_are_shown() {
    let (home, _project, root) = project(ON, &[("src/utils.ts", UTILS), ("src/join.ts", OTHER)]);
    let text = prompt_map(
        home.path(),
        &root,
        "withBase should keep the trailing slash of base",
    )
    .unwrap();
    assert!(text.contains("Project functions withBase calls:"), "{text}");
    assert!(
        text.contains("return input.endsWith(\"/\") ? input.slice(0, -1) : input;"),
        "{text}"
    );
    assert!(text.contains("return !url || url === \"/\";"), "{text}");
    assert!(
        text.contains("/^[a-z][a-z0-9+.-]*:/i.test(input)"),
        "{text}"
    );
    assert!(!text.contains("joinURL"), "{text}");
}

/// A name two files read for the map define is not guessed at.
#[test]
fn a_helper_defined_twice_is_not_listed() {
    let twice =
        "// Not the check withBase uses.\nexport function isEmptyURL(url: string): boolean {\n  return url.length === 0;\n}\n";
    let (home, _project, root) = project(ON, &[("src/utils.ts", UTILS), ("src/empty.ts", twice)]);
    let text = prompt_map(
        home.path(),
        &root,
        "withBase should keep the trailing slash of base",
    )
    .unwrap();
    assert!(text.contains("Project functions withBase calls:"), "{text}");
    assert!(!text.contains("isEmptyURL(url"), "{text}");
}

/// A rename lists every use instead.
#[test]
fn a_rename_does_not_list_helpers() {
    let (home, _project, root) = project(ON, &[("src/utils.ts", UTILS)]);
    let text = prompt_map(home.path(), &root, "Rename withBase to joinBase everywhere").unwrap();
    assert!(
        !text.contains("Project functions withBase calls:"),
        "{text}"
    );
}

/// `unicodedata.normalize(...)` is not the project's `URL.normalize`: a call
/// through another value names no project function.
#[test]
fn a_call_through_another_value_is_not_a_project_method() {
    let source = "import unicodedata


class URL:
    def normalize(self):
        return self


def quote_part(text):
    text = unicodedata.normalize('NFC', text)
    return _encode(text)


def _encode(text):
    return text.encode('utf-8')
";
    let (home, _project, root) = project(ON, &[("pkg/urls.py", source)]);
    let text = prompt_map(home.path(), &root, "Add a doctest to quote_part").unwrap();
    assert!(
        text.contains("Project functions quote_part calls:"),
        "{text}"
    );
    assert!(text.contains("return text.encode('utf-8')"), "{text}");
    assert!(!text.contains("def normalize(self):"), "{text}");
}

/// A method's calls through `self` reach the other methods of its class.
#[test]
fn a_call_through_self_reaches_a_sibling_method() {
    let source = "class Cache:
    def get(self, key):
        if self._expired(key):
            return None
        return self.data[key]

    def _expired(self, key):
        return key in self.stale


def _expired(key):
    return False
";
    let (home, _project, root) = project(ON, &[("pkg/cache.py", source)]);
    let text = prompt_map(home.path(), &root, "Cache.get should count misses").unwrap();
    assert!(text.contains("return key in self.stale"), "{text}");
    assert!(!text.contains("    return False"), "{text}");
}

/// A helper in a file Guard keeps out for what it holds, such as a line its
/// secret check takes for a credential, is never shown: the block reads only
/// the files the map may show. The same helper in a clean file is.
#[test]
fn a_helper_in_a_withheld_file_is_not_shown() {
    let caller = "def build(env):\n    session = make_session(env)\n    return session\n";
    let held = concat!("to", "ken = self.stream.current");
    let kept_out = format!("def make_session(env):\n    {held}\n    return env.open()\n");
    let clean = "def make_session(env):\n    return env.open()\n";
    let prompt = "build should log env before make_session opens it";
    for (helper, shown) in [(kept_out.as_str(), false), (clean, true)] {
        let list = [("src/app.py", caller), ("src/session.py", helper)];
        let (home, _project, root) = project(ON, &list);
        let text = prompt_map(home.path(), &root, prompt).unwrap();
        assert!(!text.contains("stream.current"), "{text}");
        assert_eq!(text.contains("return env.open()"), shown, "{text}");
    }
}

//! Definitions are found, and named, in the languages projects use.
use super::*;

fn named(line: &str) -> Option<String> {
    assert!(definition(line), "not a definition: {line}");
    written_name(line)
}

#[test]
fn methods_without_a_keyword_open_definitions_and_are_named() {
    for (line, name) in [
        ("  parse(url: string): URL {", "parse"),
        (
            "  async fetchAll<T>(ids: string[]): Promise<T[]> {",
            "fetchAll",
        ),
        ("  get size() {", "size"),
        (
            "  constructor(private readonly store: Store) {",
            "constructor",
        ),
        ("    withQuery(input, query = {}) {", "withQuery"),
        (
            "    public static int count(List<String> items) throws IOException {",
            "count",
        ),
        (
            "    private Map<String, Integer> totals(final Order order) {",
            "totals",
        ),
        ("    public synchronized void flush() {", "flush"),
        (
            "        public async Task<int> GetAsync(int id)",
            "GetAsync",
        ),
        ("std::string Box::name() const {", "name"),
        ("Box::Box(int size) : size_(size) {", "Box"),
        ("int main(int argc, char **argv) {", "main"),
        ("struct node *new_node(int v) {", "new_node"),
        ("enum color parse_color(const char *s) {", "parse_color"),
        ("static const char *label(void) {", "label"),
        ("const std::string& Box::name() const {", "name"),
        (
            "  pick<T, K extends keyof T>(obj: T, key: K): T[K] {",
            "pick",
        ),
        ("    synchronized void flush() {", "flush"),
        ("    int size() const { return size_; }", "size"),
    ] {
        assert_eq!(named(line).as_deref(), Some(name), "{line}");
    }
}

#[test]
fn keyword_definitions_in_more_languages_are_named() {
    for (line, name) in [
        ("pub const fn len(&self) -> usize {", "len"),
        (
            "pub(in crate::store) unsafe fn raw(ptr: *const u8) {",
            "raw",
        ),
        ("pub extern \"C\" fn hook(x: i32) -> i32 {", "hook"),
        ("    suspend fun load(id: Long): User {", "load"),
        ("data class Point(val x: Int, val y: Int)", "Point"),
        ("object Registry {", "Registry"),
        (
            "export declare function sign(input: string): string;",
            "sign",
        ),
        ("public record Money(decimal Amount);", "Money"),
        ("namespace Billing {", "Billing"),
        ("struct Point {", "Point"),
        ("pub(crate) struct Identifier {", "Identifier"),
        ("pub(super) enum Kind {", "Kind"),
        ("enum Color {", "Color"),
        ("object Registry extends Base {", "Registry"),
        ("extension Array where Element: Equatable {", "Array"),
    ] {
        assert_eq!(named(line).as_deref(), Some(name), "{line}");
    }
}

#[test]
fn calls_statements_and_blocks_are_not_definitions() {
    for line in [
        "    if (ready(x)) {",
        "} else if (count > 0) {",
        "    for (const item of items) {",
        "    synchronized (lock) {",
        "    return build(x) {",
        "    new Thread(task) {",
        "  it(\"adds two numbers\", () => {",
        "describe('cart', function () {",
        "    t.Run(\"empty\", func(t *testing.T) {",
        "        Ok(value) => {",
        "    UIView.animate(withDuration: 0.3) {",
        "        Button(action: save) {",
        "    items.forEach(item -> {",
        "module.exports = function (x) {",
        "  parse(url: string): URL;",
        "    run(task)",
        "        withContext(Dispatchers.IO) {",
        "    repeat(3) {",
        "        launch(start = CoroutineStart.LAZY) {",
        "        withAnimation(.spring) {",
        "[HttpGet(\"items\")]",
    ] {
        assert!(!definition(line), "{line}");
    }
}

#[test]
fn python_lines_read_as_before() {
    for (line, name) in [
        ("def parse(url):", Some("parse")),
        ("    async def fetch(self, key):", Some("fetch")),
        ("class Store(Base):", Some("Store")),
    ] {
        assert!(definition(line), "{line}");
        assert_eq!(written_name(line).as_deref(), name, "{line}");
    }
    for line in [
        "    print(value)",
        "    data = load(path)",
        "object = make()",
        "    result = run(task, {",
        "@app.route(\"/items\")",
        "    open(path).read()",
        "    private(x)",
        "object and refresh()",
        "object in seen",
    ] {
        assert!(!definition(line), "{line}");
    }
    // Top-level bindings stay definitions; locals do not.
    assert!(definition("const LIMIT = 3"));
    assert!(!definition("    const limit = 3"));
    assert_eq!(written_name("const LIMIT = 3").as_deref(), Some("LIMIT"));
}

#[test]
fn a_c_function_with_its_brace_on_the_next_line_is_named() {
    assert_eq!(
        written_name("struct node *new_node(int v)").as_deref(),
        Some("new_node")
    );
    assert_eq!(written_name("struct node {").as_deref(), Some("node"));
}

#[test]
fn many_const_words_on_one_line_are_read_in_linear_time() {
    let line = "const ".repeat(4096) + "fn late() {";
    let started = std::time::Instant::now();
    assert_eq!(written_name(&line).as_deref(), Some("late"));
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
}

#[test]
fn top_level_constants_and_typed_values_are_named_definitions() {
    for (line, name) in [
        ("MAX_INLINE_NESTING = 400", "MAX_INLINE_NESTING"),
        ("MAX_INLINE_NESTING: Final = sys.getrecursionlimit()", "MAX_INLINE_NESTING"),
        (
            "_mutable_spec: t.Tuple[t.Tuple[t.Type[t.Any], t.FrozenSet[str]], ...] = (",
            "_mutable_spec",
        ),
        ("DEFAULT_TIMEOUT=30", "DEFAULT_TIMEOUT"),
        ("static RETRIES: u32 = 3;", "RETRIES"),
        ("pub static NAMES: [&str; 2] = [\"a\", \"b\"];", "NAMES"),
        ("HTTP2 = True", "HTTP2"),
    ] {
        assert_eq!(named(line).as_deref(), Some(name), "{line}");
    }
}

#[test]
fn assignments_that_are_not_constants_stay_statements() {
    for line in [
        "object = make()",
        "result = run(task)",
        "    LIMIT = 3",
        "    limit: int = 3",
        "else: x = 1",
        "finally: CLEANUP = 1",
        "FLAG == other",
        "name: value",
        "x::y = 3",
        "url: http://example.test/?a=b",
    ] {
        assert!(!definition(line), "{line}");
    }
}

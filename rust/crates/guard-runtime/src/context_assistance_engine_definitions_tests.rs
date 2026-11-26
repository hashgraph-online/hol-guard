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
    ] {
        assert!(!definition(line), "{line}");
    }
    // Top-level bindings stay definitions; locals do not.
    assert!(definition("const LIMIT = 3"));
    assert!(!definition("    const limit = 3"));
    assert_eq!(written_name("const LIMIT = 3").as_deref(), Some("LIMIT"));
}

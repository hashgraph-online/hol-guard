use super::*;
use crate::context_assistance_prompt_files::Walk;
use std::time::{Duration, Instant};

fn section(start: usize, end: usize) -> Section {
    Section {
        start,
        end,
        name: None,
    }
}

/// Each section's parent is the smallest section around it, whatever order
/// the sections come in; top-level sections and siblings have none of each
/// other.
#[test]
fn each_section_finds_the_smallest_section_around_it() {
    let sections = vec![
        section(5, 6),
        section(1, 10),
        section(12, 14),
        section(7, 8),
        section(3, 9),
        section(13, 13),
    ];
    assert_eq!(
        more::parents(&sections),
        vec![Some(4), None, None, Some(4), Some(1), Some(2)]
    );
}

/// Many one-line definitions are placed in one pass, well inside the time a
/// prompt hook has.
#[test]
fn many_sections_are_placed_quickly() {
    let mut sections: Vec<Section> = (2..20_002).map(|line| section(line, line)).collect();
    sections.push(section(1, 20_002));
    let started = Instant::now();
    let parent = more::parents(&sections);
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(parent[..20_000].iter().all(|outer| *outer == Some(20_000)));
    assert_eq!(parent[20_000], None);
}

/// A test class, even one inside another, counts by the tests in it rather
/// than as a test of its own.
#[test]
fn a_test_class_counts_by_the_tests_inside_it() {
    let tests = "class TestTypes:
    class TestChoice:
        def test_a(self):
            click.Choice(['a'])

        def test_b(self):
            click.Choice(['b'])
";
    let walk = Walk {
        checked: 200,
        holding: vec![3],
        words: vec![3],
        ..Walk::default()
    };
    let text = map(
        &[
            (
                "src/core.py".to_owned(),
                "class Choice:\n    pass\n".to_owned(),
            ),
            ("tests/test_types.py".to_owned(), tests.to_owned()),
        ],
        &sought(&walk, &[("choice".to_owned(), true)], &[]),
        &Asked::default(),
        Instant::now() + Duration::from_secs(10),
    )
    .unwrap()
    .text;
    assert!(
        text.contains("tests/test_types.py: 2 related tests, last TestChoice.test_b 6-7"),
        "{text}"
    );
}

/// A helper defined inside a test is part of that test: the test that
/// calls `print_exception` is listed, not its `def test()` helper.
#[test]
fn a_helper_inside_a_test_is_part_of_it() {
    let tests = "def test_exception_info():
    def test():
        raise ValueError('yay fun')

    print_exception(ValueError, None, None)
";
    let walk = Walk {
        checked: 200,
        holding: vec![2],
        words: vec![2],
        ..Walk::default()
    };
    let text = map(
        &[
            (
                "src/tb.py".to_owned(),
                "def print_exception(etype, value, tb):\n    raise NotImplementedError\n"
                    .to_owned(),
            ),
            ("tests/test_tb.py".to_owned(), tests.to_owned()),
        ],
        &sought(&walk, &[("printexception".to_owned(), true)], &[]),
        &Asked::default(),
        Instant::now() + Duration::from_secs(10),
    )
    .unwrap()
    .text;
    assert!(
        text.contains("tests/test_tb.py: 1 related tests, last test_exception_info 1-5"),
        "{text}"
    );
}

/// Quoted text a docstring wraps over two lines is found at the line it
/// starts on.
#[test]
fn quoted_text_a_docstring_wraps_is_found() {
    let source = "def _multicall(hook_impls):
    \"\"\"Execute a call into multiple python functions and return the
    result(s).
    \"\"\"
    return [impl() for impl in hook_impls]
";
    let walk = Walk {
        checked: 200,
        quoting: vec![1],
        ..Walk::default()
    };
    let quoted =
        ["execute a call into multiple python functions and return the result(s).".to_owned()];
    let text = map(
        &[("src/callers.py".to_owned(), source.to_owned())],
        &sought(&walk, &[], &quoted),
        &Asked::default(),
        Instant::now() + Duration::from_secs(10),
    )
    .unwrap()
    .text;
    assert!(
        text.contains("src/callers.py:1-5 _multicall (lines 2)"),
        "{text}"
    );
}

/// A piece of a name the map places is found with it: other lines saying
/// `signature` are about something else. A piece of a name nothing defines is
/// still looked for.
#[test]
fn a_piece_of_a_placed_name_is_not_looked_for_apart() {
    let texts = [
        (
            "toolz/_signatures.py".to_owned(),
            "def create_signature_registry(module_info, signatures):\n    return signatures\n"
                .to_owned(),
        ),
        (
            "toolz/functoolz.py".to_owned(),
            "def _check_sigspec(func):\n    if signature is None:\n        return None\n    return signature(func)\n"
                .to_owned(),
        ),
    ];
    let walk = Walk {
        checked: 200,
        holding: vec![1, 2],
        words: vec![1, 2],
        ..Walk::default()
    };
    let mapped = |name: &str| {
        let terms = [(name.to_owned(), true), ("signature".to_owned(), false)];
        map(
            &texts,
            &sought(&walk, &terms, &[]),
            &Asked::default(),
            Instant::now() + Duration::from_secs(10),
        )
        .unwrap()
        .text
    };
    let text = mapped("createsignatureregistry");
    assert!(
        text.contains("toolz/_signatures.py:1-2 def create_signature_registry"),
        "{text}"
    );
    assert!(!text.contains("_check_sigspec"), "{text}");
    let text = mapped("makesignaturecache");
    assert!(
        text.contains("toolz/functoolz.py:1-4 _check_sigspec"),
        "{text}"
    );
}

/// A file the prompt names stands for its outline only when the prompt's
/// words are placed nowhere: "utils.py where the timeout is ignored" means
/// the lines using `timeout`, not the file's first definitions.
#[test]
fn a_named_file_is_outlined_only_when_its_words_are_placed_nowhere() {
    let utils =
        "def load(path):\n    return path\n\n\ndef fetch(url, timeout=None):\n    return get(url, timeout)\n";
    let texts = [("pkg/utils.py".to_owned(), utils.to_owned())];
    let walk = Walk {
        checked: 200,
        holding: vec![1],
        words: vec![1],
        ..Walk::default()
    };
    let asked = Asked {
        named: vec!["utils.py".into()],
        ..Asked::default()
    };
    let mapped = |term: &str| {
        let terms = [(term.to_owned(), false)];
        map(
            &texts,
            &sought(&walk, &terms, &[]),
            &asked,
            Instant::now() + Duration::from_secs(10),
        )
        .unwrap()
        .text
    };
    let text = mapped("timeout");
    assert!(text.contains("Where 'timeout' appear"), "{text}");
    assert!(!text.contains("def load"), "{text}");
    let text = mapped("deadline");
    assert!(text.contains("pkg/utils.py:1-2 def load"), "{text}");
}

/// With no map, a request about tests still reads the tests the walk kept
/// apart; other requests read the matched files alone.
#[test]
fn the_read_without_a_map_keeps_tests_when_asked_for() {
    let walk = Walk {
        files: vec!["src/header.py".to_owned()],
        tests: vec!["tests/test_header.py".to_owned()],
        ..Walk::default()
    };
    let words = |list: &[&str]| {
        list.iter()
            .map(|word| (*word).to_owned())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        walk.found(&words(&["header", "color", "tests"])),
        words(&["src/header.py", "tests/test_header.py"])
    );
    assert_eq!(
        walk.found(&words(&["header", "color"])),
        words(&["src/header.py"])
    );
}

/// A Rust test is known by its attribute, whatever its name; a helper beside
/// it that uses the same code is not a test.
#[test]
fn tests_marked_by_an_attribute_count_whatever_their_names() {
    let rust = "use crate::Choice;

#[test]
fn converts_values() {
    Choice::new();
}

#[tokio::test]
async fn rejects_values() {
    Choice::new();
}

fn helper() {
    Choice::new();
}
";
    let walk = Walk {
        checked: 200,
        holding: vec![3],
        words: vec![3],
        ..Walk::default()
    };
    let text = map(
        &[
            (
                "src/core.py".to_owned(),
                "class Choice:\n    pass\n".to_owned(),
            ),
            ("tests/convert.rs".to_owned(), rust.to_owned()),
        ],
        &sought(&walk, &[("choice".to_owned(), true)], &[]),
        &Asked::default(),
        Instant::now() + Duration::from_secs(10),
    )
    .unwrap()
    .text;
    assert!(
        text.contains("tests/convert.rs: 2 related tests, last rejects_values 8-11"),
        "{text}"
    );
}

/// A renamed helper no test names is checked by the tests of the code
/// calling it, listed by class and name as a runner selects them.
#[test]
fn a_renamed_helper_lists_the_tests_of_its_callers() {
    let source =
        "def _sumprod(a, b):\n    return a * b\n\n\ndef dft(xs):\n    return _sumprod(xs, xs)\n";
    let tests = "class DftTests(TestCase):\n    def test_dft(self):\n        self.assertTrue(fft.dft([1]))\n";
    let walk = Walk {
        checked: 200,
        holding: vec![1],
        words: vec![1],
        ..Walk::default()
    };
    let text = map(
        &[
            ("pkg/fft.py".to_owned(), source.to_owned()),
            ("tests/test_fft.py".to_owned(), tests.to_owned()),
        ],
        &sought(&walk, &[("sumprod".to_owned(), true)], &[]),
        &Asked {
            everywhere: true,
            ..Asked::default()
        },
        Instant::now() + Duration::from_secs(10),
    )
    .unwrap()
    .text;
    assert!(
        text.contains("tests/test_fft.py: 1 related tests, last DftTests.test_dft 2-3"),
        "{text}"
    );
}

/// A name the prompt misspells, held by no project file, is the definition
/// one letter away from it; a word held somewhere is left alone.
#[test]
fn a_misspelled_name_finds_the_definition_a_letter_away() {
    let source = "def chunked(iterable, n):\n    return [iterable[:n]]\n\n\n\
def chunk_size(n):\n    return n\n";
    let walk = |spelled| Walk {
        checked: 200,
        holding: vec![0],
        words: vec![0],
        spelled: vec![spelled],
        complete: true,
        ..Walk::default()
    };
    let mapped = |spelled| {
        map(
            &[("pkg/more.py".to_owned(), source.to_owned())],
            &sought(&walk(spelled), &[("chunkd".to_owned(), false)], &[]),
            &Asked::default(),
            Instant::now() + Duration::from_secs(10),
        )
        .map(|rendered| rendered.text)
    };
    let text = mapped(0).unwrap();
    assert!(text.contains("pkg/more.py:1-2 def chunked"), "{text}");
    assert!(!text.contains("chunk_size"), "{text}");
    assert!(mapped(1).is_none_or(|text| !text.contains("def chunked")));
}

/// A file too big or not text may hold a name, so a walk that leaves one
/// unread has not read the whole project, and a rename cannot say no other
/// file holds the old name.
#[test]
fn a_walk_that_leaves_a_file_unread_is_not_complete() {
    use crate::context_assistance_prompt_files::{plain, walk};
    let dir = tempfile::tempdir().unwrap();
    let root = plain(std::fs::canonicalize(dir.path()).unwrap());
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/app.py"), "def old_name():\n    return 1\n").unwrap();
    let words = ["oldname".to_owned()];
    let read = || walk(&root, &words, &[], &[], Duration::from_secs(5)).complete;
    assert!(read());
    std::fs::write(root.join("src/data.py"), [0xff_u8; 64]).unwrap();
    assert!(!read());
    std::fs::write(root.join("src/data.py"), "old_name = 1\n".repeat(30_000)).unwrap();
    assert!(!read());
}

/// Tests reach a special method such as `__exit__` through its class, so a
/// prompt naming the method finds the tests that use the class, and still
/// finds a test that calls the method on an instance it gets from a fixture.
#[test]
fn a_named_special_method_finds_the_tests_of_its_class() {
    let source = "class callback_iter:\n    def __init__(self, seq, callback):\n        \
self.seq = seq\n        self.callback = callback\n\n    def __enter__(self):\n        \
return iter(self.seq)\n\n    def __exit__(self, *args):\n        self.callback()\n        \
return False\n";
    let tests = "from pkg.more import callback_iter\n\n\ndef test_callback_runs_when_done():\n    \
calls = []\n    with callback_iter([1], lambda: calls.append(1)) as items:\n        \
list(items)\n    assert calls == [1]\n\n\ndef test_exit_on_instance(instance):\n    \
assert instance.__exit__(None, None, None) is False\n\n\ndef test_other():\n    assert True\n";
    let (home, _project, root) = super::project_tests::project(
        super::project_tests::ON,
        &[("pkg/more.py", source), ("tests/test_more.py", tests)],
    );
    let prompt = "Something in `callback_iter.__exit__` broke recently, please fix it.";
    let text = super::project_tests::prompt_map(home.path(), &root, prompt).unwrap();
    assert!(text.contains("def __exit__"), "{text}");
    assert!(
        text.contains("Tests:\ntests/test_more.py")
            && text.contains("test_callback_runs_when_done")
            && text.contains("test_exit_on_instance"),
        "{text}"
    );
    assert!(!text.contains("test_other"), "{text}");
}

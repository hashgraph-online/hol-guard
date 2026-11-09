use super::*;
use serde_json::json;

fn excerpt(path: &str, text: &str) -> PickedExcerpt {
    PickedExcerpt {
        path: path.into(),
        start_line: 1,
        end_line: 3,
        text: text.into(),
    }
}

fn words(list: &[&str]) -> Vec<String> {
    list.iter().map(|word| (*word).to_owned()).collect()
}

/// The context text for a session's first prompt.
fn render(picked: &[PickedExcerpt], found: &[String], words: &[String]) -> Option<String> {
    super::render(picked, found, words, &[]).map(|rendered| rendered.text)
}

fn matched(found: &[String]) -> Option<String> {
    super::matched(found).map(|rendered| rendered.text)
}

fn shown(excerpt: &PickedExcerpt) -> Span {
    Span::new(
        &excerpt.path,
        excerpt.start_line,
        excerpt.end_line,
        excerpt.text.trim_end(),
    )
}

#[test]
fn an_excerpt_the_session_already_has_is_named_instead_of_sent_again() {
    let picked = [
        excerpt("src/header.tsx", "export const Header = () => <header />;"),
        excerpt("src/header-title.ts", "export const header = 'Title';"),
    ];
    let found = words(&["src/header.tsx", "src/header-title.ts", "src/theme.css"]);
    let asked = words(&["header"]);
    let first = super::render(&picked, &found, &asked, &[]).unwrap();
    assert_eq!(first.shown, vec![shown(&picked[0]), shown(&picked[1])]);

    let earlier = [shown(&picked[0])];
    let next = super::render(&picked, &found, &asked, &earlier).unwrap();
    assert_eq!(next.shown, vec![shown(&picked[1])]);
    assert!(!next.text.contains("<header />"), "{}", next.text);
    assert!(next.text.starts_with(HEADER), "{}", next.text);
    assert!(
        next.text.contains(
            "Already shown earlier in this session: src/header.tsx (lines 1-3)\n\nOther matching files: src/theme.css"
        ),
        "{}",
        next.text
    );

    let repeat = super::render(&picked, &found, &asked, &first.shown).unwrap();
    assert!(repeat.shown.is_empty());
    assert!(repeat.text.starts_with(REPEATED_HEADER), "{}", repeat.text);
    assert!(!repeat.text.contains("```"), "{}", repeat.text);
}

#[test]
fn an_excerpt_edited_since_it_was_shown_is_sent_again() {
    let picked = [excerpt(
        "src/header.tsx",
        "export const Header = () => <header />;",
    )];
    let before = [Span::new(
        "src/header.tsx",
        1,
        3,
        "export const Header = () => <div />;",
    )];
    let next = super::render(&picked, &[], &words(&["header"]), &before).unwrap();
    assert_eq!(next.shown, vec![shown(&picked[0])]);
    assert!(next.text.contains("<header />"), "{}", next.text);
}

#[test]
fn a_file_this_prompt_did_not_rank_must_mention_two_of_its_words() {
    let picked = [
        excerpt("src/earlier.py", "def render(): pass"),
        excerpt("src/progress.py", "def render(): pass"),
        excerpt("src/older.py", "def render_progress(): pass"),
    ];
    let found = words(&["src/progress.py"]);
    let rendered = render(&picked, &found, &words(&["render", "progress"])).unwrap();
    assert!(rendered.contains("src/progress.py (lines"), "{rendered}");
    assert!(rendered.contains("src/older.py (lines"), "{rendered}");
    assert!(!rendered.contains("src/earlier.py"), "{rendered}");

    // A quoted word is also one of the prompt's words, and counts once.
    let picked = [excerpt("src/dialog.py", "confirm = True")];
    let asked = words(&["confirm", "button", "confirm"]);
    assert_eq!(render(&picked, &[], &asked), None);
}

#[test]
fn a_passing_match_gives_way_to_code_about_the_request() {
    let picked = [
        excerpt(
            "src/types.py",
            "class Choice:\n    def convert(self, value):\n        self.fail(invalid_choice)",
        ),
        excerpt("src/progress.py", "raise ValueError('bad length')"),
    ];
    let found = words(&["src/types.py", "src/progress.py"]);
    let asked = words(&["choice", "invalid", "value", "convert", "suggest"]);
    let rendered = render(&picked, &found, &asked).unwrap();
    assert!(rendered.contains("src/types.py (lines"), "{rendered}");
    assert!(!rendered.contains("src/progress.py (lines"), "{rendered}");

    // On its own, the passing match is still the best there is.
    let alone = render(&picked[1..], &found, &asked).unwrap();
    assert!(alone.contains("src/progress.py (lines"), "{alone}");
}

#[test]
fn a_test_that_repeats_the_request_does_not_push_out_its_source() {
    let picked = [
        excerpt("src/types.py", "class Choice:\n    def convert(self, raw):"),
        excerpt(
            "tests/test_types.py",
            "def test_invalid_choice_suggests():\n    convert(choice, value)",
        ),
    ];
    // The search ranks a test only when the prompt names it or only tests
    // hold its quote; this one is here from an earlier prompt.
    let found = words(&["src/types.py"]);
    let asked = words(&["choice", "invalid", "value", "convert", "suggest"]);
    let rendered = render(&picked, &found, &asked).unwrap();
    assert!(rendered.contains("src/types.py (lines"), "{rendered}");
    assert!(
        !rendered.contains("tests/test_types.py (lines"),
        "{rendered}"
    );
}

#[test]
fn matching_code_is_rendered_as_file_contents_with_other_matches_listed() {
    let picked = [
        excerpt(
            "src/components/Header.tsx",
            "export function Header() {\n  return <header />;\n}\n",
        ),
        excerpt("src/api.ts", "export const load = () => fetch('/x');"),
    ];
    let found = words(&["src/components/Header.tsx", "src/theme.css", "src/api.ts"]);
    let rendered = render(&picked, &found, &words(&["color", "header"])).unwrap();
    assert!(rendered.starts_with(HEADER));
    assert!(rendered
        .contains("src/components/Header.tsx (lines 1-3)\n```tsx\nexport function Header()"));
    assert!(
        !rendered.contains("fetch('/x')"),
        "an unrelated excerpt is dropped"
    );
    assert!(rendered.ends_with("Other matching files: src/theme.css, src/api.ts"));
}

#[test]
fn nothing_is_added_when_no_excerpt_mentions_the_request() {
    let picked = [excerpt(
        "src/api.ts",
        "export const load = () => fetch('/x');",
    )];
    assert_eq!(
        render(&picked, &words(&["src/api.ts"]), &words(&["winter"])),
        None
    );
    assert_eq!(render(&[], &[], &words(&["header"])), None);
}

#[test]
fn rendered_context_stays_bounded() {
    let long = "header ".repeat(MAX_CONTEXT_CHARS / 8);
    let picked: Vec<_> = (0..6)
        .map(|index| excerpt(&format!("src/header{index}.ts"), &long))
        .collect();
    let rendered = render(&picked, &[], &words(&["header"])).unwrap();
    assert!(rendered.len() <= MAX_CONTEXT_CHARS, "{}", rendered.len());
    assert!(rendered.contains("src/header0.ts"));
}

#[test]
fn files_that_did_not_fit_are_listed_within_the_limit() {
    let near_full = "header ".repeat(MAX_CONTEXT_CHARS / 7 - 100);
    let picked = [
        excerpt("src/header.ts", &near_full),
        excerpt("src/header-dropped.ts", &near_full),
    ];
    let mut found = words(&["src/header.ts", "src/header-dropped.ts"]);
    found.extend((0..8).map(|index| format!("src/{}/header{index}.ts", "deep/".repeat(40))));
    let rendered = render(&picked, &found, &words(&["header"])).unwrap();
    assert!(rendered.len() <= MAX_CONTEXT_CHARS, "{}", rendered.len());
    assert!(
        rendered.contains("Other matching files: src/header-dropped.ts"),
        "an excerpt cut for space is still named"
    );
    let too_big = [excerpt(
        "src/header.ts",
        &"header ".repeat(MAX_CONTEXT_CHARS / 6),
    )];
    assert_eq!(
        render(&too_big, &[], &words(&["header"])),
        None,
        "never a header with no code under it"
    );
}

#[test]
fn only_an_allowed_prompt_answer_takes_context() {
    assert!(allowed(
        &json!({"hookSpecificOutput": {"hookEventName": "UserPromptSubmit"}})
    ));
    assert!(!allowed(
        &json!({"decision": "block", "hookSpecificOutput": {}})
    ));
    assert!(!allowed(
        &json!({"continue": false, "hookSpecificOutput": {}})
    ));
    assert!(!allowed(&json!({"policy_action": "allow"})));
}

#[test]
fn context_is_appended_after_any_existing_context() {
    let mut fresh = json!({"hookSpecificOutput": {"hookEventName": "UserPromptSubmit"}});
    add_context(&mut fresh, "code");
    assert_eq!(fresh["hookSpecificOutput"]["additionalContext"], "code");
    let mut existing = json!({"hookSpecificOutput": {"additionalContext": "notice"}});
    add_context(&mut existing, "code");
    assert_eq!(
        existing["hookSpecificOutput"]["additionalContext"],
        "notice\n\ncode"
    );
}

#[test]
fn the_wait_leaves_the_hook_time_to_answer() {
    assert_eq!(waiting_time(None), DEFAULT_WAIT);
    assert_eq!(waiting_time(Some(9_000)), MAX_WAIT);
    assert_eq!(waiting_time(Some(1_000)), Duration::from_millis(750));
    assert!(waiting_time(Some(400)) < MIN_WAIT);
    assert_eq!(waiting_time(Some(100)), Duration::ZERO);
}

#[test]
fn a_long_prompt_is_cut_on_a_character_boundary() {
    let prompt = format!("{}é", "a".repeat(4_095));
    let cut = truncated(&prompt, MAX_QUERY_BYTES);
    assert_eq!(cut.len(), 4_095);
    assert_eq!(truncated("short", MAX_QUERY_BYTES), "short");
}

#[test]
fn code_fences_name_the_language() {
    assert_eq!(language("src/theme.css"), "css");
    assert_eq!(language("app/main.py"), "python");
    assert_eq!(language("README"), "");
}

#[test]
fn a_fence_inside_an_excerpt_cannot_close_the_block() {
    assert_eq!(fence_for("plain"), "```");
    assert_eq!(fence_for("a ``` b"), "````");
    let picked = [excerpt(
        "README.md",
        "Header usage:\n```tsx\n<Header />\n```",
    )];
    let rendered = render(&picked, &[], &words(&["header"])).unwrap();
    assert!(rendered.contains("README.md (lines 1-3)\n````markdown\nHeader usage:"));
    assert!(rendered.ends_with("<Header />\n```\n````"));
}

#[test]
fn a_test_an_earlier_prompt_loaded_gives_way_to_the_source() {
    let picked = [
        excerpt("src/Header.test.tsx", "it('header color', () => {});"),
        excerpt("src/Header.tsx", "export const Header = () => <header />;"),
    ];
    let rendered = render(&picked, &[], &words(&["header"])).unwrap();
    assert!(!rendered.contains("Header.test.tsx"), "{rendered}");
    let asked = render(&picked, &[], &words(&["header", "test"])).unwrap();
    assert!(asked.contains("Header.test.tsx"), "{asked}");
    let only_tests = render(&picked[..1], &[], &words(&["header"])).unwrap();
    assert!(only_tests.contains("Header.test.tsx"), "{only_tests}");
}

#[test]
fn pi_gets_context_only_from_an_extension_that_passes_it_on() {
    let flagged = json!({"prompt": "fix the cart", "guard_prompt_context": true});
    let older = json!({"prompt": "fix the cart"});
    for harness in ["pi", "omp"] {
        assert!(takes_context(harness, &flagged));
        assert!(!takes_context(harness, &older));
        assert!(!takes_context(
            harness,
            &json!({"guard_prompt_context": "yes"})
        ));
    }
    assert!(takes_context("claude-code", &older));
    assert!(takes_context("codex", &older));
    assert!(!takes_context("cursor", &flagged));
}

#[test]
fn excerpts_follow_this_prompts_ranking_before_earlier_files() {
    let picked = [
        excerpt("src/earlier.tsx", "<button>Cancel</button>"),
        excerpt("src/data-panel.tsx", "<button>Cancel</button>"),
        excerpt("src/confirm-dialog.tsx", "cancelLabel = \"Cancel\""),
    ];
    let found = words(&["src/confirm-dialog.tsx", "src/data-panel.tsx"]);
    let rendered = render(&picked, &found, &words(&["cancel"])).unwrap();
    let at = |path: &str| rendered.find(&format!("{path} (lines")).unwrap();
    assert!(
        at("src/confirm-dialog.tsx") < at("src/data-panel.tsx"),
        "{rendered}"
    );
    assert!(
        at("src/data-panel.tsx") < at("src/earlier.tsx"),
        "{rendered}"
    );
}

#[test]
fn a_prompt_cigar_cannot_answer_in_time_still_gets_the_matched_files() {
    assert_eq!(matched(&[]), None);
    let found: Vec<String> = (0..12).map(|n| format!("src/f{n}.ts")).collect();
    let listed = matched(&found).unwrap();
    assert!(listed.starts_with(MATCHED_HEADER), "{listed}");
    assert!(listed.ends_with(" src/f0.ts, src/f1.ts, src/f2.ts, src/f3.ts, src/f4.ts, src/f5.ts, src/f6.ts, src/f7.ts"), "{listed}");
}

#[test]
fn long_matched_paths_stay_within_the_context_limit() {
    let long = format!("src/{}.ts", "a".repeat(MAX_CONTEXT_CHARS / 3));
    let found = vec![long.clone(); MAX_OTHER_FILES];
    let listed = matched(&found).unwrap();
    assert!(listed.len() <= MAX_CONTEXT_CHARS, "{}", listed.len());
    assert_eq!(listed.matches(long.as_str()).count(), 2);
    assert_eq!(
        matched(&[format!("src/{}.ts", "b".repeat(MAX_CONTEXT_CHARS))]),
        None
    );
}

#[test]
fn an_excerpt_too_big_to_fit_gives_way_to_the_next_one() {
    let picked = [
        excerpt("src/header.ts", &"header ".repeat(MAX_CONTEXT_CHARS / 6)),
        excerpt("src/header-title.ts", "export const header = 'Title';"),
    ];
    let rendered = render(&picked, &[], &words(&["header"])).unwrap();
    assert!(
        rendered.contains("src/header-title.ts (lines 1-3)"),
        "{rendered}"
    );
    assert!(rendered.len() <= MAX_CONTEXT_CHARS);
}

const ON: &str = "[context_assistance]\nenabled=true\nruntime_id='selected'\n\
[context_assistance.features]\nagent_context=true\n\
[context_assistance.sources]\nworkspace_documents=true\nsource_set_id='selected-workspaces'\n";

/// A Guard home with `config`, and a project holding `files`.
fn project(
    config: &str,
    files: &[(&str, &str)],
) -> (tempfile::TempDir, tempfile::TempDir, std::path::PathBuf) {
    let home = tempfile::tempdir().unwrap();
    std::fs::write(home.path().join("config.toml"), config).unwrap();
    let project = tempfile::tempdir().unwrap();
    let root = crate::context_assistance_prompt_files::plain(
        std::fs::canonicalize(project.path()).unwrap(),
    );
    std::fs::create_dir_all(root.join("src")).unwrap();
    for (path, text) in files {
        std::fs::write(root.join(path), text).unwrap();
    }
    (home, project, root)
}

/// Guard's own read for a prompt about `terms` that matched `found`.
fn own_read(home: &Path, root: &Path, found: &[&str], terms: &[&str]) -> Option<String> {
    let later = Instant::now() + Duration::from_secs(5);
    let (found, terms) = (words(found), words(terms));
    read_matched(home, root, "codex", &found, &terms, &[], later).map(|read| read.text)
}

/// A prompt sent while CIGAR is busy with another, or still loading the
/// project as on a session's first prompt, gets the matched code from
/// Guard's own read instead of a list of file names.
#[test]
fn a_prompt_cigar_is_busy_with_gets_code_not_a_file_list() {
    let cart = "export function cartTotal() {\n  return 0;\n}\n";
    let (home, _project, root) = project(ON, &[("src/cart.ts", cart)]);
    let read = || {
        let text = own_read(home.path(), &root, &["src/cart.ts"], &["cart", "total"])?;
        Some(Rendered {
            text,
            shown: Vec::new(),
        })
    };
    for miss in [Miss::Starting, Miss::Pending] {
        let text = answered(Err(miss), read).unwrap().text;
        assert!(text.contains("src/cart.ts (lines 1-"), "{text}");
        assert!(text.contains("cartTotal"), "{text}");
        assert!(!text.starts_with(MATCHED_HEADER), "{text}");
    }
    assert!(
        answered(Ok(None), read).is_none(),
        "CIGAR's own answer stands"
    );
}

/// When no part of a matched file holds the prompt's words, as when only
/// its name matched, the read names the files it already checked rather
/// than leaving the prompt with nothing.
#[test]
fn a_read_that_finds_no_fitting_part_names_the_files_it_checked() {
    let (home, _project, root) = project(ON, &[("src/cart.ts", "export const items = [];\n")]);
    let read = own_read(home.path(), &root, &["src/cart.ts"], &["cart"]).unwrap();
    assert_eq!(read, format!("{MATCHED_HEADER} src/cart.ts"));
}

/// Guard's own read goes through the engine's checks. A fresh Guard home has
/// project context off for every workspace, so nothing is read or named,
/// even for a readable, ordinary file.
#[test]
fn guard_reads_nothing_a_workspace_has_not_allowed() {
    let (home, _project, root) = project("", &[("src/header.ts", "export const header = 1;\n")]);
    assert_eq!(
        own_read(home.path(), &root, &["src/header.ts"], &["header"]),
        None
    );
    assert!(!project_context_on(home.path(), &root, "codex"));
}

/// A library module named like a test, as Jinja's `tests.py` of template
/// tests, is the only file holding a quoted docstring. It is found and read,
/// not set aside as a test. A test that repeats a quote the source holds
/// still gives way.
#[test]
fn a_quote_only_a_test_named_module_holds_is_shown() {
    let prompt = "Which function does this? \"Return true if the variable is a number.\"";
    let module = concat!(
        "def test_number(value):\n",
        "    \"\"\"Return true if the variable is a number.\"\"\"\n",
        "    return isinstance(value, Number)\n",
    );
    let env = "class Environment:\n    def variable_number(self):\n        return True\n";
    let (home, _project, root) = project(ON, &[("src/tests.py", module), ("src/env.py", env)]);
    let words = crate::context_assistance_prompt_files::terms(prompt);
    let search = || walk(&root, &words, &phrases(prompt), &[], Duration::from_secs(5));
    let found = search().found(&words);
    assert!(found.contains(&"src/tests.py".to_owned()), "{found:?}");
    let later = Instant::now() + Duration::from_secs(5);
    let read = read_matched(home.path(), &root, "codex", &found, &words, &[], later).unwrap();
    assert!(read.text.contains("src/tests.py (lines"), "{}", read.text);
    assert!(read.text.contains("def test_number"), "{}", read.text);
    std::fs::write(root.join("src/env.py"), format!("{env}{module}")).unwrap();
    let found = search().found(&words);
    assert!(!found.contains(&"src/tests.py".to_owned()), "{found:?}");
}

/// A prompt that names its source file, with no other source matching, still
/// sets aside a test that repeats more of its words, so the test cannot raise
/// the bar the named file is measured against and hide it.
#[test]
fn a_test_cannot_push_out_the_source_file_the_prompt_names() {
    let prompt = "In types.py, convert should suggest a choice for an invalid value.";
    let source = "def convert(raw):\n    return raw\n";
    let test = "def test_invalid_choice_suggests():\n    \
assert convert('bad') == 'suggest a choice for an invalid value'\n";
    let files = [("src/types.py", source), ("src/test_types.py", test)];
    let (home, _project, root) = project(ON, &files);
    let words = crate::context_assistance_prompt_files::terms(prompt);
    let named = crate::context_assistance_prompt_words::named(prompt);
    assert_eq!(named, ["types.py".to_owned()]);
    let found = walk(
        &root,
        &words,
        &phrases(prompt),
        &named,
        Duration::from_secs(5),
    )
    .found(&words);
    assert_eq!(found, ["src/types.py".to_owned()]);
    let later = Instant::now() + Duration::from_secs(5);
    let read = read_matched(home.path(), &root, "codex", &found, &words, &[], later).unwrap();
    assert!(read.text.contains("src/types.py (lines"), "{}", read.text);
}

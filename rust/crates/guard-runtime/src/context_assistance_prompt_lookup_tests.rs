use super::*;

fn request(root: &Path, query: &str) -> Request {
    Request {
        root: root.to_path_buf(),
        app: "claude-code".into(),
        query: query.into(),
        words: vec!["cart".into()],
        found: vec!["src/cart.ts".into()],
        earlier: Vec::new(),
        names: Vec::new(),
    }
}

fn warming_now(key: &Key) -> bool {
    warming().lock().unwrap().contains(key)
}

#[test]
fn prompt_threads_have_a_process_wide_cap() {
    let budget = Box::leak(Box::new(PromptThreadBudget::new(MAX_PROMPT_THREADS)));
    let mut permits = Vec::new();
    while let Some(permit) = budget.try_acquire() {
        permits.push(permit);
    }
    assert!(permits.len() <= MAX_PROMPT_THREADS);
    assert!(budget.try_acquire().is_none());
    drop(permits);
    assert!(budget.try_acquire().is_some());
}

#[test]
fn a_prompt_that_finds_cigar_starting_leaves_one_warm_up_for_the_next() {
    let home = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    let key = (project.path().to_path_buf(), "claude-code".to_owned());
    let service = Service::default();
    service.hold_start_for_tests();
    let ask = |query: &str| {
        let soon = Instant::now() + Duration::from_millis(120) + READ_RESERVE;
        lookup(&service, home.path(), request(project.path(), query), soon)
    };

    assert_eq!(
        ask("fix the cart"),
        Err(Miss::Starting),
        "a starting CIGAR leaves the prompt to Guard's own read"
    );
    assert!(
        warming_now(&key),
        "the prompt left a warm-up waiting for the worker"
    );
    assert_eq!(
        ask("cart tax"),
        Err(Miss::Starting),
        "a later prompt is still told CIGAR is starting"
    );

    service.end_start_for_tests();
    let deadline = Instant::now() + Duration::from_secs(3);
    while warming_now(&key) {
        assert!(
            Instant::now() < deadline,
            "a start that ends frees the warm-up"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        ask("fix the cart"),
        Ok(None),
        "CIGAR neither starting nor running adds nothing"
    );
    assert!(
        !warming_now(&key),
        "no warm-up waits on a worker that is off"
    );
}

#[test]
fn a_wait_on_cigar_leaves_guard_time_to_read_the_files_itself() {
    let now = Instant::now();
    let ample = now + Duration::from_secs(2);
    assert_eq!(short_of(ample, now), ample - READ_RESERVE);
    let short = now + Duration::from_millis(200);
    assert_eq!(short_of(short, now), now + Duration::from_millis(100));
    assert_eq!(short_of(now, now + Duration::from_millis(5)), now);
}

/// Prompts that name no file, quote nothing and write no code by name get
/// no ranked excerpts; each of these got a README or changelog excerpt.
#[test]
fn only_a_prompt_that_points_at_code_gets_ranked_excerpts() {
    for prompt in [
        "keep going",
        "so is it fixed?",
        "are the actual risky calls fixed?",
        "push this branch and open a PR",
        "run the test suite and tell me what fails",
        "write a PRD, a TODO list and a takeaway prompt for this work",
        "okay just make sure we get 3.60 soon",
        "whats the severity of the FP? was it there before 3.49?",
    ] {
        assert!(!anchored(prompt), "{prompt}");
    }
    for prompt in [
        "hey, `parse_basic_str` seems busted after yesterday's change",
        "In types.py, convert should say \"suggest a choice\"",
        "why does TTLCache.expire skip the last item?",
        "the error says \"Invalid value for '--count'\"",
    ] {
        assert!(anchored(prompt), "{prompt}");
    }
}

/// A product name with a capital inside it is not code: each of these
/// matched the changelog, which mentions GitHub and TypeScript in every
/// release, and sent its first 125 lines. Written as code it still counts.
#[test]
fn a_product_name_alone_does_not_point_at_code() {
    for prompt in [
        "Add a GitHub Actions job that runs lint on pull requests",
        "Port the build script from JavaScript to TypeScript",
        "Does the CLI work on macOS and iOS?",
        "Run lint on GitHub-hosted runners",
        "Make the build TypeScript-only",
        "Does it work on macOS/iOS?",
    ] {
        assert!(!anchored(prompt), "{prompt}");
    }
    for prompt in [
        "the `GitHub` class drops redirects",
        "GitHubClient.fetch drops redirects",
        "GitHub() should accept a base URL",
        "GitHub::new drops the token",
        "api/GitHubClient drops redirects",
    ] {
        assert!(anchored(prompt), "{prompt}");
    }
}

/// Quoted text and file paths point at code only when the project has them.
/// A pasted task title, a word quoted for emphasis and a link to a guide in
/// another folder got excerpts of a manifest, build configs and an unrelated
/// module; a quoted error message the code raises, a file here and a
/// traceback's path from another machine still point at code.
#[test]
fn quoted_text_and_paths_outside_the_project_point_at_nothing() {
    use crate::context_assistance_prompt_files::{named, phrases, walk_exact};
    use crate::context_assistance_prompt_words::{spellings, terms};
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("app")).unwrap();
    std::fs::write(
        dir.path().join("app/cli.py"),
        "def count(value):\n    raise BadParameter(\"Invalid value for count\")\n",
    )
    .unwrap();
    let nowhere = |prompt: &str| {
        let budget = Duration::from_secs(5);
        let (words, quoted) = (terms(prompt), phrases(prompt));
        let walk = walk_exact(
            dir.path(),
            &words,
            &quoted,
            &named(prompt),
            &spellings(prompt),
            budget,
        );
        assert!(walk.complete, "{prompt}");
        points_nowhere(prompt, dir.path(), &walk.quoting, walk.complete)
    };
    for prompt in [
        "Do this task here: \u{201c}lockfile marks run partial\u{201d}",
        "you can use the word \"password\" to approve the count",
        "merge it with [$review-loop](/home/someone/skills/review-loop/SKILL.md) and count",
    ] {
        assert!(anchored(prompt), "{prompt}");
        assert!(nowhere(prompt), "{prompt}");
    }
    // A walk cut short may have missed the file that holds the quote.
    let title = "Do this task here: \u{201c}lockfile marks run partial\u{201d}";
    assert!(!points_nowhere(title, dir.path(), &[0], false));
    for prompt in [
        "the error says \"Invalid value for count\"",
        "In cli.py the count says \"nope\"",
        "Fix app/cli.py",
        "File \"/ci/build/proj/app/cli.py\", line 2, in count",
        "`BadParameter` says \"nope\"",
    ] {
        assert!(!nowhere(prompt), "{prompt}");
    }
}

/// In a project too big to read whole, a pasted task title or a word quoted
/// for emphasis no file the walk read holds still let excerpts ranked on the
/// prompt's plain words through: a TypeScript config for "CWV follow-up" and
/// an unrelated module for "password". A note that shows the quote, on one
/// line or wrapped in a comment, is kept, and so is one for a prompt that
/// writes code or a file here.
#[test]
fn a_note_showing_no_quote_the_walk_missed_is_dropped() {
    use crate::context_assistance_prompt_files::phrases;
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("cli.py"), "def count():\n    pass\n").unwrap();
    let title = "Do this task here: \u{201c}CWV follow-up: rail fallback\u{201d}";
    let config = "tsconfig.followup.json (lines 1-3)\n{ \"extends\": \"./tsconfig.json\" }\n";
    let unshown = |prompt: &str, quoting: &[usize], body: &str| {
        let note = format!("{}\n\n{body}", super::super::HEADER);
        quote_unshown(prompt, dir.path(), (&phrases(prompt), quoting), &note)
    };
    assert!(unshown(title, &[0], config));
    assert!(unshown(
        "use the word \"password\" to approve",
        &[0],
        config
    ));
    // Only Guard's own words in the note hold the quote: its opening
    // paragraph, an excerpt's label, a list's lead-in.
    for word in ["project", "request", "lines", "already shown"] {
        let prompt = format!("use the word \"{word}\" to approve");
        assert!(unshown(&prompt, &[0], config), "{word}");
    }
    assert!(unshown(
        "use the word \"already shown\" to approve",
        &[0],
        "Already shown earlier in this session: cli.py (lines 1-2)"
    ));
    // A file's line that starts like one of Guard's still shows the quote.
    let fenced =
        "docs/auth.md (lines 1-2)\n```markdown\nChanged definitions require password checks.\n```";
    let password = "use the word \"password\" to approve";
    assert!(!unshown(password, &[0], fenced));
    // A file holding its own ``` sits in a longer fence; its inner fence
    // lines neither end the excerpt nor make Guard's later lines a file's.
    let nested = "docs/auth.md (lines 1-3)\n````markdown\n```text\n\
Reset the password (lines 1-2)\n````\n\
Already shown earlier in this session: approve.py (lines 1-2)";
    assert!(!unshown(password, &[0], nested));
    assert!(unshown(
        "use the word \"already shown\" to approve",
        &[0],
        nested
    ));
    assert!(!unshown(
        password,
        &[0],
        "Definitions this request names:\nChanged definitions require password checks."
    ));
    // The note shows the quote CIGAR found beyond the walk.
    assert!(!unshown(
        title,
        &[0],
        "app/vitals.ts\n// CWV follow-up: rail fallback\n"
    ));
    assert!(!unshown(
        title,
        &[0],
        "app/vitals.ts\n# Track the CWV follow-up:\n# rail fallback here.\n"
    ));
    // The walk read a file holding it, the prompt writes code or names a
    // file here, or it quotes nothing.
    assert!(!unshown(title, &[1], config));
    assert!(!unshown(
        "\u{201c}rail fallback\u{201d} in `parse_args`",
        &[0],
        config
    ));
    assert!(!unshown(
        "\u{201c}rail fallback\u{201d} in cli.py",
        &[0],
        config
    ));
    assert!(!unshown("fix the rail fallback", &[], config));
}

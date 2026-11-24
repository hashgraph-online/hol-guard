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

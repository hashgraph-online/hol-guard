use super::*;

fn request(root: &Path, query: &str) -> Request {
    Request {
        root: root.to_path_buf(),
        app: "claude-code".into(),
        query: query.into(),
        words: vec!["cart".into()],
        found: vec!["src/cart.ts".into()],
    }
}

fn warming_now(key: &Key) -> bool {
    warming().lock().unwrap().contains(key)
}

#[test]
fn a_prompt_that_finds_cigar_starting_leaves_one_warm_up_for_the_next() {
    let home = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    let key = (project.path().to_path_buf(), "claude-code".to_owned());
    let service = Service::default();
    service.hold_start_for_tests();
    let ask = |query: &str| {
        let soon = Instant::now() + Duration::from_millis(120);
        lookup(&service, home.path(), request(project.path(), query), soon)
    };

    assert_eq!(
        ask("fix the cart"),
        None,
        "a starting CIGAR leaves the prompt the matched files"
    );
    assert!(
        warming_now(&key),
        "the prompt left a warm-up waiting for the worker"
    );
    assert_eq!(
        ask("cart tax"),
        None,
        "a later prompt still gets the matched files"
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
        Some(None),
        "CIGAR neither starting nor running adds nothing"
    );
    assert!(
        !warming_now(&key),
        "no warm-up waits on a worker that is off"
    );
}

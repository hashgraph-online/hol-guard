use super::*;

fn presented<'a>(grant_id: &'a str, subject: &'a str) -> Presented<'a> {
    Presented {
        grant_id,
        subject,
        operation_id: "operation-1",
        owner_pid: 41,
        deadline: "812.5",
    }
}

#[test]
fn a_grant_is_spent_once_and_only_its_claimant_holds_it() {
    let claims = Claims::default();
    let now = Instant::now();
    assert_eq!(
        claims.claim(&presented("grant-1", "subject-a"), 60.0, now),
        Ok(())
    );
    assert_eq!(
        claims.claim(&presented("grant-1", "subject-a"), 60.0, now),
        Err(CLAIMED)
    );
    assert_eq!(
        claims.check(&presented("grant-1", "subject-a"), now),
        Ok(())
    );
    assert_eq!(
        claims.check(&presented("grant-1", "subject-b"), now),
        Err(INVALID)
    );
    assert_eq!(
        claims.check(&presented("grant-2", "subject-a"), now),
        Err(INVALID)
    );
    let mut other_owner = presented("grant-1", "subject-a");
    other_owner.owner_pid = 42;
    assert_eq!(claims.check(&other_owner, now), Err(INVALID));
    other_owner.owner_pid = 41;
    other_owner.operation_id = "operation-2";
    assert_eq!(claims.check(&other_owner, now), Err(INVALID));
}

#[test]
fn a_mismatched_deadline_is_refused() {
    let claims = Claims::default();
    let now = Instant::now();
    assert_eq!(
        claims.claim(&presented("grant-1", "subject-a"), 60.0, now),
        Ok(())
    );
    for other in ["812.50", "812.4", "", "813.5"] {
        let mut changed = presented("grant-1", "subject-a");
        changed.deadline = other;
        assert_eq!(claims.check(&changed, now), Err(INVALID), "{other}");
    }
    assert_eq!(
        claims.check(&presented("grant-1", "subject-a"), now),
        Ok(())
    );
}

#[test]
fn a_claim_lapses_with_its_retirement_and_frees_its_slot() {
    let claims = Claims::default();
    let now = Instant::now();
    assert_eq!(
        claims.claim(&presented("grant-1", "subject-a"), 5.0, now),
        Ok(())
    );
    let later = now + Duration::from_secs(6);
    assert_eq!(
        claims.check(&presented("grant-1", "subject-a"), later),
        Err(INVALID)
    );
    assert_eq!(
        claims.claim(&presented("grant-1", "subject-a"), 5.0, later),
        Ok(())
    );
}

#[test]
fn a_grant_that_is_already_retired_cannot_be_claimed_into_use() {
    let claims = Claims::default();
    let now = Instant::now();
    for retirement in [0.0, -3.0, f64::NAN] {
        let id = format!("grant-{retirement}");
        assert_eq!(
            claims.claim(&presented(&id, "subject-a"), retirement, now),
            Ok(())
        );
        assert_eq!(
            claims.check(&presented(&id, "subject-a"), now),
            Err(INVALID)
        );
    }
}

#[test]
fn the_registry_is_bounded() {
    let claims = Claims::default();
    let now = Instant::now();
    for index in 0..MAX_CLAIMS {
        let id = format!("grant-{index}");
        assert_eq!(
            claims.claim(&presented(&id, "subject-a"), 60.0, now),
            Ok(())
        );
    }
    assert_eq!(
        claims.claim(&presented("one-more", "subject-a"), 60.0, now),
        Err(CAPACITY)
    );
    let later = now + Duration::from_secs(61);
    assert_eq!(
        claims.claim(&presented("one-more", "subject-a"), 60.0, later),
        Ok(())
    );
}

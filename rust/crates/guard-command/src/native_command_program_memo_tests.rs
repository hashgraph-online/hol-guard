use super::*;

fn layout() -> Arc<MemoLayout> {
    Arc::new(MemoLayout {
        slots: vec![usize::MAX, 0, 1],
        active_nodes: 2,
    })
}

#[test]
fn leases_never_reuse_previous_command_results_or_inactive_nodes() {
    let layout = layout();
    let mut first = MemoLease::new(Arc::clone(&layout));
    first.insert(1, Ok(Arc::from([3]))).unwrap();
    assert_eq!(first.get(1).unwrap().as_ref().unwrap().as_ref(), &[3]);
    assert_eq!(
        first.insert(0, Ok(Arc::from([9]))).unwrap_err(),
        "native_command_inactive_memo_node"
    );
    drop(first);
    let second = MemoLease::new(Arc::clone(&layout));
    assert!(second.get(1).is_none());
    assert!(second
        .cache
        .as_ref()
        .unwrap()
        .entries
        .iter()
        .all(|entry| entry.value.is_none()));
}

#[test]
fn nested_and_different_snapshot_leases_are_isolated() {
    let layout = layout();
    let mut outer = MemoLease::new(Arc::clone(&layout));
    outer.insert(1, Ok(Arc::from([1]))).unwrap();
    let mut inner = MemoLease::new(Arc::clone(&layout));
    assert!(inner.get(1).is_none());
    inner.insert(1, Ok(Arc::from([2]))).unwrap();
    assert_eq!(outer.get(1).unwrap().as_ref().unwrap().as_ref(), &[1]);
    drop(inner);
    let other = MemoLease::new(super::tests::layout());
    assert!(other.get(1).is_none());
    drop(other);
    assert_eq!(outer.get(1).unwrap().as_ref().unwrap().as_ref(), &[1]);
}

#[test]
fn generation_wrap_and_pool_eviction_cannot_resurrect_evidence() {
    let layout = layout();
    let mut first = MemoLease::new(Arc::clone(&layout));
    first.cache.as_mut().unwrap().generation = u64::MAX;
    first.insert(1, Err("previous matcher error")).unwrap();
    drop(first);
    let mut wrapped = MemoLease::new(Arc::clone(&layout));
    assert_eq!(wrapped.cache.as_ref().unwrap().generation, 1);
    assert!(wrapped.get(1).is_none());
    wrapped.insert(1, Ok(Arc::from([4]))).unwrap();
    drop(wrapped);
    for _ in 0..8 {
        drop(MemoLease::new(super::tests::layout()));
    }
    POOL.with(|pool| assert!(pool.borrow().len() <= CACHED_LAYOUTS));
    assert!(MemoLease::new(layout).get(1).is_none());
}

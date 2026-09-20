//! Scoped, thread-local fixture time for authority currentness tests.

use super::now_ms;

thread_local! {
    static TEST_NOW_MS: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

/// A scoped fixture clock cannot escape its originating test thread.
pub(crate) struct TestClock {
    previous: Option<u64>,
    _same_thread: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl TestClock {
    pub(crate) fn at(now: u64) -> Self {
        Self {
            previous: TEST_NOW_MS.with(|clock| clock.replace(Some(now))),
            _same_thread: std::marker::PhantomData,
        }
    }

    pub(crate) fn set(&self, now: u64) {
        TEST_NOW_MS.with(|clock| clock.set(Some(now)));
    }
}

impl Drop for TestClock {
    fn drop(&mut self) {
        TEST_NOW_MS.with(|clock| clock.set(self.previous));
    }
}

#[test]
fn fixture_clock_restores_nested_and_panicking_scopes_without_crossing_threads() {
    let outer = TestClock::at(17);
    assert_eq!(now_ms().unwrap(), 17);
    {
        let inner = TestClock::at(23);
        inner.set(29);
        assert_eq!(now_ms().unwrap(), 29);
    }
    assert_eq!(now_ms().unwrap(), 17);
    assert!(std::panic::catch_unwind(|| {
        let _inner = TestClock::at(31);
        panic!("synthetic clock unwind");
    })
    .is_err());
    assert_eq!(now_ms().unwrap(), 17);
    assert!(std::thread::spawn(now_ms).join().unwrap().unwrap() > 31);
    drop(outer);
    assert!(now_ms().unwrap() > 31);
}

pub(super) fn fixture_now_ms() -> Option<u64> {
    TEST_NOW_MS.with(std::cell::Cell::get)
}

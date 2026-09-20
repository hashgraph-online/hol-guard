#[test]
fn observation_macro_returns_original_values_and_evaluates_once() {
    let calls = std::cell::Cell::new(0);
    let value = Box::new([3u8; 8]);
    let identity = (&*value) as *const [u8; 8];
    let result: Result<Box<[u8; 8]>, ()> = crate::observe_native_phase!(ClientConnect, {
        calls.set(calls.get() + 1);
        Ok(value)
    });
    assert_eq!(calls.get(), 1);
    assert_eq!((&*result.unwrap()) as *const [u8; 8], identity);
    let error = Box::new([9u8; 8]);
    let error_identity = (&*error) as *const [u8; 8];
    let result: Result<(), Box<[u8; 8]>> = crate::observe_native_phase!(ClientConnect, {
        calls.set(calls.get() + 1);
        Err(error)
    });
    assert_eq!(calls.get(), 2);
    assert_eq!((&*result.unwrap_err()) as *const [u8; 8], error_identity);
}

#[test]
fn propagation_remains_outside_the_observed_call() {
    fn original() -> Result<(), &'static str> {
        Err("unchanged controlled error")
    }
    fn caller() -> Result<(), &'static str> {
        crate::observe_native_phase!(ClientRequestWriteFlush, original())?;
        panic!("propagation must return before this statement");
    }
    assert_eq!(caller(), Err("unchanged controlled error"));
}

#[cfg(not(all(feature = "diagnostic-phases", target_os = "linux")))]
#[test]
fn default_macros_erase_phase_and_export_dependencies() {
    let calls = std::cell::Cell::new(0);
    let result: Result<u8, ()> = crate::with_native_phase_export!(
        crate::observe_native_phase!(NoSuchPhaseMustBeErased, {
            calls.set(calls.get() + 1);
            Ok(42)
        })
    );
    assert_eq!(result, Ok(42));
    assert_eq!(calls.get(), 1);
}

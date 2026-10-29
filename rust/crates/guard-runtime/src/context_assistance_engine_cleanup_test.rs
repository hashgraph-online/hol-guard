//! Deliberately delay private host-state destruction after runtime.close() in
//! real SDK ownership tests. Production Engine has neither this field nor hook.
#[derive(Default)]
pub(crate) struct Hook(pub(crate) Option<Box<dyn FnOnce() + Send>>);
impl Drop for Hook {
    fn drop(&mut self) {
        if let Some(hook) = self.0.take() {
            hook();
        }
    }
}

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    hol_guard_runtime::fuzz_entry::shell_command(data);
});

use super::{guid_string, milliseconds_as_ns, observe, validated_boot_session_id};

#[test]
fn boot_session_ids_are_trimmed_and_bounded() {
    assert_eq!(
        validated_boot_session_id(" boot-id\n"),
        Ok("boot-id".to_owned())
    );
    assert!(validated_boot_session_id(&"a".repeat(256)).is_ok());
    for refused in ["", "  \n", &"a".repeat(257)] {
        assert_eq!(
            validated_boot_session_id(refused),
            Err("lease_continuity_boot_probe_failed")
        );
    }
}

#[test]
fn an_all_zero_identifier_is_refused() {
    for zero in [
        "00000000-0000-0000-0000-000000000000",
        "{00000000-0000-0000-0000-000000000000}",
        "0",
    ] {
        assert_eq!(
            validated_boot_session_id(zero),
            Err("lease_continuity_boot_probe_failed")
        );
    }
    assert_eq!(
        validated_boot_session_id(&guid_string([0; 16])),
        Err("lease_continuity_boot_probe_failed")
    );
}

#[test]
fn guids_print_their_little_endian_fields_like_python() {
    let mut raw = [0u8; 16];
    raw[0] = 1;
    assert_eq!(guid_string(raw), "00000001-0000-0000-0000-000000000000");
    let raw: [u8; 16] = std::array::from_fn(|index| index as u8);
    // uuid.UUID(bytes_le=bytes(range(16)))
    assert_eq!(guid_string(raw), "03020100-0504-0706-0809-0a0b0c0d0e0f");
}

#[test]
fn tick_counts_keep_their_64_bit_range() {
    assert_eq!(milliseconds_as_ns(3_000_000_000), Ok(3_000_000_000_000_000));
    assert_eq!(
        milliseconds_as_ns(u64::MAX),
        Err("lease_continuity_monotonic_probe_failed")
    );
}

#[cfg(any(target_os = "macos", windows, target_os = "linux"))]
#[test]
fn this_boot_is_observed_with_an_uptime_that_never_falls() {
    let first = observe().expect("the host boot is observable");
    let second = observe().expect("the host boot is observable");
    assert!(!first.boot_session_id.is_empty());
    assert_eq!(first.boot_session_id, second.boot_session_id);
    assert!(second.monotonic_uptime_ns >= first.monotonic_uptime_ns);
}

use super::*;

#[test]
fn limits_only_ever_come_down() {
    let infinite = libc::RLIM_INFINITY;
    assert_eq!(lowered(infinite, infinite, 256), (256, 256));
    assert_eq!(lowered(100, infinite, 256), (100, 256));
    assert_eq!(lowered(infinite, 200, 256), (200, 200));
    assert_eq!(lowered(1024, 4096, 256), (256, 256));
}

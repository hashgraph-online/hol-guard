//! Inherited socket and privilege syscall filter matching the original contract.
use super::BoundaryResult as Result;

pub(super) fn instructions(machine: &str) -> Result<Vec<(u16, u8, u8, u32)>> {
    let (arch, pair, clone, denied): (u32, u32, u32, &[u32]) = match machine {
        "x86_64" => (
            0xc000003e,
            53,
            56,
            &[41, 42, 101, 311, 319, 272, 308, 165, 166, 155],
        ),
        "aarch64" => (
            0xc00000b7,
            199,
            220,
            &[198, 203, 117, 271, 279, 97, 268, 40, 39, 41],
        ),
        _ => return Err("Unsupported Linux socket-filter architecture."),
    };
    let allow = 0x7fff0000;
    let kill = 0x80000000;
    let deny = 0x00050000 | 1;
    let mut result = vec![
        (0x20, 0, 0, 4),
        (0x15, 1, 0, arch),
        (0x06, 0, 0, kill),
        (0x20, 0, 0, 0),
        (0x35, 0, 1, 0x40000000),
        (0x06, 0, 0, kill),
    ];
    for number in denied
        .iter()
        .copied()
        .chain([425, 426, 427, 428, 429, 430, 431, 432, 433, 442])
    {
        result.extend([(0x15, 0, 1, number), (0x06, 0, 0, deny)]);
    }
    result.extend([(0x15, 0, 1, 435), (0x06, 0, 0, 0x00050000 | 38)]);
    result.extend([
        (0x15, 0, 4, clone),
        (0x20, 0, 0, 16),
        (0x54, 0, 0, 0x7e020080),
        (0x15, 1, 0, 0),
        (0x06, 0, 0, deny),
        (0x20, 0, 0, 0),
    ]);
    result.extend([
        (0x15, 1, 0, pair),
        (0x06, 0, 0, allow),
        (0x20, 0, 0, 16),
        (0x15, 1, 0, 1),
        (0x06, 0, 0, deny),
    ]);
    result.extend([
        (0x20, 0, 0, 24),
        (0x54, 0, 0, 0xffffffff ^ (0x80000 | 0x800)),
        (0x15, 1, 0, 1),
        (0x06, 0, 0, deny),
    ]);
    result.extend([
        (0x20, 0, 0, 32),
        (0x15, 1, 0, 0),
        (0x06, 0, 0, deny),
        (0x06, 0, 0, allow),
    ]);
    Ok(result)
}

#[cfg(target_os = "linux")]
pub(super) fn enforce() -> Result<()> {
    let items = instructions(std::env::consts::ARCH)?;
    let filters: Vec<seccompiler::sock_filter> = items
        .into_iter()
        .map(|(code, jt, jf, k)| seccompiler::sock_filter { code, jt, jf, k })
        .collect();
    seccompiler::apply_filter(&filters).map_err(|_| "Could not enforce Linux socket isolation.")?;
    Ok(())
}

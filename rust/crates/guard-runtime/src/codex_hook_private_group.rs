//! Whether a POSIX group is provably private to one file owner.
//!
//! Linux distributions commonly create one primary group per user and pair it
//! with a 0002 umask, which leaves user-owned 0664 config files and package
//! modules extracted by pip or pipx. The group-write bit on such a file is
//! safe only when the account database proves that no other account belongs
//! to the group. Every lookup failure stays fail-closed.

/// The file owner as the account database names it.
pub(crate) struct Owner<'a> {
    pub(crate) name: &'a str,
    pub(crate) gid: u32,
}

/// The file's group as the group database lists it.
pub(crate) struct GroupEntry<'a> {
    pub(crate) gid: u32,
    pub(crate) name: &'a str,
    pub(crate) members: &'a [String],
}

/// Whether `group` is private to `owner`, given every account's name and
/// primary group (`None` when the host gives no complete listing).
///
/// User-private groups often list no members: membership comes from the
/// owner's primary group. When no account listing is available, only the
/// classic convention is accepted: the group is named after the owner, is the
/// owner's primary group, and lists nobody. Any evidence of a second member
/// rejects.
pub(crate) fn group_private_to(
    owner: &Owner<'_>,
    group: &GroupEntry<'_>,
    accounts: Option<&[(String, u32)]>,
) -> bool {
    let primary = owner.gid == group.gid;
    let listed = group.members.iter().any(|member| member == owner.name);
    if !primary && !listed {
        return false;
    }
    if group.members.iter().any(|member| member != owner.name) {
        return false;
    }
    match accounts {
        Some(accounts) if !accounts.is_empty() => {
            if accounts
                .iter()
                .any(|(name, gid)| *gid == group.gid && name != owner.name)
            {
                return false;
            }
            // Proven private membership: the owner is a member and no one
            // else is. A listing that omits the owner proves nothing.
            listed
                || accounts
                    .iter()
                    .any(|(name, gid)| name == owner.name && *gid == group.gid)
        }
        _ => group.members.is_empty() && group.name == owner.name && primary,
    }
}

/// Each account's name and primary gid from `/etc/passwd` text, or `None`
/// when the file defers to another source or holds a malformed entry.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn parse_passwd(text: &str) -> Option<Vec<(String, u32)>> {
    let mut accounts = Vec::new();
    for line in text.lines() {
        let line = line.trim_end_matches('\r');
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('+') || line.starts_with('-') {
            return None;
        }
        let mut fields = line.split(':');
        let name = fields.next()?;
        let gid = fields.nth(2)?.parse::<u32>().ok()?;
        accounts.push((name.to_owned(), gid));
    }
    Some(accounts)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE: Owner<'static> = Owner {
        name: "alice",
        gid: 1000,
    };

    fn group<'a>(name: &'a str, members: &'a [String]) -> GroupEntry<'a> {
        GroupEntry {
            gid: 1000,
            name,
            members,
        }
    }

    fn accounts(entries: &[(&str, u32)]) -> Vec<(String, u32)> {
        entries
            .iter()
            .map(|(name, gid)| ((*name).to_owned(), *gid))
            .collect()
    }

    #[test]
    fn primary_and_explicit_members_are_counted() {
        let none: Vec<String> = Vec::new();
        let listing = accounts(&[("alice", 1000), ("bob", 2000)]);
        assert!(group_private_to(
            &ALICE,
            &group("alice", &none),
            Some(&listing)
        ));

        let shared = accounts(&[("alice", 1000), ("bob", 1000)]);
        assert!(!group_private_to(
            &ALICE,
            &group("alice", &none),
            Some(&shared)
        ));

        let bob = vec!["bob".to_owned()];
        assert!(!group_private_to(
            &ALICE,
            &group("alice", &bob),
            Some(&listing)
        ));
    }

    #[test]
    fn classic_user_private_group_is_accepted_without_a_listing() {
        let none: Vec<String> = Vec::new();
        assert!(group_private_to(&ALICE, &group("alice", &none), Some(&[])));
        assert!(group_private_to(&ALICE, &group("alice", &none), None));
    }

    #[test]
    fn a_shared_name_is_refused_without_a_listing() {
        let none: Vec<String> = Vec::new();
        assert!(!group_private_to(&ALICE, &group("users", &none), Some(&[])));
        assert!(!group_private_to(&ALICE, &group("users", &none), None));
    }

    #[test]
    fn a_partial_listing_missing_the_owner_is_refused() {
        let none: Vec<String> = Vec::new();
        let listing = accounts(&[("carol", 2000)]);
        assert!(!group_private_to(
            &ALICE,
            &group("alice", &none),
            Some(&listing)
        ));
    }

    #[test]
    fn a_group_the_owner_is_not_in_is_refused() {
        let none: Vec<String> = Vec::new();
        let owner = Owner {
            name: "alice",
            gid: 2000,
        };
        let listing = accounts(&[("alice", 2000)]);
        assert!(!group_private_to(
            &owner,
            &group("alice", &none),
            Some(&listing)
        ));
    }

    #[test]
    fn passwd_text_is_read_and_compat_entries_refuse() {
        let text =
            "# local\nroot:x:0:0:root:/root:/bin/sh\nalice:x:1000:1000::/home/alice:/bin/sh\n";
        assert_eq!(
            parse_passwd(text),
            Some(accounts(&[("root", 0), ("alice", 1000)]))
        );
        assert_eq!(parse_passwd("+::::::\n"), None);
        assert_eq!(parse_passwd("broken\n"), None);
    }
}

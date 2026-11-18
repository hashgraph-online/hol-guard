//! The shell state the git rules carry from one command to the next: the
//! folder the shell is in, relative to where the agent started, and which
//! hook-manager switches are set in the environment.

/// Where the shell is, relative to the folder the agent started in.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Dir {
    /// The starting folder, where `.` names the whole tree.
    #[default]
    Root,
    /// This many folders below it.
    Below(u16),
    /// Somewhere Guard cannot place: above it, an absolute path, a variable.
    Elsewhere,
}

impl Dir {
    /// The folder after changing into `target`.
    pub(crate) fn enter(self, target: &str) -> Self {
        if target.contains("--show-toplevel") {
            return Self::Root;
        }
        if target.starts_with(['/', '\\', '$', '~', '`']) || target.contains(':') {
            return Self::Elsewhere;
        }
        target
            .split(['/', '\\'])
            .fold(self, |dir, part| match (dir, part) {
                (dir, "" | ".") => dir,
                (Self::Root, "..") | (Self::Elsewhere, _) => Self::Elsewhere,
                (Self::Below(1), "..") => Self::Root,
                (Self::Below(depth), "..") => Self::Below(depth - 1),
                (Self::Root, _) => Self::Below(1),
                (Self::Below(depth), _) => Self::Below(depth.saturating_add(1)),
            })
    }
}

/// The variables that switch a hook manager off.
const HOOK_VARIABLES: &[&str] = &[
    "HUSKY",
    "LEFTHOOK",
    "HUSKY_SKIP_HOOKS",
    "OVERCOMMIT_DISABLE",
    "SKIP",
];

/// Which hook-manager switches are set, one bit per [`HOOK_VARIABLES`] entry.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Hooks(u8);

impl Hooks {
    pub(crate) fn off(self) -> bool {
        self.0 != 0
    }

    /// The switches after `NAME=value`: a disarming value sets the switch,
    /// any other value clears it.
    pub(crate) fn assign(self, token: &str) -> Self {
        let Some((name, value)) = assignment(token) else {
            return self;
        };
        let Some(bit) = bit(name) else {
            return self;
        };
        if disarms(name, value) {
            Self(self.0 | bit)
        } else {
            Self(self.0 & !bit)
        }
    }

    /// The switches after `unset NAME` or `env -u NAME`.
    pub(crate) fn unset(self, name: &str) -> Self {
        bit(name).map_or(self, |bit| Self(self.0 & !bit))
    }

    /// The switches a command's leading words set: assignments, and `env`
    /// with its `-i` and `-u NAME` options. Returns the switches and how many
    /// words were read.
    pub(crate) fn prefix(mut self, words: &[&str]) -> (Self, usize) {
        let mut index = 0;
        let mut in_env = false;
        while let Some(word) = words.get(index) {
            if assignment(word).is_some() {
                self = self.assign(word);
            } else if *word == "env" && !in_env {
                in_env = true;
            } else if in_env && matches!(*word, "-i" | "--ignore-environment" | "-") {
                self = Self::default();
            } else if in_env && matches!(*word, "-u" | "--unset") {
                if let Some(name) = words.get(index + 1) {
                    self = self.unset(name);
                }
                index += 1;
            } else if in_env && matches!(*word, "-C" | "--chdir" | "-S" | "--split-string") {
                index += 1;
            } else if !(in_env && word.starts_with('-')) {
                break;
            }
            index += 1;
        }
        (self, index)
    }
}

/// The shell state that carries from one segment to the next.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct State {
    pub(crate) dir: Dir,
    /// The folder `cd -` and `popd` return to.
    pub(crate) previous: Dir,
    /// The switches exported for every later command.
    pub(crate) hooks: Hooks,
}

impl State {
    /// `cd`, `pushd` or `popd` with their arguments.
    pub(crate) fn change_directory(&mut self, program: &str, args: &[&str]) {
        let target = args
            .iter()
            .find(|word| !word.starts_with('-') || **word == "-")
            .copied();
        let next = match (program, target) {
            ("popd", _) | (_, Some("-")) => self.previous,
            (_, None) => Dir::Elsewhere,
            (_, Some(target)) => self.dir.enter(target),
        };
        self.previous = if program == "popd" {
            Dir::Elsewhere
        } else {
            self.dir
        };
        self.dir = next;
    }

    /// `export`, `declare`, `typeset` or `unset` with their arguments.
    pub(crate) fn environment(&mut self, program: &str, args: &[&str]) {
        for word in args.iter().filter(|word| !word.starts_with('-')) {
            self.hooks = if program == "unset" {
                self.hooks.unset(word)
            } else {
                self.hooks.assign(word)
            };
        }
    }
}

fn bit(name: &str) -> Option<u8> {
    HOOK_VARIABLES
        .iter()
        .position(|variable| *variable == name)
        .map(|index| 1 << index)
}

/// Whether `NAME=value` switches its hook manager off.
fn disarms(name: &str, value: &str) -> bool {
    let value = value.trim_matches(|c| c == '"' || c == '\'');
    match name {
        "HUSKY" | "LEFTHOOK" => value == "0",
        "HUSKY_SKIP_HOOKS" | "OVERCOMMIT_DISABLE" => {
            matches!(value, "1" | "true" | "TRUE" | "yes")
        }
        // pre-commit skips the hook ids it lists.
        "SKIP" => !value.is_empty(),
        _ => false,
    }
}

pub(crate) fn assignment(token: &str) -> Option<(&str, &str)> {
    let (name, value) = token.split_once('=')?;
    let valid = !name.is_empty()
        && !name.starts_with(|c: char| c.is_ascii_digit())
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    valid.then_some((name, value))
}
